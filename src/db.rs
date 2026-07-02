use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{AuditEvent, CreateTask, Task, TaskStatus, UpdateTask};

pub type DbPool = Pool<SqliteConnectionManager>;

/// Build a connection pool. `path` may be a filesystem path or ":memory:".
///
/// Note: for in-memory databases we use a single connection so all callers
/// share the same schema/data (each SQLite `:memory:` connection is isolated).
pub fn build_pool(path: &str) -> AppResult<DbPool> {
    let manager = if path == ":memory:" {
        SqliteConnectionManager::memory()
    } else {
        SqliteConnectionManager::file(path)
    };

    let max_size = if path == ":memory:" { 1 } else { 8 };

    let pool = Pool::builder()
        .max_size(max_size)
        .build(manager)
        .map_err(|e| AppError::Internal(format!("failed to build pool: {e}")))?;
    Ok(pool)
}

/// Create tables if they do not exist. Enables WAL + foreign keys for file DBs.
pub fn init_schema(pool: &DbPool) -> AppResult<()> {
    let conn = pool.get()?;
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS task (
            id           TEXT PRIMARY KEY,
            title        TEXT NOT NULL,
            description  TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL DEFAULT 'todo',
            owner        TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_task_owner ON task(owner);

        CREATE TABLE IF NOT EXISTS audit_event (
            id           TEXT PRIMARY KEY,
            actor        TEXT NOT NULL,
            action       TEXT NOT NULL,
            entity_type  TEXT NOT NULL,
            entity_id    TEXT NOT NULL,
            timestamp    TEXT NOT NULL,
            detail       TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_event(actor);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_event(action);
        "#,
    )?;
    Ok(())
}

/// Lightweight readiness check: run a trivial query.
pub fn ping(pool: &DbPool) -> AppResult<()> {
    let conn = pool.get()?;
    conn.query_row("SELECT 1", [], |_| Ok(()))?;
    Ok(())
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn row_to_task(row: &rusqlite::Row) -> rusqlite::Result<Task> {
    let status_str: String = row.get("status")?;
    let created_str: String = row.get("created_at")?;
    let updated_str: String = row.get("updated_at")?;
    Ok(Task {
        id: row.get("id")?,
        title: row.get("title")?,
        description: row.get("description")?,
        status: TaskStatus::from_str(&status_str).unwrap_or(TaskStatus::Todo),
        owner: row.get("owner")?,
        created_at: parse_ts(&created_str),
        updated_at: parse_ts(&updated_str),
    })
}

/// List tasks with pagination.
pub fn list_tasks(pool: &DbPool, limit: i64, offset: i64) -> AppResult<Vec<Task>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, owner, created_at, updated_at \
         FROM task ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt.query_map(params![limit, offset], row_to_task)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Fetch a single task by id.
pub fn get_task(pool: &DbPool, id: &str) -> AppResult<Option<Task>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, owner, created_at, updated_at \
         FROM task WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id], row_to_task)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

/// Create a task owned by `owner`.
pub fn create_task(pool: &DbPool, owner: &str, input: &CreateTask) -> AppResult<Task> {
    let now = Utc::now();
    let task = Task {
        id: Uuid::new_v4().to_string(),
        title: input.title.trim().to_string(),
        description: input.description.clone(),
        status: input.status.unwrap_or(TaskStatus::Todo),
        owner: owner.to_string(),
        created_at: now,
        updated_at: now,
    };
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO task (id, title, description, status, owner, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            task.id,
            task.title,
            task.description,
            task.status.as_str(),
            task.owner,
            task.created_at.to_rfc3339(),
            task.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(task)
}

/// Apply a partial update to an existing task and return the new state.
pub fn update_task(pool: &DbPool, existing: &Task, input: &UpdateTask) -> AppResult<Task> {
    let mut updated = existing.clone();
    if let Some(title) = &input.title {
        updated.title = title.trim().to_string();
    }
    if let Some(desc) = &input.description {
        updated.description = desc.clone();
    }
    if let Some(status) = input.status {
        updated.status = status;
    }
    updated.updated_at = Utc::now();

    let conn = pool.get()?;
    conn.execute(
        "UPDATE task SET title = ?1, description = ?2, status = ?3, updated_at = ?4 \
         WHERE id = ?5",
        params![
            updated.title,
            updated.description,
            updated.status.as_str(),
            updated.updated_at.to_rfc3339(),
            updated.id,
        ],
    )?;
    Ok(updated)
}

/// Delete a task by id. Returns true if a row was removed.
pub fn delete_task(pool: &DbPool, id: &str) -> AppResult<bool> {
    let conn = pool.get()?;
    let n = conn.execute("DELETE FROM task WHERE id = ?1", params![id])?;
    Ok(n > 0)
}

/// Insert an audit event.
pub fn record_audit(
    pool: &DbPool,
    actor: &str,
    action: &str,
    entity_type: &str,
    entity_id: &str,
    detail: &str,
) -> AppResult<()> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO audit_event (id, actor, action, entity_type, entity_id, timestamp, detail) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            Uuid::new_v4().to_string(),
            actor,
            action,
            entity_type,
            entity_id,
            Utc::now().to_rfc3339(),
            detail,
        ],
    )?;
    Ok(())
}

/// Query audit events with optional filters.
pub fn list_audit(
    pool: &DbPool,
    actor: Option<&str>,
    action: Option<&str>,
    limit: i64,
) -> AppResult<Vec<AuditEvent>> {
    let conn = pool.get()?;
    let mut sql = String::from(
        "SELECT id, actor, action, entity_type, entity_id, timestamp, detail \
         FROM audit_event WHERE 1=1",
    );
    let mut binds: Vec<String> = Vec::new();
    if let Some(a) = actor {
        sql.push_str(&format!(" AND actor = ?{}", binds.len() + 1));
        binds.push(a.to_string());
    }
    if let Some(a) = action {
        sql.push_str(&format!(" AND action = ?{}", binds.len() + 1));
        binds.push(a.to_string());
    }
    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", binds.len() + 1));
    binds.push(limit.to_string());

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        let ts: String = row.get("timestamp")?;
        Ok(AuditEvent {
            id: row.get("id")?,
            actor: row.get("actor")?,
            action: row.get("action")?,
            entity_type: row.get("entity_type")?,
            entity_id: row.get("entity_id")?,
            timestamp: parse_ts(&ts),
            detail: row.get("detail")?,
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
