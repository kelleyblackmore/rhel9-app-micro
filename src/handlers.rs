use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{issue_token, verify_password, TOKEN_TTL_SECONDS};
use crate::db;
use crate::error::{AppError, AppResult};
use crate::extract::{AdminUser, AuthUser};
use crate::models::{
    AuditEvent, CreateTask, LoginRequest, LoginResponse, Task, UpdateTask,
};
use crate::state::AppState;

// ----- Query params -----

#[derive(Debug, Deserialize)]
pub struct Pagination {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, 500)
}

fn clamp_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).max(0)
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub limit: Option<i64>,
}

// ----- Auth -----

/// POST /api/auth/login
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login succeeded", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let user = state
        .users
        .get(&req.username)
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_string()))?;

    if !verify_password(&req.password, &user.password_hash) {
        return Err(AppError::Unauthorized("invalid credentials".to_string()));
    }

    let token = issue_token(&state.config.jwt_secret, &user.username, user.role)?;
    Ok(Json(LoginResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: TOKEN_TTL_SECONDS,
        role: user.role.as_str().to_string(),
    }))
}

// ----- Tasks -----

/// GET /api/tasks
#[utoipa::path(
    get,
    path = "/api/tasks",
    params(("limit" = Option<i64>, Query, description = "max rows"),
           ("offset" = Option<i64>, Query, description = "rows to skip")),
    responses((status = 200, description = "List of tasks", body = [Task])),
    security(("bearer_auth" = [])),
    tag = "tasks"
)]
pub async fn list_tasks(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(p): Query<Pagination>,
) -> AppResult<Json<Vec<Task>>> {
    let tasks = db::list_tasks(&state.pool, clamp_limit(p.limit), clamp_offset(p.offset))?;
    Ok(Json(tasks))
}

/// GET /api/tasks/:id
#[utoipa::path(
    get,
    path = "/api/tasks/{id}",
    params(("id" = String, Path, description = "task id")),
    responses((status = 200, description = "A task", body = Task),
              (status = 404, description = "Not found")),
    security(("bearer_auth" = [])),
    tag = "tasks"
)]
pub async fn get_task(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<Task>> {
    let task = db::get_task(&state.pool, &id)?
        .ok_or_else(|| AppError::NotFound("task not found".to_string()))?;
    Ok(Json(task))
}

/// POST /api/tasks
#[utoipa::path(
    post,
    path = "/api/tasks",
    request_body = CreateTask,
    responses((status = 201, description = "Created", body = Task),
              (status = 400, description = "Validation error")),
    security(("bearer_auth" = [])),
    tag = "tasks"
)]
pub async fn create_task(
    State(state): State<AppState>,
    user: AuthUser,
    Json(input): Json<CreateTask>,
) -> AppResult<impl IntoResponse> {
    input.validate().map_err(AppError::BadRequest)?;
    let task = db::create_task(&state.pool, &user.username, &input)?;
    db::record_audit(
        &state.pool,
        &user.username,
        "create",
        "task",
        &task.id,
        &format!("title={}", task.title),
    )?;
    Ok((StatusCode::CREATED, Json(task)))
}

/// PUT /api/tasks/:id
#[utoipa::path(
    put,
    path = "/api/tasks/{id}",
    params(("id" = String, Path, description = "task id")),
    request_body = UpdateTask,
    responses((status = 200, description = "Updated", body = Task),
              (status = 403, description = "Forbidden"),
              (status = 404, description = "Not found")),
    security(("bearer_auth" = [])),
    tag = "tasks"
)]
pub async fn update_task(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<UpdateTask>,
) -> AppResult<Json<Task>> {
    input.validate().map_err(AppError::BadRequest)?;
    let existing = db::get_task(&state.pool, &id)?
        .ok_or_else(|| AppError::NotFound("task not found".to_string()))?;

    if !user.is_admin() && existing.owner != user.username {
        return Err(AppError::Forbidden(
            "you may only modify your own tasks".to_string(),
        ));
    }

    let updated = db::update_task(&state.pool, &existing, &input)?;
    db::record_audit(
        &state.pool,
        &user.username,
        "update",
        "task",
        &updated.id,
        &format!("status={}", updated.status.as_str()),
    )?;
    Ok(Json(updated))
}

/// DELETE /api/tasks/:id
#[utoipa::path(
    delete,
    path = "/api/tasks/{id}",
    params(("id" = String, Path, description = "task id")),
    responses((status = 204, description = "Deleted"),
              (status = 403, description = "Forbidden"),
              (status = 404, description = "Not found")),
    security(("bearer_auth" = [])),
    tag = "tasks"
)]
pub async fn delete_task(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let existing = db::get_task(&state.pool, &id)?
        .ok_or_else(|| AppError::NotFound("task not found".to_string()))?;

    if !user.is_admin() && existing.owner != user.username {
        return Err(AppError::Forbidden(
            "you may only delete your own tasks".to_string(),
        ));
    }

    db::delete_task(&state.pool, &id)?;
    db::record_audit(
        &state.pool,
        &user.username,
        "delete",
        "task",
        &id,
        "",
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- Audit (admin only) -----

/// GET /api/audit
#[utoipa::path(
    get,
    path = "/api/audit",
    params(("actor" = Option<String>, Query, description = "filter by actor"),
           ("action" = Option<String>, Query, description = "filter by action"),
           ("limit" = Option<i64>, Query, description = "max rows")),
    responses((status = 200, description = "Audit events", body = [AuditEvent]),
              (status = 403, description = "Admin required")),
    security(("bearer_auth" = [])),
    tag = "audit"
)]
pub async fn list_audit(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<Vec<AuditEvent>>> {
    let limit = clamp_limit(q.limit);
    let events = db::list_audit(
        &state.pool,
        q.actor.as_deref(),
        q.action.as_deref(),
        limit,
    )?;
    Ok(Json(events))
}

// ----- Health & metrics -----

/// GET /healthz
#[utoipa::path(get, path = "/healthz", responses((status = 200, description = "Alive")), tag = "health")]
pub async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// GET /readyz
#[utoipa::path(
    get,
    path = "/readyz",
    responses((status = 200, description = "Ready"), (status = 503, description = "Not ready")),
    tag = "health"
)]
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match db::ping(&state.pool) {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "reason": "database unavailable" })),
        ),
    }
}
