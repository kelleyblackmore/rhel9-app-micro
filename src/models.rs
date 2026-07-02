use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A user role for RBAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

/// A seeded user (in-memory).
#[derive(Clone, Debug)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
}

/// Task status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Todo,
    Doing,
    Done,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Todo => "todo",
            TaskStatus::Doing => "doing",
            TaskStatus::Done => "done",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<TaskStatus> {
        match s {
            "todo" => Some(TaskStatus::Todo),
            "doing" => Some(TaskStatus::Doing),
            "done" => Some(TaskStatus::Done),
            _ => None,
        }
    }
}

/// A task record.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: TaskStatus,
    pub owner: String,
    #[schema(value_type = String, format = DateTime)]
    pub created_at: DateTime<Utc>,
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: DateTime<Utc>,
}

/// Request body for creating a task.
#[derive(Clone, Debug, Deserialize, ToSchema)]
pub struct CreateTask {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub status: Option<TaskStatus>,
}

/// Request body for updating a task. Fields are optional (partial update).
#[derive(Clone, Debug, Deserialize, ToSchema)]
pub struct UpdateTask {
    pub title: Option<String>,
    pub description: Option<String>,
    pub status: Option<TaskStatus>,
}

impl CreateTask {
    /// Basic manual validation. Returns an error message on failure.
    pub fn validate(&self) -> Result<(), String> {
        let title = self.title.trim();
        if title.is_empty() {
            return Err("title must not be empty".to_string());
        }
        if title.len() > 200 {
            return Err("title must be at most 200 characters".to_string());
        }
        if self.description.len() > 2000 {
            return Err("description must be at most 2000 characters".to_string());
        }
        Ok(())
    }
}

impl UpdateTask {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(title) = &self.title {
            let t = title.trim();
            if t.is_empty() {
                return Err("title must not be empty".to_string());
            }
            if t.len() > 200 {
                return Err("title must be at most 200 characters".to_string());
            }
        }
        if let Some(desc) = &self.description {
            if desc.len() > 2000 {
                return Err("description must be at most 2000 characters".to_string());
            }
        }
        Ok(())
    }
}

/// An append-only audit event.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    #[schema(value_type = String, format = DateTime)]
    pub timestamp: DateTime<Utc>,
    pub detail: String,
}

/// Login request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response containing the signed JWT.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub role: String,
}
