use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::handlers;
use crate::models::{
    AuditEvent, CreateTask, LoginRequest, LoginResponse, Task, TaskStatus, UpdateTask,
};

/// Adds the bearer_auth security scheme to the generated spec.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::login,
        handlers::list_tasks,
        handlers::get_task,
        handlers::create_task,
        handlers::update_task,
        handlers::delete_task,
        handlers::list_audit,
        handlers::healthz,
        handlers::readyz,
    ),
    components(schemas(
        LoginRequest,
        LoginResponse,
        Task,
        TaskStatus,
        CreateTask,
        UpdateTask,
        AuditEvent,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Authentication"),
        (name = "tasks", description = "Task CRUD"),
        (name = "audit", description = "Audit log (admin)"),
        (name = "health", description = "Health & readiness"),
    ),
    info(
        title = "SecureLedger API",
        version = "0.1.0",
        description = "A secure task & audit REST API."
    )
)]
pub struct ApiDoc;
