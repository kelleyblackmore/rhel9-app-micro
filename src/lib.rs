pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod extract;
pub mod handlers;
pub mod models;
pub mod observe;
pub mod openapi;
pub mod ratelimit;
pub mod state;

use axum::routing::get;
use axum::{middleware, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::openapi::ApiDoc;
use crate::state::AppState;

/// Build the full application router given shared state and a metrics handle.
pub fn build_router(state: AppState, metrics_handle: PrometheusHandle) -> Router {
    // Public auth routes.
    let auth_routes = Router::new().route("/login", axum::routing::post(handlers::login));

    // Task routes (require a valid user; enforced via the AuthUser extractor).
    let task_routes = Router::new()
        .route("/", get(handlers::list_tasks).post(handlers::create_task))
        .route(
            "/:id",
            get(handlers::get_task)
                .put(handlers::update_task)
                .delete(handlers::delete_task),
        );

    // Audit routes (admin only; enforced via the AdminUser extractor).
    let audit_routes = Router::new().route("/", get(handlers::list_audit));

    let api = Router::new()
        .nest("/auth", auth_routes)
        .nest("/tasks", task_routes)
        .nest("/audit", audit_routes);

    let metrics_handle_for_route = metrics_handle.clone();

    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route(
            "/metrics",
            get(move || {
                let handle = metrics_handle_for_route.clone();
                async move { handle.render() }
            }),
        )
        .nest("/api", api)
        // Rate limit applies to all routes below. Registered before the metrics
        // middleware so that 429 responses are still counted.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observe::rate_limit,
        ))
        .layer(middleware::from_fn(observe::track_metrics))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Test/helper constructor: build a fully-wired app backed by an in-memory
/// SQLite database with a generous rate limit and a non-global metrics handle.
///
/// Returns the router plus the shared state (so tests can inspect the DB).
pub fn build_test_app() -> (Router, AppState) {
    let config = config::Config {
        jwt_secret: "test-secret".to_string(),
        db_path: ":memory:".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        rate_limit_per_min: 100_000,
    };
    let pool = db::build_pool(":memory:").expect("build in-memory pool");
    db::init_schema(&pool).expect("init schema");
    let users = auth::seed_users();
    let rate_limiter = ratelimit::RateLimiter::new(config.rate_limit_per_min);
    let state = AppState::new(config, pool, users, rate_limiter);
    let handle = observe::build_metrics_handle();
    let router = build_router(state.clone(), handle);
    (router, state)
}
