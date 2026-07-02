use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::error::AppError;
use crate::state::AppState;

/// Install the Prometheus recorder globally and return a handle for rendering
/// /metrics. Must be called at most once per process (production startup).
pub fn install_metrics() -> PrometheusHandle {
    PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}

/// Build a Prometheus handle WITHOUT installing a global recorder. Used by
/// tests, where the global recorder can only be installed once per process.
pub fn build_metrics_handle() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}

/// Middleware that records request count and latency, labelled by method,
/// route template and status.
pub async fn track_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();

    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let method = req.method().clone();

    let response = next.run(req).await;

    let latency = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    counter!(
        "http_requests_total",
        "method" => method.to_string(),
        "path" => path.clone(),
        "status" => status.clone(),
    )
    .increment(1);

    histogram!(
        "http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path,
    )
    .record(latency);

    response
}

/// Middleware enforcing a per-client rate limit. The client key is the JWT
/// subject when present, otherwise the peer's connection info / IP header.
pub async fn rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let key = client_key(&state, &req);
    if !state.rate_limiter.check(&key) {
        return AppError::TooManyRequests.into_response();
    }
    next.run(req).await
}

/// Derive a rate-limit key. Prefer the authenticated subject; fall back to
/// X-Forwarded-For / X-Real-IP header, else a shared "anonymous" bucket.
fn client_key(state: &AppState, req: &Request) -> String {
    if let Some(header) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(value) = header.to_str() {
            let token = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "));
            if let Some(tok) = token {
                if let Ok(claims) =
                    crate::auth::decode_token(&state.config.jwt_secret, tok.trim())
                {
                    return format!("sub:{}", claims.sub);
                }
            }
        }
    }

    for h in ["x-forwarded-for", "x-real-ip"] {
        if let Some(val) = req.headers().get(h) {
            if let Ok(s) = val.to_str() {
                if let Some(first) = s.split(',').next() {
                    let ip = first.trim();
                    if !ip.is_empty() {
                        return format!("ip:{ip}");
                    }
                }
            }
        }
    }

    "ip:anonymous".to_string()
}
