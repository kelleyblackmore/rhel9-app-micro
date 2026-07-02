use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Application-wide error type. Converts into an HTTP response with a JSON body.
#[derive(Debug)]
pub enum AppError {
    /// 400
    BadRequest(String),
    /// 401
    Unauthorized(String),
    /// 403
    Forbidden(String),
    /// 404
    NotFound(String),
    /// 429
    TooManyRequests,
    /// 500
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(m) => write!(f, "bad request: {m}"),
            AppError::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            AppError::Forbidden(m) => write!(f, "forbidden: {m}"),
            AppError::NotFound(m) => write!(f, "not found: {m}"),
            AppError::TooManyRequests => write!(f, "too many requests"),
            AppError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for AppError {}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            AppError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "rate limit exceeded".to_string(),
            ),
            AppError::Internal(m) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                m.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let body = Json(ErrorBody {
            error: code.to_string(),
            message,
        });
        (status, body).into_response()
    }
}

// Convenient conversions so handlers can use `?`.
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(format!("database error: {e}"))
    }
}

impl From<r2d2::Error> for AppError {
    fn from(e: r2d2::Error) -> Self {
        AppError::Internal(format!("pool error: {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
