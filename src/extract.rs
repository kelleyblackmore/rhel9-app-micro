use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::{decode_token, Claims};
use crate::error::AppError;
use crate::models::Role;
use crate::state::AppState;

/// An authenticated principal derived from a validated Bearer JWT.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
    #[allow(dead_code)]
    pub claims: Claims,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

fn bearer_token(parts: &Parts) -> Result<String, AppError> {
    let header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = header
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| AppError::Unauthorized("expected Bearer token".to_string()))?;
    Ok(token.trim().to_string())
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)?;
        let claims = decode_token(&state.config.jwt_secret, &token)?;
        let role = claims
            .role()
            .ok_or_else(|| AppError::Unauthorized("unknown role in token".to_string()))?;
        Ok(AuthUser {
            username: claims.sub.clone(),
            role,
            claims,
        })
    }
}

/// An authenticated admin principal. Rejects non-admins with 403.
#[derive(Clone, Debug)]
pub struct AdminUser(pub AuthUser);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.role != Role::Admin {
            return Err(AppError::Forbidden("admin role required".to_string()));
        }
        Ok(AdminUser(user))
    }
}
