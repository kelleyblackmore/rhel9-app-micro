use std::collections::HashMap;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::models::{Role, User};

/// JWT lifetime in seconds.
pub const TOKEN_TTL_SECONDS: i64 = 3600;

/// JWT claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (username).
    pub sub: String,
    /// Role string ("admin" | "user").
    pub role: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued at (unix seconds).
    pub iat: i64,
}

impl Claims {
    pub fn role(&self) -> Option<Role> {
        Role::from_str(&self.role)
    }
}

/// Hash a plaintext password using Argon2id.
pub fn hash_password(plain: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("hash error: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC hash string.
pub fn verify_password(plain: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

/// Seed the two default users. Panics only if hashing fails (startup only).
pub fn seed_users() -> HashMap<String, User> {
    let mut users = HashMap::new();

    let admin_hash = hash_password("admin123").expect("hash admin password");
    users.insert(
        "admin".to_string(),
        User {
            username: "admin".to_string(),
            password_hash: admin_hash,
            role: Role::Admin,
        },
    );

    let user_hash = hash_password("user123").expect("hash user password");
    users.insert(
        "user".to_string(),
        User {
            username: "user".to_string(),
            password_hash: user_hash,
            role: Role::User,
        },
    );

    users
}

/// Create and sign a JWT for the given user.
pub fn issue_token(secret: &str, username: &str, role: Role) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = now + Duration::seconds(TOKEN_TTL_SECONDS);
    let claims = Claims {
        sub: username.to_string(),
        role: role.as_str().to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt encode error: {e}")))
}

/// Validate a JWT and return its claims.
pub fn decode_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    let mut validation = Validation::default(); // HS256 by default
    validation.validate_exp = true;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized("invalid or expired token".to_string()))?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("secret").unwrap();
        assert!(verify_password("secret", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn token_roundtrip() {
        let secret = "test-secret";
        let tok = issue_token(secret, "alice", Role::Admin).unwrap();
        let claims = decode_token(secret, &tok).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.role(), Some(Role::Admin));
    }

    #[test]
    fn token_rejects_bad_secret() {
        let tok = issue_token("secret-a", "bob", Role::User).unwrap();
        assert!(decode_token("secret-b", &tok).is_err());
    }
}
