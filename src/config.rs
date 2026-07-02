use std::env;

/// Runtime configuration sourced from environment variables with sane defaults.
#[derive(Clone, Debug)]
pub struct Config {
    pub jwt_secret: String,
    pub db_path: String,
    pub bind_addr: String,
    /// Requests allowed per minute per client.
    pub rate_limit_per_min: u32,
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "dev-insecure-change-me-secret-key".to_string());
        let db_path =
            env::var("DB_PATH").unwrap_or_else(|_| "/app/data/secureledger.db".to_string());
        let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let rate_limit_per_min = env::var("RATE_LIMIT_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        Config {
            jwt_secret,
            db_path,
            bind_addr,
            rate_limit_per_min,
        }
    }
}
