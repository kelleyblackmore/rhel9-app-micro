use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::db::DbPool;
use crate::models::User;
use crate::ratelimit::RateLimiter;

/// Shared application state, cheaply cloneable (Arc-wrapped internals).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: DbPool,
    pub users: Arc<HashMap<String, User>>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(
        config: Config,
        pool: DbPool,
        users: HashMap<String, User>,
        rate_limiter: RateLimiter,
    ) -> Self {
        AppState {
            config: Arc::new(config),
            pool,
            users: Arc::new(users),
            rate_limiter: Arc::new(rate_limiter),
        }
    }
}
