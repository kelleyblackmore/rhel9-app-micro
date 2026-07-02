use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovLimiter};

type DirectLimiter = GovLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// A simple keyed in-memory token-bucket rate limiter built on `governor`.
///
/// One limiter per client key (JWT subject or IP). Allows `per_minute`
/// requests per 60s window with a burst equal to the per-minute allowance.
pub struct RateLimiter {
    per_minute: NonZeroU32,
    clock: DefaultClock,
    buckets: Mutex<HashMap<String, DirectLimiter>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        let per_minute = NonZeroU32::new(per_minute.max(1)).unwrap();
        RateLimiter {
            per_minute,
            clock: DefaultClock::default(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request for `key` is allowed, false if limited.
    pub fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let clock = &self.clock;
        let limiter = buckets.entry(key.to_string()).or_insert_with(|| {
            let quota = Quota::per_minute(self.per_minute);
            GovLimiter::direct_with_clock(quota, clock)
        });
        limiter.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let rl = RateLimiter::new(3);
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        // 4th within the same window should be blocked.
        assert!(!rl.check("a"));
        // Different key is independent.
        assert!(rl.check("b"));
    }
}
