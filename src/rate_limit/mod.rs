use std::collections::HashMap;
use std::time::Instant;

use crate::domain::ServerId;

pub struct RateLimitConfig {
    pub max_calls_per_minute: Option<u32>,
    pub max_message_bytes: Option<usize>,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity / 60.0,
            last_refill: now,
        }
    }

    fn check(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: HashMap<ServerId, TokenBucket>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
        }
    }

    pub fn check_message_size(&self, bytes: usize) -> bool {
        self.config.max_message_bytes.is_none_or(|max| bytes <= max)
    }

    pub fn check_tool_call(&mut self, server_id: &ServerId, now: Instant) -> bool {
        let capacity = match self.config.max_calls_per_minute {
            Some(n) => n as f64,
            None => return true,
        };
        let bucket = self
            .buckets
            .entry(server_id.clone())
            .or_insert_with(|| TokenBucket::new(capacity, now));
        bucket.check(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_id() -> ServerId {
        ServerId::parse("test-server".to_owned()).unwrap()
    }

    #[test]
    fn no_limit_always_allows() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: None,
            max_message_bytes: None,
        });
        let now = Instant::now();
        let id = server_id();
        for _ in 0..1000 {
            assert!(limiter.check_tool_call(&id, now));
        }
    }

    #[test]
    fn burst_up_to_capacity_then_blocked() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: Some(5),
            max_message_bytes: None,
        });
        let now = Instant::now();
        let id = server_id();
        for _ in 0..5 {
            assert!(limiter.check_tool_call(&id, now));
        }
        assert!(!limiter.check_tool_call(&id, now));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: Some(60),
            max_message_bytes: None,
        });
        let id = server_id();
        let t0 = Instant::now();
        for _ in 0..60 {
            limiter.check_tool_call(&id, t0);
        }
        assert!(!limiter.check_tool_call(&id, t0));

        // 60 tokens/min = 1 token/sec; one second later the bucket has exactly 1 token
        let t1 = t0 + std::time::Duration::from_secs(1);
        assert!(limiter.check_tool_call(&id, t1));
        assert!(!limiter.check_tool_call(&id, t1));
    }

    #[test]
    fn full_refill_after_one_minute() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: Some(10),
            max_message_bytes: None,
        });
        let id = server_id();
        let t0 = Instant::now();
        for _ in 0..10 {
            limiter.check_tool_call(&id, t0);
        }
        assert!(!limiter.check_tool_call(&id, t0));

        let t1 = t0 + std::time::Duration::from_secs(60);
        for _ in 0..10 {
            assert!(limiter.check_tool_call(&id, t1));
        }
        assert!(!limiter.check_tool_call(&id, t1));
    }

    #[test]
    fn size_check_accepts_at_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: None,
            max_message_bytes: Some(100),
        });
        assert!(limiter.check_message_size(100));
        assert!(!limiter.check_message_size(101));
    }

    #[test]
    fn size_check_no_limit_always_accepts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_calls_per_minute: None,
            max_message_bytes: None,
        });
        assert!(limiter.check_message_size(usize::MAX));
    }
}
