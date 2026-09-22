//! Token-bucket rate limiting.
//!
//! Used on connections to bound how many inbound frames a peer can deliver
//! per second. Over-limit frames are dropped (not disconnected), so a
//! misbehaving peer cannot consume unbounded processing while legitimate
//! traffic keeps flowing.

use std::time::Instant;

/// Token bucket with fractional refill.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl RateLimiter {
    /// Create a limiter allowing `capacity` frames per second.
    pub fn new(capacity: u32) -> Self {
        let capacity = capacity.max(1) as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: capacity,
            last: Instant::now(),
        }
    }

    /// Try to consume one token at `now`.
    ///
    /// Returns false when the bucket is empty; the caller should drop the
    /// frame but keep the connection.
    pub fn check_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to consume one token at the current time.
    pub fn check(&mut self) -> bool {
        self.check_at(Instant::now())
    }

    /// Configured capacity (frames per second).
    pub fn capacity(&self) -> u32 {
        self.capacity as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_burst_up_to_capacity_then_denies() {
        let mut limiter = RateLimiter::new(3);
        let start = Instant::now();
        assert!(limiter.check_at(start));
        assert!(limiter.check_at(start));
        assert!(limiter.check_at(start));
        assert!(!limiter.check_at(start), "fourth frame in the same instant");
    }

    #[test]
    fn refills_over_time() {
        let mut limiter = RateLimiter::new(2);
        let start = Instant::now();
        assert!(limiter.check_at(start));
        assert!(limiter.check_at(start));
        assert!(!limiter.check_at(start));
        // Half a second at 2/s refills one token.
        let later = start + Duration::from_millis(500);
        assert!(limiter.check_at(later));
        assert!(!limiter.check_at(later));
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut limiter = RateLimiter::new(2);
        let start = Instant::now();
        assert!(limiter.check_at(start));
        // A long idle period must not accumulate an unbounded burst.
        let later = start + Duration::from_secs(60);
        assert!(limiter.check_at(later));
        assert!(limiter.check_at(later));
        assert!(!limiter.check_at(later));
    }

    #[test]
    fn zero_capacity_is_clamped() {
        let limiter = RateLimiter::new(0);
        assert_eq!(limiter.capacity(), 1);
    }
}
