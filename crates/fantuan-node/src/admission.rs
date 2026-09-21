//! Relay admission control.
//!
//! Per-origin state: monotonic nonces, freshness window, rate limit and
//! TOFU identity-key pinning. All quotas are keyed by the verified identity
//! key (fingerprint), so many claimed uids cannot multiply the quota.

use anyhow::{Result, bail};
use std::collections::HashMap;

/// Rate limit window in seconds.
pub const RATE_WINDOW_SECS: u64 = 60;
/// Maximum relay envelopes per origin per window.
pub const MAX_PER_WINDOW: u32 = 60;
/// Maximum tracks kept per table (coarse anti-memory-DoS eviction).
pub const MAX_TRACKED: usize = 4096;

/// Relay admission state.
pub struct AdmissionControl {
    last_nonce: HashMap<String, u64>,
    rate: HashMap<String, (u64, u32)>,
    pins: HashMap<String, Vec<u8>>,
}

impl Default for AdmissionControl {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionControl {
    /// Create empty admission state.
    pub fn new() -> Self {
        Self {
            last_nonce: HashMap::new(),
            rate: HashMap::new(),
            pins: HashMap::new(),
        }
    }

    /// TOFU-pin the originator's certificate bytes.
    ///
    /// Ok when the fingerprint is new or unchanged; an error when a different
    /// certificate was pinned before (possible impersonation).
    pub fn pin(&mut self, fingerprint: &str, cert_bytes: &[u8]) -> Result<()> {
        match self.pins.get(fingerprint) {
            None => {
                if self.pins.len() >= MAX_TRACKED {
                    self.pins.clear();
                    tracing::warn!("relay pin table full; cleared");
                }
                self.pins
                    .insert(fingerprint.to_string(), cert_bytes.to_vec());
                Ok(())
            }
            Some(previous) if previous.as_slice() == cert_bytes => Ok(()),
            Some(_) => bail!("relay certificate changed for {fingerprint}"),
        }
    }

    /// Admit or reject one relay envelope.
    ///
    /// Checks nonce monotonicity, the freshness window and the rate limit,
    /// then records the nonce.
    pub fn check(&mut self, fingerprint: &str, nonce: u64, timestamp: u64, now: u64) -> Result<()> {
        if let Some(&last) = self.last_nonce.get(fingerprint) {
            if nonce <= last {
                bail!("replayed relay nonce {nonce} (last {last})");
            }
        }

        if now.abs_diff(timestamp) > crate::relay::MAX_AGE_SECS {
            bail!("relay timestamp {timestamp} outside freshness window");
        }

        if self.rate.len() >= MAX_TRACKED {
            self.rate.clear();
            tracing::warn!("relay rate table full; cleared");
        }
        let (window_start, count) = self.rate.entry(fingerprint.to_string()).or_insert((now, 0));
        if now.abs_diff(*window_start) >= RATE_WINDOW_SECS {
            *window_start = now;
            *count = 0;
        }
        if *count >= MAX_PER_WINDOW {
            bail!("relay rate limit exceeded for {fingerprint}");
        }
        *count += 1;

        if self.last_nonce.len() >= MAX_TRACKED {
            self.last_nonce.clear();
            tracing::warn!("relay nonce table full; cleared");
        }
        self.last_nonce.insert(fingerprint.to_string(), nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replays() {
        let mut control = AdmissionControl::new();
        assert!(control.check("A", 5, 1000, 1000).is_ok());
        assert!(control.check("A", 6, 1000, 1000).is_ok());
        assert!(control.check("A", 6, 1000, 1000).is_err());
        assert!(control.check("A", 5, 1000, 1000).is_err());
    }

    #[test]
    fn rejects_expired() {
        let mut control = AdmissionControl::new();
        assert!(control.check("A", 1, 1000, 1030).is_ok());
        assert!(control.check("A", 2, 1000, 1100).is_err());
        assert!(control.check("A", 2, 2000, 1000).is_err());
    }

    #[test]
    fn rate_limit_per_fingerprint() {
        let mut control = AdmissionControl::new();
        for nonce in 1..=MAX_PER_WINDOW as u64 {
            assert!(control.check("A", nonce, 1000, 1000).is_ok());
        }
        assert!(control.check("A", 1000, 1000, 1000).is_err());
        // A different origin has its own quota.
        assert!(control.check("B", 1, 1000, 1000).is_ok());
        // The window slides.
        assert!(control.check("A", 1001, 1061, 1061).is_ok());
    }

    #[test]
    fn tofu_pin() {
        let mut control = AdmissionControl::new();
        assert!(control.pin("A", b"cert-a").is_ok());
        assert!(control.pin("A", b"cert-a").is_ok());
        assert!(control.pin("A", b"cert-b").is_err());
        assert!(control.pin("B", b"cert-b").is_ok());
    }
}
