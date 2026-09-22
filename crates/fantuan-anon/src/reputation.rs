//! Dropout tracking and eviction.
//!
//! Every time a round expires with missing shares, the missing participants
//! collect a strike. After [`MAX_STRIKES`] consecutive strikes a node is
//! evicted from future rounds until explicitly reinstated.

use std::collections::{HashMap, HashSet};

/// Strikes before eviction.
pub const MAX_STRIKES: u32 = 3;

/// Per-peer strike counters.
#[derive(Debug, Default)]
pub struct ReputationTracker {
    strikes: HashMap<String, u32>,
    evicted: HashSet<String>,
}

impl ReputationTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a round dropout for `uid`.
    ///
    /// Returns true when the peer was evicted by this strike.
    pub fn penalize(&mut self, uid: &str) -> bool {
        let strikes = self.strikes.entry(uid.to_string()).or_insert(0);
        *strikes += 1;
        if *strikes >= MAX_STRIKES && self.evicted.insert(uid.to_string()) {
            tracing::warn!(
                peer = uid,
                "evicted from DC-Net rounds after {strikes} strikes"
            );
            return true;
        }
        false
    }

    /// Clear strikes after a successful round.
    pub fn reward(&mut self, uid: &str) {
        self.strikes.insert(uid.to_string(), 0);
    }

    /// Current strike count.
    pub fn strikes(&self, uid: &str) -> u32 {
        self.strikes.get(uid).copied().unwrap_or(0)
    }

    /// True when the peer is evicted.
    pub fn is_evicted(&self, uid: &str) -> bool {
        self.evicted.contains(uid)
    }

    /// Evicted peers, sorted.
    pub fn evicted(&self) -> Vec<String> {
        let mut peers: Vec<String> = self.evicted.iter().cloned().collect();
        peers.sort();
        peers
    }

    /// Allow an evicted peer to participate again.
    pub fn reinstate(&mut self, uid: &str) {
        self.evicted.remove(uid);
        self.strikes.insert(uid.to_string(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strikes_accumulate_and_evict() {
        let mut tracker = ReputationTracker::new();
        assert!(!tracker.penalize("bob"));
        assert!(!tracker.penalize("bob"));
        assert!(tracker.penalize("bob"), "third strike evicts");
        assert!(tracker.is_evicted("bob"));
        assert_eq!(tracker.evicted(), vec!["bob".to_string()]);
        assert_eq!(tracker.strikes("bob"), 3);
    }

    #[test]
    fn reward_clears_strikes() {
        let mut tracker = ReputationTracker::new();
        tracker.penalize("bob");
        tracker.reward("bob");
        assert_eq!(tracker.strikes("bob"), 0);
        assert!(!tracker.is_evicted("bob"));
    }

    #[test]
    fn reinstate_clears_eviction() {
        let mut tracker = ReputationTracker::new();
        for _ in 0..MAX_STRIKES {
            tracker.penalize("bob");
        }
        assert!(tracker.is_evicted("bob"));
        tracker.reinstate("bob");
        assert!(!tracker.is_evicted("bob"));
        assert_eq!(tracker.strikes("bob"), 0);
    }
}
