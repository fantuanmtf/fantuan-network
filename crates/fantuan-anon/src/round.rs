//! Round tracking and share collection.

use crate::error::{AnonError, Result};
use crate::share::{xor_all, xor_in_place};
use fantuan_msg::DCNET_MAX_DEADLINE_SECS;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Single monotonic round counter.
///
/// Round ids may only advance by exactly one, so a malicious far-future id
/// cannot push a node past legitimate rounds (split-brain hardening).
pub struct RoundTracker {
    current_round_id: u64,
}

impl Default for RoundTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundTracker {
    /// Start at round zero.
    pub fn new() -> Self {
        Self {
            current_round_id: 0,
        }
    }

    /// Current round id.
    pub fn current(&self) -> u64 {
        self.current_round_id
    }

    /// Advance by exactly one (initiator side).
    pub fn next_round(&mut self) -> u64 {
        self.current_round_id += 1;
        self.current_round_id
    }

    /// Accept a round id observed from the network; only `current + 1`.
    pub fn mark_seen(&mut self, round_id: u64) -> bool {
        if round_id == self.current_round_id + 1 {
            self.current_round_id = round_id;
            true
        } else {
            false
        }
    }

    /// True when the round id already passed.
    pub fn is_stale(&self, round_id: u64) -> bool {
        round_id <= self.current_round_id
    }
}

/// Collects shares for one round.
pub struct RoundCollector {
    /// Channel label.
    pub channel: String,
    /// Round id.
    pub round_id: u64,
    /// Initiator fingerprint.
    pub initiator: String,
    /// Expected participants.
    pub participants: HashSet<String>,
    /// Received shares by fingerprint.
    pub shares: HashMap<String, Vec<u8>>,
    /// Deadline.
    pub deadline: Instant,
    /// Expected share length.
    pub payload_len: usize,
}

impl RoundCollector {
    /// Create a collector, clamping the deadline to the protocol maximum.
    pub fn new(
        channel: &str,
        round_id: u64,
        initiator: &str,
        participants: &[String],
        deadline_secs: u64,
        payload_len: usize,
    ) -> Result<Self> {
        if participants.len() < 2 {
            return Err(AnonError::Round(
                "need at least two participants".to_string(),
            ));
        }
        if !(36..=fantuan_msg::DCNET_MAX_PAYLOAD_LEN).contains(&payload_len) {
            return Err(AnonError::Round("payload length out of range".to_string()));
        }
        Ok(Self {
            channel: channel.to_string(),
            round_id,
            initiator: initiator.to_string(),
            participants: participants.iter().cloned().collect(),
            shares: HashMap::new(),
            deadline: Instant::now()
                + Duration::from_secs(deadline_secs.clamp(1, DCNET_MAX_DEADLINE_SECS)),
            payload_len,
        })
    }

    /// True when the deadline passed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// True when every participant submitted.
    pub fn is_complete(&self) -> bool {
        self.shares.len() >= self.participants.len()
    }

    /// Submit a share, rejecting outsiders, duplicates and wrong lengths.
    pub fn submit_share(&mut self, peer_uid: &str, share: &[u8]) -> Result<()> {
        if !self.participants.contains(peer_uid) {
            return Err(AnonError::Round(format!(
                "{peer_uid} is not a participant of round {}",
                self.round_id
            )));
        }
        if self.shares.contains_key(peer_uid) {
            return Err(AnonError::Round(format!("duplicate share from {peer_uid}")));
        }
        if share.len() != self.payload_len {
            return Err(AnonError::Round(format!(
                "share length {} does not match {}",
                share.len(),
                self.payload_len
            )));
        }
        self.shares.insert(peer_uid.to_string(), share.to_vec());
        Ok(())
    }

    /// Participants that have not submitted yet, sorted.
    pub fn missing_participants(&self) -> Vec<String> {
        let mut missing: Vec<String> = self
            .participants
            .iter()
            .filter(|participant| !self.shares.contains_key(*participant))
            .cloned()
            .collect();
        missing.sort();
        missing
    }

    /// Number of received shares.
    pub fn received_count(&self) -> usize {
        self.shares.len()
    }

    /// XOR all received shares.
    pub fn extract(&self) -> Option<Vec<u8>> {
        if self.shares.is_empty() {
            return None;
        }
        let shares: Vec<Vec<u8>> = self.shares.values().cloned().collect();
        Some(xor_all(&shares, self.payload_len))
    }
}

/// XOR a padded message into a share (used by the driver).
pub fn add_message(share: &mut [u8], padded: &[u8]) {
    xor_in_place(share, padded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_msg::{pad_message, unpad_message};

    #[test]
    fn tracker_only_advances_by_one() {
        let mut tracker = RoundTracker::new();
        assert!(tracker.mark_seen(1));
        assert!(!tracker.mark_seen(3));
        assert!(!tracker.mark_seen(100));
        assert_eq!(tracker.current(), 1);
        assert!(tracker.is_stale(1));
        assert_eq!(tracker.next_round(), 2);
        assert!(tracker.mark_seen(3));
    }

    #[test]
    fn collector_rejects_outsiders_duplicates_and_lengths() {
        let participants = vec!["A".to_string(), "B".to_string()];
        let mut collector =
            RoundCollector::new("#g", 1, "A", &participants, 10, 64).expect("collector");
        assert!(collector.submit_share("EVE", &[0u8; 64]).is_err());
        collector.submit_share("A", &[1u8; 64]).expect("first");
        assert!(collector.submit_share("A", &[2u8; 64]).is_err());
        assert!(collector.submit_share("B", &[0u8; 32]).is_err());
        assert_eq!(collector.missing_participants(), vec!["B".to_string()]);
        collector.submit_share("B", &[3u8; 64]).expect("second");
        assert!(collector.is_complete());
        assert_eq!(collector.received_count(), 2);
    }

    #[test]
    fn extract_cancels_shares_and_recovers_message() {
        let mut collector =
            RoundCollector::new("#g", 1, "A", &["A".to_string(), "B".to_string()], 10, 128)
                .expect("collector");
        let message = b"hello";
        let padded = pad_message(message, 128).expect("pad");
        collector.submit_share("A", &padded).expect("A");
        collector.submit_share("B", &[0u8; 128]).expect("B");
        let extracted = collector.extract().expect("extract");
        assert_eq!(unpad_message(&extracted).as_deref(), Some(&message[..]));
    }

    #[test]
    fn deadline_is_clamped() {
        let participants = vec!["A".to_string(), "B".to_string()];
        let collector =
            RoundCollector::new("#g", 1, "A", &participants, u64::MAX, 64).expect("collector");
        assert!(!collector.is_expired());
    }
}
