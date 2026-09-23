//! Round tracking and share collection.

use crate::error::{AnonError, Result};
use crate::share::{xor_all, xor_in_place};
use fantuan_msg::DCNET_MAX_DEADLINE_SECS;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// How far ahead of the local clock an announced round id may be, in
/// milliseconds.
///
/// Bounds how far a malicious peer can push the counter, without rejecting the
/// legitimate rounds of a peer whose clock runs slightly fast.
pub const MAX_FUTURE_SKEW_MS: u64 = 30_000;

/// Granularity of round ids, in milliseconds.
///
/// Initiators that start within the same window produce the *same* id, which
/// the driver resolves with its deterministic initiator tie-break: one round
/// proceeds, the other is retried. Two rounds that ran concurrently under one
/// id would mix their shares, so a collision must be resolved, never merged.
pub const ROUND_ID_GRANULARITY_MS: u64 = 100;

/// Monotonic round counter with a clock floor.
///
/// Round ids are wall-clock milliseconds of the initiator, floored by the
/// highest id seen so far. Two properties follow, and both are needed:
///
/// * Ids advance even for a node that never observed a round (its own clock
///   moves), so counters cannot diverge and leave one node unable to initiate
///   while its peers wait for ids that will never arrive. A pure
///   `current + 1` counter had exactly that failure: one missed round, or one
///   difference in participant sets, desynchronised a node permanently.
/// * An id at or below the current one is stale and rejected (replay
///   hardening), and an id beyond [`MAX_FUTURE_SKEW_MS`] is refused
///   (split-brain hardening).
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

    /// Next round id we may initiate, given the current time in milliseconds.
    pub fn next_round(&mut self, now_ms: u64) -> u64 {
        let base = (now_ms / ROUND_ID_GRANULARITY_MS) * ROUND_ID_GRANULARITY_MS;
        self.current_round_id = self.current_round_id.max(base).saturating_add(1);
        self.current_round_id
    }

    /// Accept a round id observed from the network.
    ///
    /// Accepted when it is ahead of the current id and not implausibly far in
    /// the future; stale ids and far-future ids are rejected.
    pub fn mark_seen(&mut self, round_id: u64, now_ms: u64) -> bool {
        if round_id <= self.current_round_id || round_id > now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
        {
            return false;
        }
        self.current_round_id = round_id;
        true
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
    fn tracker_uses_the_clock_and_stays_monotonic() {
        let mut tracker = RoundTracker::new();
        let first = tracker.next_round(1_000);
        assert_eq!(first, 1_001);
        assert!(
            tracker.mark_seen(first + 1_000, 1_500),
            "a peer's later round is accepted"
        );
        assert_eq!(tracker.current(), first + 1_000);
        assert!(
            tracker.next_round(1_500) > first + 1_000,
            "our next id stays ahead of everything seen"
        );
    }

    #[test]
    fn tracker_rejects_stale_and_far_future_ids() {
        let mut tracker = RoundTracker::new();
        assert!(tracker.mark_seen(5_000, 4_000));
        assert!(!tracker.mark_seen(4_999, 4_000), "stale id");
        assert!(!tracker.mark_seen(5_000, 4_000), "replay");
        assert!(tracker.is_stale(5_000));
        assert!(
            !tracker.mark_seen(4_000 + MAX_FUTURE_SKEW_MS + 1, 4_000),
            "an id beyond the skew bound must not burn the id space"
        );
        assert!(tracker.mark_seen(4_000 + MAX_FUTURE_SKEW_MS, 4_000));
    }

    #[test]
    fn a_lagging_node_can_still_initiate() {
        // The regression that a plain `current + 1` counter caused: a node
        // that never saw a round is far behind its peers and every start it
        // sends is rejected as stale, so it can never initiate again.
        let mut lagging = RoundTracker::new();
        let mut ahead = RoundTracker::new();
        assert!(ahead.mark_seen(9_000, 9_000));
        assert!(ahead.mark_seen(9_500, 9_500));

        let mine = lagging.next_round(9_600);
        assert!(mine > 9_500, "a clock-based id is comparable, not behind");
        assert!(ahead.mark_seen(mine, 9_600), "the ahead node accepts it");
    }

    #[test]
    fn a_fresh_tracker_accepts_any_past_id() {
        // Documents the replay window after a restart: staleness is measured
        // against in-memory state (`current_round_id` starts at 0), and the
        // only other bound is on the *future*. A process that has just
        // started therefore accepts a round id from any time in the past.
        let mut tracker = RoundTracker::new();
        let ancient = 1;
        assert!(
            tracker.mark_seen(ancient, 1_700_000_000_000),
            "an id from any earlier time passes"
        );
    }

    #[test]
    fn a_receiver_more_than_thirty_seconds_behind_rejects_honest_starts() {
        // The tolerance is two-sided: an honest id is approximately real time,
        // so a receiver whose clock lags by more than the future bound sees it
        // as impossibly far ahead.
        let now = 1_700_000_000_000;
        let mut behind = RoundTracker::new();
        assert!(
            !behind.mark_seen(now, now - 31_000),
            "a clock 31 s behind rejects an honest round"
        );
        let mut nearly = RoundTracker::new();
        assert!(
            nearly.mark_seen(now, now - 29_000),
            "29 s behind still works"
        );
    }

    #[test]
    fn an_initiator_behind_the_latest_round_cannot_start_one() {
        // Initiation is bounded by the high-water mark, not by the 30 s
        // window: the id must exceed what peers have already seen, and that is
        // approximately the newest round's timestamp.
        let now = 1_700_000_000_000;
        let mut ahead = RoundTracker::new();
        assert!(ahead.mark_seen(now, now));

        let mut behind = RoundTracker::new();
        let id = behind.next_round(now - 5_000);
        assert!(
            !ahead.mark_seen(id, now),
            "a clock 5 s behind the newest round produces a stale start"
        );
    }

    #[test]
    fn the_future_bound_is_strict() {
        let now = 1_700_000_000_000;
        let mut at_bound = RoundTracker::new();
        assert!(
            at_bound.mark_seen(now + MAX_FUTURE_SKEW_MS, now),
            "exactly at the bound is accepted"
        );
        let mut beyond = RoundTracker::new();
        assert!(
            !beyond.mark_seen(now + MAX_FUTURE_SKEW_MS + 1, now),
            "one millisecond past the bound is rejected"
        );
    }

    #[test]
    fn simultaneous_initiators_agree_on_the_same_id() {
        // Same window means the same id, which the driver resolves by
        // initiator tie-break; different ids would silently make one round
        // invisible to the other node.
        let mut alice = RoundTracker::new();
        let mut bob = RoundTracker::new();
        assert_eq!(alice.next_round(1_040), bob.next_round(1_060));
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
