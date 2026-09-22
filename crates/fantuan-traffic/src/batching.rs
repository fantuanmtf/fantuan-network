//! Epoch batching and timing jitter (mix-lite).
//!
//! Outgoing traffic for one epoch is released together, so an observer sees
//! a burst rather than per-message timings. Jitter adds a small random delay
//! per frame. This is a lightweight approximation of a mix; a full mixnet is
//! deferred to a later hardening phase.

use getrandom::fill;

/// Default epoch length in milliseconds.
pub const EPOCH_MS: u64 = 10_000;
/// Maximum jitter applied per frame.
pub const MAX_JITTER_MS: u64 = 250;

/// Collects frames until the next epoch boundary.
#[derive(Debug)]
pub struct EpochBatcher {
    epoch_ms: u64,
    current_epoch: u64,
    pending: Vec<Vec<u8>>,
}

impl EpochBatcher {
    /// Create a batcher with the given epoch length.
    pub fn new(epoch_ms: u64) -> Self {
        Self {
            epoch_ms: epoch_ms.max(1),
            current_epoch: 0,
            pending: Vec::new(),
        }
    }

    /// Queue a frame for the next release.
    pub fn push(&mut self, frame: Vec<u8>) {
        self.pending.push(frame);
    }

    /// Number of queued frames.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Release everything when `now_ms` crossed into a new epoch.
    pub fn flush(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let epoch = now_ms / self.epoch_ms;
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
            std::mem::take(&mut self.pending)
        } else {
            Vec::new()
        }
    }
}

/// Random jitter in `0..=MAX_JITTER_MS` milliseconds (0 when entropy fails).
pub fn jitter_millis() -> u64 {
    let mut bytes = [0u8; 8];
    if fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes) % (MAX_JITTER_MS + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_release_on_epoch_boundary() {
        let mut batcher = EpochBatcher::new(1000);
        batcher.push(b"one".to_vec());
        batcher.push(b"two".to_vec());
        assert_eq!(batcher.len(), 2);

        // Same epoch: nothing is released.
        assert!(batcher.flush(500).is_empty());
        assert!(batcher.flush(999).is_empty());

        // New epoch: everything is released at once.
        let released = batcher.flush(1000);
        assert_eq!(released.len(), 2);
        assert!(batcher.is_empty());
        assert!(batcher.flush(1500).is_empty());
    }

    #[test]
    fn jitter_is_bounded() {
        for _ in 0..100 {
            assert!(jitter_millis() <= MAX_JITTER_MS);
        }
    }
}
