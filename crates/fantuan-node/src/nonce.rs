//! Restart-safe relay nonce allocation.
//!
//! Relay admission requires strictly increasing nonces per origin
//! ([`crate::admission`]), so a node must never hand out a nonce it has used
//! before — not even across a restart. Peers keep the previous high-water
//! mark in memory and treat a lower nonce as a replay, which used to tear the
//! session down and made every restart look like an attack.
//!
//! Two mechanisms keep the counter monotonic:
//!
//! 1. A reservation block is persisted *before* any nonce inside it is handed
//!    out, so a crash can only skip values, never repeat them.
//! 2. The counter also starts at the current wall-clock time in milliseconds,
//!    so a node whose state file was lost (or whose clock runs behind) does
//!    not restart below values peers may already have observed.
//!
//! A node with no state path keeps mechanism 2 only; that is enough for the
//! in-process tests, which do not write to the user's data directory.

use fantuan_core::fs::write_private_file;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Values reserved by one durable write.
pub const RESERVE_BLOCK: u64 = 1024;

/// Monotonic nonce source with an optional durable reservation file.
pub struct RelayNonce {
    value: AtomicU64,
    reservation: AtomicU64,
    path: Option<PathBuf>,
    write_lock: Mutex<()>,
}

impl RelayNonce {
    /// Load the reservation stored at `path` (if any) and start above it and
    /// above the current wall clock.
    pub fn load(path: Option<PathBuf>) -> Self {
        Self::at(path, fantuan_core::time::now_unix_millis() as u64)
    }

    /// [`RelayNonce::load`] with an explicit clock, so tests can simulate a
    /// restart within the same millisecond or a clock that runs backwards.
    pub fn at(path: Option<PathBuf>, now_ms: u64) -> Self {
        let persisted = path.as_deref().and_then(read_reservation).unwrap_or(0);
        let start = persisted.max(now_ms);
        Self {
            value: AtomicU64::new(start),
            reservation: AtomicU64::new(start),
            path,
            write_lock: Mutex::new(()),
        }
    }

    /// Next nonce. Reserves a fresh block on disk before returning a value
    /// that the current reservation does not cover yet.
    pub fn next(&self) -> u64 {
        let value = self.value.fetch_add(1, Ordering::Relaxed) + 1;
        if value >= self.reservation.load(Ordering::Relaxed) {
            self.reserve(value.saturating_add(RESERVE_BLOCK));
        }
        value
    }

    /// Highest value covered by the durable reservation.
    pub fn reservation(&self) -> u64 {
        self.reservation.load(Ordering::Relaxed)
    }

    /// Extend the reservation to `upto` and persist it. Never lowers it.
    ///
    /// The lock serialises the compare-and-swap with the write so the file can
    /// only ever move forward.
    fn reserve(&self, upto: u64) {
        let _guard = self.write_lock.lock();
        let mut current = self.reservation.load(Ordering::Relaxed);
        while upto > current {
            match self.reservation.compare_exchange_weak(
                current,
                upto,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        let Some(path) = &self.path else {
            return;
        };
        if let Err(error) = write_private_file(path, upto.to_string().as_bytes()) {
            // Not fatal: the wall-clock floor still keeps nonces increasing in
            // the common case, it just cannot survive a clock that runs
            // backwards as well as a lost state file.
            tracing::warn!(path = %path.display(), "cannot persist relay nonce reservation: {error}");
        }
    }
}

fn read_reservation(path: &Path) -> Option<u64> {
    let text = fantuan_core::fs::read_to_string(path).ok()?;
    match text.trim().parse::<u64>() {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(path = %path.display(), "unreadable relay nonce reservation: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_strictly_increasing() {
        let nonce = RelayNonce::at(None, 0);
        let values: Vec<u64> = (0..8).map(|_| nonce.next()).collect();
        assert!(
            values.windows(2).all(|pair| pair[1] > pair[0]),
            "{values:?}"
        );
    }

    #[test]
    fn a_restart_never_repeats_a_nonce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay.nonce");
        // A restart in the same millisecond is the worst case: the wall clock
        // floor cannot help, only the persisted reservation can.
        let first = RelayNonce::at(Some(path.clone()), 1_000_000);
        let last = (0..3).map(|_| first.next()).last().expect("nonces");
        drop(first);

        let second = RelayNonce::at(Some(path), 1_000_000);
        assert!(
            second.next() > last,
            "a restarted node must not reuse nonces (last {last})"
        );
    }

    #[test]
    fn the_reservation_outlives_a_lost_state_file() {
        // No path: the clock floor alone must keep the counter ahead.
        let nonce = RelayNonce::at(None, 5_000_000);
        assert!(nonce.next() > 5_000_000);
        assert!(nonce.next() > 5_000_000);
    }

    #[test]
    fn a_corrupt_state_file_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay.nonce");
        fantuan_core::fs::write_private_file(&path, b"not a number").expect("write");
        let nonce = RelayNonce::at(Some(path), 42);
        assert_eq!(nonce.next(), 43);
    }
}
