//! Durable epoch reservation (initiator side) and rollback detection.
//!
//! Frozen specification (`docs/PROTOCOL.md` section 11.1, Q28 matrix): epochs
//! come only from a persistent reservation, never from a clock or a counter
//! that a restart could rewind. The file is the initiator's anchor: for this
//! side "marker" in the Q28 matrix means this reservation file.
//!
//! ```text
//! rounds.epoch (58 bytes)
//!   magic(8) = "FTNEPO01" ‖ version(2) ‖ own_proto_id(32)
//!   ‖ reserved_upto(8, BE) ‖ checksum(8)
//! ```
//!
//! Reservation block semantics: `reserved_upto` is the highest epoch this node
//! may hand out *without another durable write*. A block is persisted before
//! any epoch inside it is used, so a crash can skip epochs but never repeat
//! one. On open the cursor resumes at `reserved_upto + 1`: the whole previous
//! block is abandoned, which is the safe direction and costs nothing because
//! epochs are cheap.
//!
//! Failure policy (frozen): if the reservation cannot be persisted, `take`
//! returns an error and hands out **no** epoch. The round is skipped rather
//! than run with an epoch that a restart could reuse.

use crate::admission::EPOCH_MAX_USABLE;
use crate::durable::{IdentityFreshness, StoreError};
use fantuan_identity::PROTO_ID_LEN;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Reservation file name inside the data directory.
pub const RESERVATION_FILE: &str = "rounds.epoch";

/// Reservation magic.
const RESERVATION_MAGIC: &[u8; 8] = b"FTNEPO01";
/// Reservation format version.
const RESERVATION_VERSION: u16 = 1;
/// Reservation record size.
const RESERVATION_LEN: usize = 58;
/// Integrity field width.
const CHECKSUM_LEN: usize = 8;
/// Domain separator for the reservation checksum.
const RESERVATION_DOMAIN: &[u8] = b"fantuan-round-reservation-v1";
/// Epochs reserved by one durable write.
pub const DEFAULT_RESERVATION_BLOCK: u64 = 1024;
/// Consecutive peer rejections that indicate a rolled-back namespace.
pub const ROLLBACK_REJECTION_LIMIT: u32 = 3;

/// Epoch source: strictly increasing, restart-safe, fail-closed.
pub struct EpochReservation {
    path: PathBuf,
    /// Identity this reservation belongs to, validated at open.
    own_proto_id: [u8; PROTO_ID_LEN],
    /// Highest epoch covered by the persisted reservation.
    reserved_upto: u64,
    /// Next epoch to hand out.
    next: u64,
    block: u64,
}

impl EpochReservation {
    /// Open the reservation, creating it only for a genuinely fresh node.
    pub fn open(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
        freshness: IdentityFreshness,
    ) -> std::result::Result<Self, StoreError> {
        Self::open_with_block(dir, own_proto_id, freshness, DEFAULT_RESERVATION_BLOCK)
    }

    /// Open with an explicit block size (small blocks make failure paths
    /// reachable in tests).
    pub fn open_with_block(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
        freshness: IdentityFreshness,
        block: u64,
    ) -> std::result::Result<Self, StoreError> {
        if block == 0 {
            return Err(StoreError::Io(
                "reservation block must be positive".to_string(),
            ));
        }
        let path = dir.join(RESERVATION_FILE);
        if !path.exists() {
            return match freshness {
                IdentityFreshness::Fresh => Self::initialize_with_block(dir, own_proto_id, block),
                IdentityFreshness::Established => Err(StoreError::MissingMarker),
            };
        }
        let bytes = fantuan_core::fs::read_file(&path)
            .map_err(|error| StoreError::Io(error.to_string()))?;
        let reserved_upto = decode_reservation(&bytes, &own_proto_id)?;
        Ok(Self::resume(path, own_proto_id, reserved_upto, block))
    }

    /// Explicit operator initialization: start a fresh namespace.
    pub fn initialize(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
    ) -> std::result::Result<Self, StoreError> {
        Self::initialize_with_block(dir, own_proto_id, DEFAULT_RESERVATION_BLOCK)
    }

    fn initialize_with_block(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
        block: u64,
    ) -> std::result::Result<Self, StoreError> {
        fantuan_core::fs::ensure_dir_0700(dir)
            .map_err(|error| StoreError::Io(error.to_string()))?;
        let path = dir.join(RESERVATION_FILE);
        write_reservation(&path, &own_proto_id, 0)?;
        Ok(Self::resume(path, own_proto_id, 0, block))
    }

    fn resume(
        path: PathBuf,
        own_proto_id: [u8; PROTO_ID_LEN],
        reserved_upto: u64,
        block: u64,
    ) -> Self {
        // The previous block is abandoned: epochs below `reserved_upto + 1` may
        // already have been used, and reusing one would be a self-replay.
        Self {
            path,
            own_proto_id,
            reserved_upto,
            next: reserved_upto.saturating_add(1),
            block,
        }
    }

    /// Highest epoch covered by the current durable reservation.
    pub fn reserved_upto(&self) -> u64 {
        self.reserved_upto
    }

    /// Next epoch that will be handed out.
    pub fn peek(&self) -> u64 {
        self.next
    }

    /// Reserve and return the next epoch.
    ///
    /// Persists a fresh block first when the current one is used up. On any
    /// failure no epoch is handed out and the cursor does not move.
    pub fn take(&mut self) -> std::result::Result<u64, StoreError> {
        if self.next > EPOCH_MAX_USABLE {
            return Err(StoreError::Exhausted);
        }
        if self.next > self.reserved_upto {
            let extend_to = self
                .next
                .saturating_add(self.block - 1)
                .min(EPOCH_MAX_USABLE);
            // The identity is cached from `open`: re-reading it here would
            // turn a transient read failure into a wrong-identity write, which
            // the next open would (correctly) treat as a foreign data dir.
            write_reservation(&self.path, &self.own_proto_id, extend_to)?;
            self.reserved_upto = extend_to;
        }
        let epoch = self.next;
        self.next += 1;
        Ok(epoch)
    }
}

fn write_reservation(
    path: &Path,
    own_proto_id: &[u8; PROTO_ID_LEN],
    reserved_upto: u64,
) -> std::result::Result<(), StoreError> {
    let mut record = Vec::with_capacity(RESERVATION_LEN);
    record.extend_from_slice(RESERVATION_MAGIC);
    record.extend_from_slice(&RESERVATION_VERSION.to_be_bytes());
    record.extend_from_slice(own_proto_id);
    record.extend_from_slice(&reserved_upto.to_be_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESERVATION_DOMAIN);
    hasher.update(&record);
    record.extend_from_slice(&hasher.finalize().as_bytes()[..CHECKSUM_LEN]);

    // Written through a truncating write plus fsync; a partial write leaves a
    // short file, which `decode_reservation` rejects on the next open (HALT
    // rather than a silently rewound namespace).
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| StoreError::Io(error.to_string()))?;
    file.write_all(&record)
        .map_err(|error| StoreError::Io(error.to_string()))?;
    file.sync_all()
        .map_err(|error| StoreError::Io(error.to_string()))?;
    Ok(())
}

fn decode_reservation(
    bytes: &[u8],
    own_proto_id: &[u8; PROTO_ID_LEN],
) -> std::result::Result<u64, StoreError> {
    if bytes.len() != RESERVATION_LEN || &bytes[..8] != RESERVATION_MAGIC {
        return Err(StoreError::CorruptMarker);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != RESERVATION_VERSION {
        return Err(StoreError::CorruptMarker);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESERVATION_DOMAIN);
    hasher.update(&bytes[..RESERVATION_LEN - CHECKSUM_LEN]);
    if hasher.finalize().as_bytes()[..CHECKSUM_LEN] != bytes[RESERVATION_LEN - CHECKSUM_LEN..] {
        return Err(StoreError::CorruptMarker);
    }
    if &bytes[10..10 + PROTO_ID_LEN] != own_proto_id {
        return Err(StoreError::ForeignIdentity);
    }
    Ok(u64::from_be_bytes(
        bytes[RESERVATION_LEN - CHECKSUM_LEN - 8..RESERVATION_LEN - CHECKSUM_LEN]
            .try_into()
            .expect("fixed width"),
    ))
}

/// Detects an initiator-side rollback from peer behaviour.
///
/// A rolled-back node cannot see its own regression locally, but its starts
/// look stale (or equivocation) to peers. Repeated rejection of *our own*
/// starts therefore means the namespace may have moved backwards, and the
/// frozen policy is to stop initiating until an operator acts.
#[derive(Debug, Default)]
pub struct RollbackWatch {
    consecutive_rejections: u32,
    halted: bool,
}

impl RollbackWatch {
    /// Create a watch that has not seen anything yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a peer refused one of our starts.
    ///
    /// Returns true when the halt threshold is reached.
    pub fn observe_rejection(&mut self) -> bool {
        self.consecutive_rejections = self.consecutive_rejections.saturating_add(1);
        if self.consecutive_rejections >= ROLLBACK_REJECTION_LIMIT {
            self.halted = true;
        }
        self.halted
    }

    /// Record that a start of ours was accepted.
    pub fn observe_acceptance(&mut self) {
        self.consecutive_rejections = 0;
    }

    /// Consecutive rejections seen so far.
    pub fn consecutive_rejections(&self) -> u32 {
        self.consecutive_rejections
    }

    /// True once initiation must stop; sticky until [`RollbackWatch::reset`].
    pub fn halted(&self) -> bool {
        self.halted
    }

    /// Operator action: allow initiation again.
    pub fn reset(&mut self) {
        self.consecutive_rejections = 0;
        self.halted = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const OWN: [u8; PROTO_ID_LEN] = [0x33; PROTO_ID_LEN];

    /// Q28 initiator rows: missing on an established node, corrupt and foreign
    /// reservations all HALT; a fresh node initializes.
    #[test]
    fn reservation_open_matrix() {
        let dir = TempDir::new().expect("tempdir");
        {
            let mut reservation =
                EpochReservation::open(dir.path(), OWN, IdentityFreshness::Fresh).expect("fresh");
            reservation.take().expect("epoch");
        }

        // Established node reopens and never rewinds.
        let mut reopened = EpochReservation::open(dir.path(), OWN, IdentityFreshness::Established)
            .expect("reopen");
        let first_after_restart = reopened.take().expect("epoch");

        // Foreign identity (restored backup of another node).
        assert!(matches!(
            EpochReservation::open(
                dir.path(),
                [0x44; PROTO_ID_LEN],
                IdentityFreshness::Established
            ),
            Err(StoreError::ForeignIdentity)
        ));

        // Corrupt reservation.
        let path = dir.path().join(RESERVATION_FILE);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[20] ^= 0xff;
        std::fs::write(&path, &bytes).expect("write");
        assert!(matches!(
            EpochReservation::open(dir.path(), OWN, IdentityFreshness::Established),
            Err(StoreError::CorruptMarker)
        ));

        // A truncated record (partial write) is corruption, not a rewind.
        std::fs::write(&path, &bytes[..30]).expect("write");
        assert!(matches!(
            EpochReservation::open(dir.path(), OWN, IdentityFreshness::Established),
            Err(StoreError::CorruptMarker)
        ));

        // Missing on an established node.
        let empty = TempDir::new().expect("tempdir");
        assert!(matches!(
            EpochReservation::open(empty.path(), OWN, IdentityFreshness::Established),
            Err(StoreError::MissingMarker)
        ));
        assert!(
            !empty.path().join(RESERVATION_FILE).exists(),
            "opening must not create state for an established node"
        );
        assert!(first_after_restart > 0);
    }

    #[test]
    fn epochs_are_strictly_increasing_and_survive_restarts() {
        let dir = TempDir::new().expect("tempdir");
        let mut handed_out = Vec::new();
        {
            let mut reservation =
                EpochReservation::open_with_block(dir.path(), OWN, IdentityFreshness::Fresh, 4)
                    .expect("fresh");
            for _ in 0..10 {
                handed_out.push(reservation.take().expect("epoch"));
            }
        }
        {
            let mut reservation = EpochReservation::open_with_block(
                dir.path(),
                OWN,
                IdentityFreshness::Established,
                4,
            )
            .expect("reopen");
            for _ in 0..5 {
                handed_out.push(reservation.take().expect("epoch"));
            }
        }
        assert!(
            handed_out.windows(2).all(|pair| pair[1] > pair[0]),
            "epochs must strictly increase across restarts: {handed_out:?}"
        );
    }

    /// Frozen failure policy: a reservation that cannot be persisted hands out
    /// no epoch and does not move the cursor.
    #[test]
    fn reservation_write_failure_is_fail_closed() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(RESERVATION_FILE);
        let mut reservation =
            EpochReservation::open_with_block(dir.path(), OWN, IdentityFreshness::Fresh, 1)
                .expect("fresh");
        assert_eq!(reservation.take().expect("first epoch"), 1);

        // Make the reservation unwritable by replacing it with a directory:
        // any open/write on that path fails.
        std::fs::remove_file(&path).expect("remove");
        std::fs::create_dir(&path).expect("directory");
        let before = reservation.peek();
        assert!(
            reservation.take().is_err(),
            "an unpersistable reservation must not hand out an epoch"
        );
        assert_eq!(
            reservation.peek(),
            before,
            "the cursor must not move when the reservation cannot be persisted"
        );

        // Restoring a valid file lets it continue from the same place.
        std::fs::remove_dir(&path).expect("remove directory");
        write_reservation(&path, &OWN, 0).expect("restore");
        let resumed =
            EpochReservation::open_with_block(dir.path(), OWN, IdentityFreshness::Established, 1)
                .expect("reopen");
        assert_eq!(
            resumed.peek(),
            1,
            "no epoch was consumed by the failed attempt"
        );
    }

    #[test]
    fn exhausted_namespace_halts_initiation() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(RESERVATION_FILE);
        // Resume starts one past the reserved range, so reserve up to
        // MAX_USABLE - 1 to leave exactly one usable epoch.
        write_reservation(&path, &OWN, EPOCH_MAX_USABLE - 1).expect("write");
        let mut reservation =
            EpochReservation::open_with_block(dir.path(), OWN, IdentityFreshness::Established, 4)
                .expect("open");
        assert_eq!(
            reservation.take().expect("last usable epoch"),
            EPOCH_MAX_USABLE
        );
        assert!(matches!(reservation.take(), Err(StoreError::Exhausted)));
        assert!(matches!(reservation.take(), Err(StoreError::Exhausted)));
    }

    #[test]
    fn rollback_watch_halts_after_repeated_rejections() {
        let mut watch = RollbackWatch::new();
        assert!(!watch.observe_rejection());
        assert!(!watch.observe_rejection());
        assert!(
            watch.observe_rejection(),
            "the third consecutive rejection halts initiation"
        );
        assert!(watch.halted());
        // Sticky: an acceptance does not clear a halt, only an operator does.
        watch.observe_acceptance();
        assert!(watch.halted());

        watch.reset();
        assert!(!watch.halted());
        // Scattered rejections do not accumulate.
        assert!(!watch.observe_rejection());
        assert!(!watch.observe_rejection());
        watch.observe_acceptance();
        assert!(!watch.observe_rejection());
        assert!(!watch.halted());
        assert_eq!(watch.consecutive_rejections(), 1);
    }
}
