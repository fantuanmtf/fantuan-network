//! Durable namespace state (receiver side).
//!
//! Frozen specification (`docs/PROTOCOL.md` section 11.2, review findings R6
//! and the Q28 matrix):
//!
//! * an initialization marker (`rounds.state`) is the only bootstrap anchor —
//!   "the data directory looks like it exists" is never a criterion;
//! * the watermark log (`rounds.log`) is append-only, fixed-record, and each
//!   record is fsynced before the accept it describes becomes visible;
//! * a torn tail record is discarded and the file truncated to the last
//!   complete record, because the record was never acted upon;
//! * a corrupt marker, a corrupt log record, a non-monotonic log or a marker
//!   belonging to another identity all HALT the module;
//! * a runtime write failure refuses the round (`Admission::StoreFailed`): the
//!   old state stays in place, nothing is classified, no round advances.
//!
//! Record layouts (all integers big endian, all files mode 0600):
//!
//! ```text
//! marker  (58 bytes) : magic(8) ‖ version(2) ‖ own_proto_id(32)
//!                      ‖ created_unix_secs(8) ‖ checksum(8)
//! log     (96 bytes) : initiator(32) ‖ epoch(8) ‖ instance(16)
//!                      ‖ context_hash(32) ‖ checksum(8)
//! ```
//!
//! `checksum(8)` is `BLAKE3(domain ‖ preceding bytes)[..8]`. The specification
//! calls this field a CRC; a truncated BLAKE3 is used because it is the hash
//! this crate already depends on, and both are fixed-size integrity checks.

use crate::admission::{NamespaceState, NamespaceStore};
use crate::error::{AnonError, Result};
use fantuan_identity::PROTO_ID_LEN;
use fantuan_msg::{CONTEXT_HASH_LEN, INSTANCE_LEN};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Marker file name inside the data directory.
pub const MARKER_FILE: &str = "rounds.state";
/// Watermark log file name inside the data directory.
pub const LOG_FILE: &str = "rounds.log";

/// Marker magic.
const MARKER_MAGIC: &[u8; 8] = b"FTNRND01";
/// Marker format version.
const MARKER_VERSION: u16 = 1;
/// Marker record size.
const MARKER_LEN: usize = 58;
/// Log record size.
const LOG_RECORD_LEN: usize = 96;
/// Integrity field width.
const CHECKSUM_LEN: usize = 8;
/// Domain separator for marker checksums.
const MARKER_DOMAIN: &[u8] = b"fantuan-round-marker-v1";
/// Domain separator for log record checksums.
const RECORD_DOMAIN: &[u8] = b"fantuan-round-record-v1";
/// Records appended since the last compaction before one is attempted.
const COMPACT_AFTER_RECORDS: usize = 1024;

/// Why durable round state is unusable.
///
/// Every variant is a HALT condition for the anonymous layer: the module must
/// not run until an operator acts. `TornTail` is *not* here — a torn tail is
/// recovered automatically.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The marker is missing although this node has run before.
    #[error(
        "round state marker is missing on an established node (HALT-DCNET); run the explicit round-state initialization to accept a fresh replay window"
    )]
    MissingMarker,
    /// The marker does not decode, has the wrong magic/version or a bad
    /// checksum.
    #[error("round state marker is corrupt (HALT-DCNET)")]
    CorruptMarker,
    /// The marker belongs to a different identity (foreign data directory or
    /// restored backup).
    #[error("round state belongs to another identity (HALT-DCNET)")]
    ForeignIdentity,
    /// A log record has a bad checksum, or the log is otherwise unreadable.
    #[error("round watermark log is corrupt (HALT-DCNET)")]
    CorruptLog,
    /// The log is not strictly increasing per namespace.
    #[error("round watermark log is not monotonic (HALT-DCNET)")]
    NonMonotonicLog,
    /// The namespace is exhausted.
    #[error("round epoch namespace is exhausted (HALT-DCNET)")]
    Exhausted,
    /// Underlying I/O failure.
    #[error("round state i/o failed: {0}")]
    Io(String),
}

/// Whether this node's identity already existed before this start.
///
/// Supplied explicitly by the caller (`identity init` knows the answer); the
/// module never guesses from directory contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFreshness {
    /// The identity was just created in this run.
    Fresh,
    /// The node has run before with this identity.
    Established,
}

/// Append-only, fsynced watermark log plus its initialization marker.
pub struct DurableStore {
    dir: PathBuf,
    log: File,
    namespaces: HashMap<[u8; PROTO_ID_LEN], NamespaceState>,
    records: usize,
    appended_since_compact: usize,
}

impl DurableStore {
    /// Open the durable state, creating it only for a genuinely fresh node.
    pub fn open(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
        freshness: IdentityFreshness,
        now_unix: u64,
    ) -> std::result::Result<Self, StoreError> {
        let marker_path = dir.join(MARKER_FILE);
        let log_path = dir.join(LOG_FILE);
        match (marker_path.exists(), log_path.exists()) {
            (false, false) if freshness == IdentityFreshness::Fresh => {
                Self::initialize(dir, own_proto_id, now_unix)
            }
            (false, _) => Err(StoreError::MissingMarker),
            (true, _) => Self::open_existing(dir, own_proto_id),
        }
    }

    /// Explicit operator initialization: (re)creates the marker and an empty
    /// log, starting a fresh replay window.
    pub fn initialize(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
        now_unix: u64,
    ) -> std::result::Result<Self, StoreError> {
        fantuan_core::fs::ensure_dir_0700(dir).map_err(core_err)?;
        let marker = encode_marker(own_proto_id, now_unix);
        fantuan_core::fs::write_private_file(&dir.join(MARKER_FILE), &marker).map_err(core_err)?;
        fantuan_core::fs::write_private_file(&dir.join(LOG_FILE), &[]).map_err(core_err)?;
        Self::open_existing(dir, own_proto_id)
    }

    fn open_existing(
        dir: &Path,
        own_proto_id: [u8; PROTO_ID_LEN],
    ) -> std::result::Result<Self, StoreError> {
        let marker_bytes = fantuan_core::fs::read_file(&dir.join(MARKER_FILE)).map_err(core_err)?;
        let marker = decode_marker(&marker_bytes)?;
        if marker != own_proto_id {
            return Err(StoreError::ForeignIdentity);
        }

        let log_path = dir.join(LOG_FILE);
        let mut namespaces: HashMap<[u8; PROTO_ID_LEN], NamespaceState> = HashMap::new();
        let (records, good_bytes) = {
            let mut file = File::open(&log_path).map_err(io_err)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(io_err)?;
            replay_log(&bytes, &mut namespaces)?
        };

        // A torn tail record is discarded, and the file is truncated to the
        // last complete record so the next append starts on a record boundary.
        let file_len = std::fs::metadata(&log_path).map_err(io_err)?.len();
        if good_bytes as u64 != file_len {
            let file = OpenOptions::new()
                .write(true)
                .open(&log_path)
                .map_err(io_err)?;
            file.set_len(good_bytes as u64).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
            tracing::warn!(
                discarded = file_len - good_bytes as u64,
                "discarded a torn round log record; the accept it described never took effect"
            );
        }

        let log = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .map_err(io_err)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            log,
            namespaces,
            records,
            appended_since_compact: 0,
        })
    }

    /// Restored namespaces, for [`crate::admission::RoundAdmission::restore`].
    pub fn load(&self) -> Vec<([u8; PROTO_ID_LEN], NamespaceState)> {
        self.namespaces.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Number of records currently in the log.
    pub fn record_count(&self) -> usize {
        self.records
    }

    /// Data directory this store lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Rewrite the log with one record per namespace.
    ///
    /// Written to a temporary file, fsynced and renamed, so an interrupted
    /// compaction leaves either the old log or the new one, never a mixture.
    pub fn compact(&mut self) -> std::result::Result<(), StoreError> {
        let temporary = self.dir.join(format!("{LOG_FILE}.tmp"));
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .map_err(io_err)?;
        for (initiator, state) in &self.namespaces {
            file.write_all(&encode_record(initiator, state))
                .map_err(io_err)?;
        }
        file.sync_all().map_err(io_err)?;
        drop(file);
        std::fs::rename(&temporary, self.dir.join(LOG_FILE)).map_err(io_err)?;
        self.log = OpenOptions::new()
            .append(true)
            .open(self.dir.join(LOG_FILE))
            .map_err(io_err)?;
        self.records = self.namespaces.len();
        self.appended_since_compact = 0;
        Ok(())
    }

    fn append(&mut self, initiator: &[u8; PROTO_ID_LEN], state: &NamespaceState) -> Result<()> {
        let record = encode_record(initiator, state);
        self.log
            .write_all(&record)
            .map_err(|error| AnonError::Round(format!("append failed: {error}")))?;
        self.log
            .sync_all()
            .map_err(|error| AnonError::Round(format!("fsync failed: {error}")))?;
        self.records += 1;
        self.appended_since_compact += 1;
        Ok(())
    }
}

impl NamespaceStore for DurableStore {
    fn commit(&mut self, initiator: &[u8; PROTO_ID_LEN], state: &NamespaceState) -> Result<()> {
        // Persist first: only after this returns does the caller publish the
        // new state or emit a classification.
        self.append(initiator, state)?;
        self.namespaces.insert(*initiator, *state);
        if self.appended_since_compact >= COMPACT_AFTER_RECORDS
            && self.records > self.namespaces.len() * 2
            && let Err(error) = self.compact()
        {
            // Compaction is an optimization; the log is already durable.
            tracing::warn!("round log compaction failed: {error}");
        }
        Ok(())
    }
}

fn io_err(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

fn core_err(error: fantuan_core::error::CoreError) -> StoreError {
    StoreError::Io(error.to_string())
}

fn checksum(domain: &[u8], bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..CHECKSUM_LEN]);
    out
}

fn encode_marker(own_proto_id: [u8; PROTO_ID_LEN], now_unix: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MARKER_LEN);
    out.extend_from_slice(MARKER_MAGIC);
    out.extend_from_slice(&MARKER_VERSION.to_be_bytes());
    out.extend_from_slice(&own_proto_id);
    out.extend_from_slice(&now_unix.to_be_bytes());
    out.extend_from_slice(&checksum(MARKER_DOMAIN, &out));
    out
}

fn decode_marker(bytes: &[u8]) -> std::result::Result<[u8; PROTO_ID_LEN], StoreError> {
    if bytes.len() != MARKER_LEN || &bytes[..8] != MARKER_MAGIC {
        return Err(StoreError::CorruptMarker);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != MARKER_VERSION {
        return Err(StoreError::CorruptMarker);
    }
    let body = &bytes[..MARKER_LEN - CHECKSUM_LEN];
    if checksum(MARKER_DOMAIN, body) != bytes[MARKER_LEN - CHECKSUM_LEN..] {
        return Err(StoreError::CorruptMarker);
    }
    let mut own = [0u8; PROTO_ID_LEN];
    own.copy_from_slice(&bytes[10..10 + PROTO_ID_LEN]);
    Ok(own)
}

fn encode_record(initiator: &[u8; PROTO_ID_LEN], state: &NamespaceState) -> Vec<u8> {
    let mut out = Vec::with_capacity(LOG_RECORD_LEN);
    out.extend_from_slice(initiator);
    out.extend_from_slice(&state.watermark().to_be_bytes());
    out.extend_from_slice(state.instance());
    out.extend_from_slice(state.context_hash());
    out.extend_from_slice(&checksum(RECORD_DOMAIN, &out));
    out
}

/// Replay a log image into `namespaces`.
///
/// Returns `(complete records, bytes covered by them)`. A trailing partial
/// record is reported through `bytes` so the caller can truncate it; a
/// complete record with a bad checksum or a non-monotonic epoch is a HALT.
fn replay_log(
    bytes: &[u8],
    namespaces: &mut HashMap<[u8; PROTO_ID_LEN], NamespaceState>,
) -> std::result::Result<(usize, usize), StoreError> {
    let mut records = 0usize;
    let mut offset = 0usize;
    while offset + LOG_RECORD_LEN <= bytes.len() {
        let record = &bytes[offset..offset + LOG_RECORD_LEN];
        if checksum(RECORD_DOMAIN, &record[..LOG_RECORD_LEN - CHECKSUM_LEN])
            != record[LOG_RECORD_LEN - CHECKSUM_LEN..]
        {
            return Err(StoreError::CorruptLog);
        }
        let mut initiator = [0u8; PROTO_ID_LEN];
        initiator.copy_from_slice(&record[..PROTO_ID_LEN]);
        let epoch = u64::from_be_bytes(
            record[PROTO_ID_LEN..PROTO_ID_LEN + 8]
                .try_into()
                .expect("fixed width"),
        );
        let mut instance = [0u8; INSTANCE_LEN];
        instance.copy_from_slice(&record[PROTO_ID_LEN + 8..PROTO_ID_LEN + 8 + INSTANCE_LEN]);
        let mut context_hash = [0u8; CONTEXT_HASH_LEN];
        context_hash.copy_from_slice(
            &record
                [LOG_RECORD_LEN - CHECKSUM_LEN - CONTEXT_HASH_LEN..LOG_RECORD_LEN - CHECKSUM_LEN],
        );

        if let Some(previous) = namespaces.get(&initiator)
            && epoch <= previous.watermark()
        {
            return Err(StoreError::NonMonotonicLog);
        }
        namespaces.insert(
            initiator,
            NamespaceState::from_parts(epoch, instance, context_hash),
        );
        records += 1;
        offset += LOG_RECORD_LEN;
    }
    Ok((records, offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{Admission, AuthenticatedRound, RoundAdmission};
    use fantuan_msg::{RoundContext, RoundIdentity};
    use tempfile::TempDir;

    const OWN: [u8; PROTO_ID_LEN] = [0x11; PROTO_ID_LEN];
    const PEER: [u8; PROTO_ID_LEN] = [0x22; PROTO_ID_LEN];

    fn state(epoch: u64, seed: u8) -> NamespaceState {
        NamespaceState::from_parts(epoch, [seed; INSTANCE_LEN], [seed; CONTEXT_HASH_LEN])
    }

    fn open_fresh(dir: &Path) -> DurableStore {
        DurableStore::open(dir, OWN, IdentityFreshness::Fresh, 1_000).expect("fresh store")
    }

    fn open_established(dir: &Path) -> std::result::Result<DurableStore, StoreError> {
        DurableStore::open(dir, OWN, IdentityFreshness::Established, 2_000)
    }

    fn log_path(dir: &Path) -> PathBuf {
        dir.join(LOG_FILE)
    }

    fn read_log(dir: &Path) -> Vec<u8> {
        std::fs::read(log_path(dir)).expect("log")
    }

    /// T-STATE-CORRUPTION-MATRIX: every row of the frozen matrix that the
    /// receiver side can decide, asserted by observable state — not by error
    /// codes alone.
    #[test]
    fn state_corruption_matrix() {
        // 1. Fresh node: initialize, persist, reload.
        let dir = TempDir::new().expect("tempdir");
        {
            let mut store = open_fresh(dir.path());
            store.commit(&PEER, &state(7, 1)).expect("commit");
            assert_eq!(store.record_count(), 1);
        }
        assert!(dir.path().join(MARKER_FILE).exists());
        let reopened = open_established(dir.path()).expect("established node reopens");
        assert_eq!(reopened.load(), vec![(PEER, state(7, 1))]);

        // 2. Marker missing on an established node: HALT, and nothing is
        //    created or repaired behind the operator's back.
        let bare = TempDir::new().expect("tempdir");
        std::fs::write(
            bare.path().join(LOG_FILE),
            encode_record(&PEER, &state(7, 1)),
        )
        .expect("write log");
        let before = read_log(bare.path());
        assert!(matches!(
            open_established(bare.path()),
            Err(StoreError::MissingMarker)
        ));
        assert!(
            !bare.path().join(MARKER_FILE).exists(),
            "no marker was created"
        );
        assert_eq!(read_log(bare.path()), before, "the log was left alone");

        // 3. Corrupt marker: HALT without touching the log.
        let corrupt_marker = TempDir::new().expect("tempdir");
        {
            let mut store = open_fresh(corrupt_marker.path());
            store.commit(&PEER, &state(7, 1)).expect("commit");
        }
        let before = read_log(corrupt_marker.path());
        let mut marker = std::fs::read(corrupt_marker.path().join(MARKER_FILE)).expect("marker");
        marker[20] ^= 0xff;
        std::fs::write(corrupt_marker.path().join(MARKER_FILE), &marker).expect("write");
        assert!(matches!(
            open_established(corrupt_marker.path()),
            Err(StoreError::CorruptMarker)
        ));
        assert_eq!(read_log(corrupt_marker.path()), before);

        // 3b. Unsupported marker version is corruption, not silent acceptance.
        let mut versioned = marker.clone();
        versioned[9] = 9;
        std::fs::write(corrupt_marker.path().join(MARKER_FILE), &versioned).expect("write");
        assert!(matches!(
            open_established(corrupt_marker.path()),
            Err(StoreError::CorruptMarker)
        ));

        // 4. Foreign identity (restored backup of another node): HALT.
        let foreign = TempDir::new().expect("tempdir");
        DurableStore::initialize(foreign.path(), [0x99; PROTO_ID_LEN], 1_000).expect("init");
        assert!(matches!(
            open_established(foreign.path()),
            Err(StoreError::ForeignIdentity)
        ));

        // 5. Corrupt log record: HALT (a complete record must be intact).
        let corrupt_log = TempDir::new().expect("tempdir");
        {
            let mut store = open_fresh(corrupt_log.path());
            store.commit(&PEER, &state(7, 1)).expect("commit");
        }
        let mut bytes = read_log(corrupt_log.path());
        bytes[10] ^= 0xff;
        std::fs::write(log_path(corrupt_log.path()), &bytes).expect("write");
        assert!(matches!(
            open_established(corrupt_log.path()),
            Err(StoreError::CorruptLog)
        ));

        // 6. Non-monotonic log: HALT.
        let regressed = TempDir::new().expect("tempdir");
        let mut log = encode_record(&PEER, &state(9, 1));
        log.extend_from_slice(&encode_record(&PEER, &state(4, 2)));
        std::fs::write(
            regressed.path().join(MARKER_FILE),
            encode_marker(OWN, 1_000),
        )
        .expect("marker");
        std::fs::write(regressed.path().join(LOG_FILE), &log).expect("log");
        assert!(matches!(
            open_established(regressed.path()),
            Err(StoreError::NonMonotonicLog)
        ));
    }

    /// T-PARTIAL-APPEND: a torn tail record is discarded, the file is cut back
    /// to the last complete record, and later appends start on a boundary.
    #[test]
    fn partial_append_is_discarded_and_truncated() {
        let dir = TempDir::new().expect("tempdir");
        let torn = {
            let mut store = open_fresh(dir.path());
            store.commit(&PEER, &state(3, 1)).expect("commit");
            store.commit(&PEER, &state(4, 2)).expect("commit");
            // A record that was half-written when the process died.
            let partial = encode_record(&PEER, &state(5, 3));
            let mut open = OpenOptions::new()
                .append(true)
                .open(log_path(dir.path()))
                .expect("append");
            open.write_all(&partial[..40]).expect("torn write");
            open.sync_all().expect("sync");
            40
        };

        let mut store = open_established(dir.path()).expect("torn tail recovers");
        assert_eq!(store.record_count(), 2, "the torn record is not counted");
        assert_eq!(store.load(), vec![(PEER, state(4, 2))]);
        assert_eq!(
            read_log(dir.path()).len(),
            2 * LOG_RECORD_LEN,
            "the file was truncated to the last complete record"
        );
        assert!(torn > 0);

        // A later append lands on a record boundary and reloads cleanly.
        store
            .commit(&PEER, &state(6, 4))
            .expect("commit after recovery");
        let reopened = open_established(dir.path()).expect("reopen");
        assert_eq!(reopened.record_count(), 3);
        assert_eq!(reopened.load(), vec![(PEER, state(6, 4))]);
    }

    /// T-FSYNC-CRASH-RECOVERY: the durable record survives a crash that
    /// happened after fsync but before the in-memory state was published. The
    /// recovered node treats the epoch as used (no second instance accepted)
    /// and keeps making progress at the next epoch (no liveness cost).
    #[test]
    fn fsync_before_publish_is_conservative_and_costs_no_liveness() {
        let dir = TempDir::new().expect("tempdir");
        let local = [0xAA; PROTO_ID_LEN];
        let accepted_context =
            RoundContext::new("#anon", vec![local, PEER], 15, 1024).expect("context");
        let accepted_instance = [3u8; INSTANCE_LEN];
        let accepted = NamespaceState::from_parts(7, accepted_instance, accepted_context.hash());
        // The durable write happened; the caller never published it.
        {
            let mut store = open_fresh(dir.path());
            store.commit(&PEER, &accepted).expect("commit");
        }

        let mut store = open_established(dir.path()).expect("reopen");
        let mut admission = RoundAdmission::new(crate::admission::VolatileStore);
        for (initiator, recovered) in store.load() {
            admission.restore(initiator, recovered);
        }

        // The accepted epoch is not accepted a second time.
        assert_eq!(
            admission.admit(
                &local,
                &AuthenticatedRound::verified(
                    RoundIdentity::new(PEER, 7, accepted_instance),
                    accepted_context.clone()
                )
            ),
            Admission::Replay,
            "the recovered watermark refuses the round that was already durable"
        );
        // A different instance at the same epoch is an equivocation, not an
        // acceptance: recovery never widens the namespace.
        assert_eq!(
            admission.admit(
                &local,
                &AuthenticatedRound::verified(
                    RoundIdentity::new(PEER, 7, [9u8; INSTANCE_LEN]),
                    accepted_context.clone()
                )
            ),
            Admission::Equivocation
        );
        // And the namespace moves on: no liveness cost for being conservative.
        assert_eq!(
            admission.admit(
                &local,
                &AuthenticatedRound::verified(
                    RoundIdentity::new(PEER, 8, [9u8; INSTANCE_LEN]),
                    accepted_context
                )
            ),
            Admission::Accepted
        );
        store
            .commit(&PEER, &state(8, 9))
            .expect("commit after recovery");
        assert_eq!(
            open_established(dir.path()).expect("reopen").load(),
            vec![(PEER, state(8, 9))]
        );
    }

    /// T-SNAPSHOT-ROLLBACK (receiver side): restoring a snapshot rolls the
    /// watermark back. This is the declared threat-model limitation — the node
    /// cannot detect it locally — and the test asserts the limitation rather
    /// than pretending it is safe.
    #[test]
    fn snapshot_rollback_reopens_the_replay_window_and_is_undetectable() {
        let dir = TempDir::new().expect("tempdir");
        let snapshot = TempDir::new().expect("snapshot");
        {
            let mut store = open_fresh(dir.path());
            store.commit(&PEER, &state(10, 1)).expect("commit");
        }
        // Snapshot marker and log, then keep running.
        std::fs::copy(
            dir.path().join(MARKER_FILE),
            snapshot.path().join(MARKER_FILE),
        )
        .expect("copy");
        std::fs::copy(log_path(dir.path()), snapshot.path().join(LOG_FILE)).expect("copy");
        {
            let mut store = open_established(dir.path()).expect("reopen");
            store.commit(&PEER, &state(11, 2)).expect("commit");
            assert_eq!(store.load(), vec![(PEER, state(11, 2))]);
        }

        // Restore the snapshot: the node is now behind its own history.
        std::fs::copy(
            snapshot.path().join(MARKER_FILE),
            dir.path().join(MARKER_FILE),
        )
        .expect("copy");
        std::fs::copy(snapshot.path().join(LOG_FILE), log_path(dir.path())).expect("copy");

        let mut store = open_established(dir.path()).expect("rollback loads without complaint");
        assert_eq!(
            store.load(),
            vec![(PEER, state(10, 1))],
            "the watermark regressed: this is the limitation, not a bug"
        );
        let mut admission = RoundAdmission::new(crate::admission::VolatileStore);
        for (initiator, recovered) in store.load() {
            admission.restore(initiator, recovered);
        }
        let local = [0xAA; PROTO_ID_LEN];
        let context = RoundContext::new("#anon", vec![local, PEER], 15, 1024).expect("context");
        // Epoch 11 is accepted again: the replay window is open, and nothing
        // in the node can tell this apart from a first arrival.
        assert_eq!(
            admission.admit(
                &local,
                &AuthenticatedRound::verified(
                    RoundIdentity::new(PEER, 11, [2; INSTANCE_LEN]),
                    context
                )
            ),
            Admission::Accepted
        );
        // What survives is pad uniqueness: a new attempt always mints a fresh
        // instance, so a rolled-back node never reuses key material.
        let first = RoundIdentity::fresh_instance().expect("instance");
        let second = RoundIdentity::fresh_instance().expect("instance");
        assert_ne!(first, second);
        store.commit(&PEER, &state(11, 2)).expect("commit");
    }
}
