//! Persistent trust graph storage.
//!
//! SQLite schema:
//!
//! ```sql
//! peer(fingerprint PK, uid, public_key_hex, descriptor, descriptor_sig,
//!      trust_score, first_seen, last_seen)
//! relationship(signer, subject, level, updated_at, signature,
//!              PK(signer, subject))
//! ```
//!
//! Relationships are directed trust vouches; the signature column stores the
//! OpenPGP detached signature made by the signer so the vouch can be relayed
//! in gossip without re-signing. Scoring lives in [`crate::trust_graph`].

use crate::error::{IdentityError, Result};
use crate::proto_id::{PROTO_ID_LEN, proto_id_from_cert_bytes};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Trust level on the same scale as OpenPGP's own model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Explicitly distrusted.
    Never = -1,
    /// No usable path from our own key.
    Unknown = 0,
    /// Trusted to introduce others, weakly.
    Marginal = 1,
    /// Fully trusted introducer.
    Full = 2,
    /// Our own key or an explicit override.
    Ultimate = 3,
}

impl TrustLevel {
    /// Convert from an integer level (out-of-range values become Unknown).
    pub fn from_i32(value: i32) -> Self {
        match value {
            -1 => TrustLevel::Never,
            0 => TrustLevel::Unknown,
            1 => TrustLevel::Marginal,
            2 => TrustLevel::Full,
            3 => TrustLevel::Ultimate,
            _ => TrustLevel::Unknown,
        }
    }

    /// Integer value.
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Map to a cached score in `0.0..=1.0`.
    pub fn to_score(self) -> f64 {
        match self {
            TrustLevel::Never | TrustLevel::Unknown => 0.0,
            TrustLevel::Marginal => 0.4,
            TrustLevel::Full => 0.8,
            TrustLevel::Ultimate => 1.0,
        }
    }
}

/// One known peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerRecord {
    /// Uppercase hex OpenPGP fingerprint.
    pub fingerprint: String,
    /// Last known display name.
    pub uid: String,
    /// OpenPGP certificate bytes, hex encoded.
    pub public_key_hex: String,
    /// Cached trust score in the range `0.0..=1.0`.
    pub trust_score: f64,
    /// Unix seconds of first contact.
    pub first_seen: u64,
    /// Unix seconds of last contact.
    pub last_seen: u64,
    /// Protocol identity, recomputed from the stored certificate.
    ///
    /// `None` for rows written before the field existed, or when the stored
    /// key material is not a parseable certificate.
    pub proto_id: Option<[u8; PROTO_ID_LEN]>,
}

/// A directed trust relationship.
#[derive(Debug, Clone, PartialEq)]
pub struct Relationship {
    /// Signer fingerprint.
    pub signer: String,
    /// Subject fingerprint.
    pub subject: String,
    /// Trust level assigned by the signer (0..=3).
    pub level: u8,
    /// Unix seconds of the last update.
    pub updated_at: u64,
    /// Detached OpenPGP signature over the vouch payload.
    pub signature: Vec<u8>,
}

/// A stored descriptor: fingerprint, canonical CBOR and detached signature.
pub type StoredDescriptor = (String, Vec<u8>, Vec<u8>);

/// Map a `peer` row to a [`PeerRecord`].
fn map_peer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerRecord> {
    let proto_id: Option<Vec<u8>> = row.get(6)?;
    Ok(PeerRecord {
        fingerprint: row.get(0)?,
        uid: row.get(1)?,
        public_key_hex: row.get(2)?,
        trust_score: row.get(3)?,
        first_seen: row.get::<_, i64>(4)? as u64,
        last_seen: row.get::<_, i64>(5)? as u64,
        proto_id: proto_id.and_then(|raw| raw.as_slice().try_into().ok()),
    })
}

/// Recompute the protocol identity of a hex-encoded certificate.
///
/// Returns `None` when the material is absent or is not a certificate; callers
/// store `NULL` rather than a guessed value.
fn proto_id_of_public_key_hex(public_key_hex: &str) -> Option<[u8; PROTO_ID_LEN]> {
    if public_key_hex.is_empty() {
        return None;
    }
    let bytes = hex::decode(public_key_hex).ok()?;
    proto_id_from_cert_bytes(&bytes).ok()
}

/// Trust graph storage backed by SQLite.
pub struct TrustStore {
    conn: Connection,
}

impl TrustStore {
    /// Open (or create) a trust database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(trust_err)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an ephemeral in-memory database (tests, simulations).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(trust_err)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS peer (
                     fingerprint     TEXT PRIMARY KEY,
                     uid             TEXT NOT NULL DEFAULT '',
                     public_key_hex  TEXT NOT NULL DEFAULT '',
                     descriptor      BLOB,
                     descriptor_sig  BLOB,
                     trust_score     REAL NOT NULL DEFAULT 0.0,
                     first_seen      INTEGER NOT NULL,
                     last_seen       INTEGER NOT NULL,
                     proto_id        BLOB
                 );
                 CREATE TABLE IF NOT EXISTS relationship (
                     signer       TEXT NOT NULL,
                     subject      TEXT NOT NULL,
                     level        INTEGER NOT NULL,
                     updated_at   INTEGER NOT NULL,
                     signature    BLOB NOT NULL DEFAULT x'',
                     PRIMARY KEY (signer, subject)
                 );",
            )
            .map_err(trust_err)?;

        // Migrate databases created before Phase 2.
        self.ensure_column("peer", "descriptor", "BLOB")?;
        self.ensure_column("peer", "descriptor_sig", "BLOB")?;
        self.ensure_column("relationship", "signature", "BLOB NOT NULL DEFAULT x''")?;
        // Protocol identity column (Phase 8); rows written by earlier builds
        // keep NULL until the peer is seen again.
        self.ensure_column("peer", "proto_id", "BLOB")?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, declaration: &str) -> Result<()> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2 LIMIT 1",
                params![table, column],
                |_| Ok(true),
            )
            .optional()
            .map_err(trust_err)?
            .unwrap_or(false);
        if !exists {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}");
            self.conn.execute(&sql, []).map_err(trust_err)?;
        }
        Ok(())
    }

    /// Insert or refresh a peer. `first_seen` is preserved on conflict.
    ///
    /// The protocol identity is recomputed from the supplied certificate, so
    /// `proto_id` always follows from the key material rather than from a
    /// claimed value. A later upsert without a certificate never clears a
    /// known `proto_id`.
    pub fn upsert_peer(
        &self,
        fingerprint: &str,
        uid: &str,
        public_key_hex: &str,
        now: u64,
    ) -> Result<()> {
        let proto_id = proto_id_of_public_key_hex(public_key_hex);
        self.conn
            .execute(
                "INSERT INTO peer (fingerprint, uid, public_key_hex, trust_score,
                                   first_seen, last_seen, proto_id)
                 VALUES (?1, ?2, ?3, 0.0, ?4, ?4, ?5)
                 ON CONFLICT(fingerprint) DO UPDATE SET
                     uid = excluded.uid,
                     public_key_hex = excluded.public_key_hex,
                     last_seen = excluded.last_seen,
                     proto_id = COALESCE(excluded.proto_id, peer.proto_id)",
                params![
                    fingerprint,
                    uid,
                    public_key_hex,
                    now as i64,
                    proto_id.map(|id| id.to_vec())
                ],
            )
            .map_err(trust_err)?;
        Ok(())
    }

    /// Fetch a peer by protocol identity.
    ///
    /// `proto_id` is the namespace key the protocol uses; the fingerprint
    /// (`cert_id`) remains the OpenPGP-level key.
    pub fn get_peer_by_proto_id(
        &self,
        proto_id: &[u8; PROTO_ID_LEN],
    ) -> Result<Option<PeerRecord>> {
        self.conn
            .query_row(
                "SELECT fingerprint, uid, public_key_hex, trust_score,
                        first_seen, last_seen, proto_id
                 FROM peer WHERE proto_id = ?1",
                params![proto_id.to_vec()],
                map_peer_row,
            )
            .optional()
            .map_err(trust_err)
    }

    /// Fetch a peer by fingerprint.
    pub fn get_peer(&self, fingerprint: &str) -> Result<Option<PeerRecord>> {
        self.conn
            .query_row(
                "SELECT fingerprint, uid, public_key_hex, trust_score,
                        first_seen, last_seen, proto_id
                 FROM peer WHERE fingerprint = ?1",
                params![fingerprint],
                map_peer_row,
            )
            .optional()
            .map_err(trust_err)
    }

    /// List peers ordered by fingerprint.
    pub fn peers(&self, limit: usize) -> Result<Vec<PeerRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT fingerprint, uid, public_key_hex, trust_score,
                        first_seen, last_seen, proto_id
                 FROM peer ORDER BY fingerprint LIMIT ?1",
            )
            .map_err(trust_err)?;
        let rows = stmt
            .query_map(params![limit as i64], map_peer_row)
            .map_err(trust_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(trust_err)
    }

    /// Store a peer's self-signed descriptor for gossip.
    pub fn store_descriptor(
        &self,
        fingerprint: &str,
        descriptor: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE peer SET descriptor = ?2, descriptor_sig = ?3
                 WHERE fingerprint = ?1",
                params![fingerprint, descriptor, signature],
            )
            .map_err(trust_err)?;
        if updated == 0 {
            return Err(IdentityError::Trust(format!(
                "cannot store descriptor for unknown peer {fingerprint}"
            )));
        }
        Ok(())
    }

    /// Fetch a stored descriptor and its signature.
    pub fn descriptor_of(&self, fingerprint: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT descriptor, descriptor_sig FROM peer
                 WHERE fingerprint = ?1 AND descriptor IS NOT NULL",
                params![fingerprint],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(trust_err)
    }

    /// All stored descriptors `(fingerprint, descriptor, signature)`.
    pub fn descriptors(&self, limit: usize) -> Result<Vec<StoredDescriptor>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT fingerprint, descriptor, descriptor_sig FROM peer
                 WHERE descriptor IS NOT NULL
                 ORDER BY fingerprint LIMIT ?1",
            )
            .map_err(trust_err)?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(trust_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(trust_err)
    }

    /// Store a directed trust relationship (last write wins).
    pub fn set_relationship(
        &self,
        signer: &str,
        subject: &str,
        level: u8,
        updated_at: u64,
        signature: &[u8],
    ) -> Result<()> {
        if level > 3 {
            return Err(IdentityError::Trust(format!(
                "trust level {level} out of range 0..=3"
            )));
        }
        self.conn
            .execute(
                "INSERT INTO relationship
                     (signer, subject, level, updated_at, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(signer, subject) DO UPDATE SET
                     level = excluded.level,
                     updated_at = excluded.updated_at,
                     signature = excluded.signature",
                params![signer, subject, level, updated_at as i64, signature],
            )
            .map_err(trust_err)?;
        Ok(())
    }

    /// Fetch one relationship.
    pub fn relationship(&self, signer: &str, subject: &str) -> Result<Option<Relationship>> {
        self.conn
            .query_row(
                "SELECT signer, subject, level, updated_at, signature
                 FROM relationship WHERE signer = ?1 AND subject = ?2",
                params![signer, subject],
                relationship_from_row,
            )
            .optional()
            .map_err(trust_err)
    }

    /// All relationships, ordered for deterministic scoring.
    pub fn relationships(&self) -> Result<Vec<Relationship>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT signer, subject, level, updated_at, signature
                 FROM relationship ORDER BY signer, subject",
            )
            .map_err(trust_err)?;
        let rows = stmt
            .query_map([], relationship_from_row)
            .map_err(trust_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(trust_err)
    }

    /// Update the cached trust score of a peer.
    pub fn set_trust_score(&self, fingerprint: &str, score: f64) -> Result<()> {
        if !(0.0..=1.0).contains(&score) {
            return Err(IdentityError::Trust(format!(
                "trust score {score} out of range 0.0..=1.0"
            )));
        }
        self.conn
            .execute(
                "UPDATE peer SET trust_score = ?2 WHERE fingerprint = ?1",
                params![fingerprint, score],
            )
            .map_err(trust_err)?;
        Ok(())
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM peer", [], |row| row.get::<_, i64>(0))
            .map(|n| n as u64)
            .map_err(trust_err)
    }
}

fn relationship_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Relationship> {
    Ok(Relationship {
        signer: row.get(0)?,
        subject: row.get(1)?,
        level: row.get(2)?,
        updated_at: row.get::<_, i64>(3)? as u64,
        signature: row.get(4)?,
    })
}

fn trust_err(e: rusqlite::Error) -> IdentityError {
    IdentityError::Trust(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_preserves_first_seen() {
        let store = TrustStore::in_memory().expect("store");
        store
            .upsert_peer("FP1", "alice", "aabb", 100)
            .expect("insert");
        store
            .upsert_peer("FP1", "alice2", "aabb", 200)
            .expect("update");

        let peer = store.get_peer("FP1").expect("get").expect("present");
        assert_eq!(peer.uid, "alice2");
        assert_eq!(peer.first_seen, 100);
        assert_eq!(peer.last_seen, 200);
        assert_eq!(store.peer_count().unwrap(), 1);
    }

    #[test]
    fn relationships_are_directed_and_ordered() {
        let store = TrustStore::in_memory().expect("store");
        store
            .set_relationship("ALICE", "BOB", 2, 10, b"sig-a")
            .expect("rel");
        store
            .set_relationship("CAROL", "BOB", 1, 11, b"sig-c")
            .expect("rel");

        let rel = store
            .relationship("ALICE", "BOB")
            .unwrap()
            .expect("present");
        assert_eq!(rel.level, 2);
        assert_eq!(rel.signature, b"sig-a");
        assert!(
            store.relationship("BOB", "ALICE").unwrap().is_none(),
            "relationships must be directed"
        );

        let all = store.relationships().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].signer, "ALICE");
        assert_eq!(all[1].signer, "CAROL");
    }

    #[test]
    fn descriptors_roundtrip_and_require_known_peer() {
        let store = TrustStore::in_memory().expect("store");
        store.upsert_peer("FP1", "alice", "aa", 1).expect("insert");
        store
            .store_descriptor("FP1", b"descriptor", b"signature")
            .expect("store");
        let (descriptor, signature) = store.descriptor_of("FP1").unwrap().unwrap();
        assert_eq!(descriptor, b"descriptor");
        assert_eq!(signature, b"signature");
        assert_eq!(store.descriptors(10).unwrap().len(), 1);

        assert!(store.store_descriptor("FP2", b"x", b"y").is_err());
    }

    #[test]
    fn trust_score_is_validated() {
        let store = TrustStore::in_memory().expect("store");
        store.upsert_peer("FP1", "alice", "aa", 1).expect("insert");
        assert!(store.set_trust_score("FP1", 0.5).is_ok());
        assert!(store.set_trust_score("FP1", 1.5).is_err());
        assert!(store.set_trust_score("FP1", -0.1).is_err());
        assert_eq!(store.get_peer("FP1").unwrap().unwrap().trust_score, 0.5);
    }

    #[test]
    fn rejects_out_of_range_trust_level() {
        let store = TrustStore::in_memory().expect("store");
        assert!(store.set_relationship("A", "B", 4, 1, b"").is_err());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.sqlite");
        {
            let store = TrustStore::open(&path).expect("open");
            store.upsert_peer("FP1", "alice", "aa", 42).expect("insert");
            store
                .store_descriptor("FP1", b"desc", b"sig")
                .expect("descriptor");
        }
        let store = TrustStore::open(&path).expect("reopen");
        assert_eq!(store.peer_count().unwrap(), 1);
        assert!(store.descriptor_of("FP1").unwrap().is_some());
    }

    #[test]
    fn proto_id_is_derived_from_the_stored_certificate() {
        let alice = crate::keys::Identity::generate("alice", "dest-alice").expect("identity");
        let fingerprint = alice.fingerprint_hex();
        let hex_cert = hex::encode(alice.public_cert_bytes().expect("bytes"));
        let store = TrustStore::in_memory().expect("store");
        store
            .upsert_peer(&fingerprint, "alice", &hex_cert, 1)
            .expect("insert");

        let peer = store.get_peer(&fingerprint).expect("get").expect("present");
        assert_eq!(
            peer.proto_id,
            Some(alice.proto_id()),
            "the stored protocol identity follows from the certificate"
        );
        let by_proto = store
            .get_peer_by_proto_id(&alice.proto_id())
            .expect("lookup")
            .expect("found by proto_id");
        assert_eq!(by_proto.fingerprint, fingerprint);
    }

    #[test]
    fn proto_id_lookup_misses_unknown_identities_and_survives_garbage() {
        let store = TrustStore::in_memory().expect("store");
        // Not a certificate: the row is kept, but no protocol identity is
        // invented for it.
        store
            .upsert_peer("FP1", "nobody", "aabb", 1)
            .expect("insert");
        let peer = store.get_peer("FP1").expect("get").expect("present");
        assert_eq!(peer.proto_id, None);
        assert!(
            store
                .get_peer_by_proto_id(&[0u8; PROTO_ID_LEN])
                .expect("lookup")
                .is_none()
        );

        // An upsert without usable key material must not clear a known value.
        let alice = crate::keys::Identity::generate("alice", "dest-alice").expect("identity");
        let hex_cert = hex::encode(alice.public_cert_bytes().expect("bytes"));
        store
            .upsert_peer("FP2", "alice", &hex_cert, 1)
            .expect("insert");
        store.upsert_peer("FP2", "alice", "", 2).expect("refresh");
        let peer = store.get_peer("FP2").expect("get").expect("present");
        assert_eq!(peer.proto_id, Some(alice.proto_id()));
    }

    #[test]
    fn trust_level_ordering_and_scores() {
        assert!(TrustLevel::Ultimate > TrustLevel::Full);
        assert!(TrustLevel::Full > TrustLevel::Marginal);
        assert!(TrustLevel::Marginal > TrustLevel::Unknown);
        assert!(TrustLevel::Unknown > TrustLevel::Never);
        assert_eq!(TrustLevel::from_i32(-1), TrustLevel::Never);
        assert_eq!(TrustLevel::Full.to_score(), 0.8);
    }
}
