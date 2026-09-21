//! Persistent trust graph storage.
//!
//! SQLite schema:
//!
//! ```sql
//! peer(fingerprint PK, uid, public_key_hex, trust_score, first_seen, last_seen)
//! relationship(signer, subject, level, updated_at, PK(signer, subject))
//! ```
//!
//! Trust scoring and gossip land in Phase 2; this module owns the durable
//! shape of the graph and its invariants.

use crate::error::{IdentityError, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

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
                     trust_score     REAL NOT NULL DEFAULT 0.0,
                     first_seen      INTEGER NOT NULL,
                     last_seen       INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS relationship (
                     signer       TEXT NOT NULL,
                     subject      TEXT NOT NULL,
                     level        INTEGER NOT NULL,
                     updated_at   INTEGER NOT NULL,
                     PRIMARY KEY (signer, subject)
                 );",
            )
            .map_err(trust_err)
    }

    /// Insert or refresh a peer. `first_seen` is preserved on conflict.
    pub fn upsert_peer(
        &self,
        fingerprint: &str,
        uid: &str,
        public_key_hex: &str,
        now: u64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO peer (fingerprint, uid, public_key_hex, trust_score,
                                   first_seen, last_seen)
                 VALUES (?1, ?2, ?3, 0.0, ?4, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE SET
                     uid = excluded.uid,
                     public_key_hex = excluded.public_key_hex,
                     last_seen = excluded.last_seen",
                params![fingerprint, uid, public_key_hex, now as i64],
            )
            .map_err(trust_err)?;
        Ok(())
    }

    /// Fetch a peer by fingerprint.
    pub fn get_peer(&self, fingerprint: &str) -> Result<Option<PeerRecord>> {
        self.conn
            .query_row(
                "SELECT fingerprint, uid, public_key_hex, trust_score,
                        first_seen, last_seen
                 FROM peer WHERE fingerprint = ?1",
                params![fingerprint],
                |row| {
                    Ok(PeerRecord {
                        fingerprint: row.get(0)?,
                        uid: row.get(1)?,
                        public_key_hex: row.get(2)?,
                        trust_score: row.get(3)?,
                        first_seen: row.get::<_, i64>(4)? as u64,
                        last_seen: row.get::<_, i64>(5)? as u64,
                    })
                },
            )
            .optional()
            .map_err(trust_err)
    }

    /// Store a directed trust relationship (last write wins).
    pub fn set_relationship(&self, signer: &str, subject: &str, level: u8, now: u64) -> Result<()> {
        if level > 3 {
            return Err(IdentityError::Trust(format!(
                "trust level {level} out of range 0..=3"
            )));
        }
        self.conn
            .execute(
                "INSERT INTO relationship (signer, subject, level, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(signer, subject) DO UPDATE SET
                     level = excluded.level,
                     updated_at = excluded.updated_at",
                params![signer, subject, level, now as i64],
            )
            .map_err(trust_err)?;
        Ok(())
    }

    /// Fetch one relationship.
    pub fn relationship(&self, signer: &str, subject: &str) -> Result<Option<Relationship>> {
        self.conn
            .query_row(
                "SELECT signer, subject, level, updated_at
                 FROM relationship WHERE signer = ?1 AND subject = ?2",
                params![signer, subject],
                |row| {
                    Ok(Relationship {
                        signer: row.get(0)?,
                        subject: row.get(1)?,
                        level: row.get(2)?,
                        updated_at: row.get::<_, i64>(3)? as u64,
                    })
                },
            )
            .optional()
            .map_err(trust_err)
    }

    /// All incoming relationships for a subject.
    pub fn relationships_for(&self, subject: &str) -> Result<Vec<Relationship>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT signer, subject, level, updated_at
                 FROM relationship WHERE subject = ?1 ORDER BY signer",
            )
            .map_err(trust_err)?;
        let rows = stmt
            .query_map(params![subject], |row| {
                Ok(Relationship {
                    signer: row.get(0)?,
                    subject: row.get(1)?,
                    level: row.get(2)?,
                    updated_at: row.get::<_, i64>(3)? as u64,
                })
            })
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
        store.set_relationship("ALICE", "BOB", 2, 10).expect("rel");
        store.set_relationship("CAROL", "BOB", 1, 11).expect("rel");

        let rel = store
            .relationship("ALICE", "BOB")
            .unwrap()
            .expect("present");
        assert_eq!(rel.level, 2);
        assert!(
            store.relationship("BOB", "ALICE").unwrap().is_none(),
            "relationships must be directed"
        );

        let incoming = store.relationships_for("BOB").unwrap();
        assert_eq!(incoming.len(), 2);
        assert_eq!(incoming[0].signer, "ALICE");
        assert_eq!(incoming[1].signer, "CAROL");
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
        assert!(store.set_relationship("A", "B", 4, 1).is_err());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.sqlite");
        {
            let store = TrustStore::open(&path).expect("open");
            store.upsert_peer("FP1", "alice", "aa", 42).expect("insert");
        }
        let store = TrustStore::open(&path).expect("reopen");
        assert_eq!(store.peer_count().unwrap(), 1);
    }
}
