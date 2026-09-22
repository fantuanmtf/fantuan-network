//! Local message store (SQLite).
//!
//! Stores verified channel messages and forum posts, plus per-peer history
//! sync checkpoints used to deliver messages missed while offline.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

/// One stored channel message.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredMessage {
    /// Object id.
    pub id: Vec<u8>,
    /// Sender fingerprint.
    pub from: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub text: String,
    /// Canonical `Object` bytes as received.
    pub object: Vec<u8>,
}

/// One stored forum post.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPost {
    /// Object id.
    pub id: Vec<u8>,
    /// Sender fingerprint.
    pub from: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Post title.
    pub title: String,
    /// Post body.
    pub body: String,
    /// Canonical `Object` bytes as received.
    pub object: Vec<u8>,
}

/// One stored file manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredManifest {
    /// File id.
    pub file_id: Vec<u8>,
    /// Owner fingerprint.
    pub owner: String,
    /// File name.
    pub name: String,
    /// Plaintext size.
    pub size: u64,
    /// Canonical `Object::FileManifest` bytes.
    pub manifest: Vec<u8>,
    /// Unix seconds when received.
    pub received_at: u64,
}

/// SQLite-backed message store.
pub struct MessageStore {
    conn: Connection,
}

impl MessageStore {
    /// Open (or create) the store at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("cannot open message database")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Ephemeral in-memory store (tests).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS channel_message (
                 id         BLOB PRIMARY KEY,
                 channel    TEXT NOT NULL,
                 sender     TEXT NOT NULL,
                 timestamp  INTEGER NOT NULL,
                 text       BLOB NOT NULL,
                 object     BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_channel_message_topic
                 ON channel_message(channel, timestamp);
             CREATE TABLE IF NOT EXISTS forum_post (
                 id         BLOB PRIMARY KEY,
                 board      TEXT NOT NULL,
                 sender     TEXT NOT NULL,
                 timestamp  INTEGER NOT NULL,
                 title      TEXT NOT NULL,
                 body       BLOB NOT NULL,
                 object     BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_forum_post_topic
                 ON forum_post(board, timestamp);
             CREATE TABLE IF NOT EXISTS file_manifest (
                 file_id     BLOB PRIMARY KEY,
                 owner       TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 size        INTEGER NOT NULL,
                 manifest    BLOB NOT NULL,
                 received_at INTEGER NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Insert a channel message; returns false when the id already exists.
    pub fn insert_channel_message(
        &self,
        channel: &str,
        sender: &str,
        timestamp: u64,
        text: &[u8],
        object: &[u8],
    ) -> Result<bool> {
        let id = object_id(object);
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO channel_message
                 (id, channel, sender, timestamp, text, object)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, channel, sender, timestamp as i64, text, object],
        )?;
        Ok(changed > 0)
    }

    /// Messages for a channel newer than `since`, oldest first.
    pub fn channel_messages(
        &self,
        channel: &str,
        since: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, timestamp, text, object FROM channel_message
             WHERE channel = ?1 AND timestamp > ?2
             ORDER BY timestamp ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![channel, since as i64, limit as i64], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                from: row.get(1)?,
                timestamp: row.get::<_, i64>(2)? as u64,
                text: String::from_utf8_lossy(&row.get::<_, Vec<u8>>(3)?).to_string(),
                object: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Highest stored timestamp for a channel (0 when empty).
    pub fn latest_channel_timestamp(&self, channel: &str) -> Result<u64> {
        let value: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(timestamp) FROM channel_message WHERE channel = ?1",
                params![channel],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(value.unwrap_or(0) as u64)
    }

    /// Insert a forum post; returns false when the id already exists.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_forum_post(
        &self,
        board: &str,
        sender: &str,
        timestamp: u64,
        title: &str,
        body: &[u8],
        object: &[u8],
    ) -> Result<bool> {
        let id = object_id(object);
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO forum_post
                 (id, board, sender, timestamp, title, body, object)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, board, sender, timestamp as i64, title, body, object],
        )?;
        Ok(changed > 0)
    }

    /// Posts for a board newer than `since`, oldest first.
    pub fn forum_posts(&self, board: &str, since: u64, limit: usize) -> Result<Vec<StoredPost>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, timestamp, title, body, object FROM forum_post
             WHERE board = ?1 AND timestamp > ?2
             ORDER BY timestamp ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![board, since as i64, limit as i64], |row| {
            Ok(StoredPost {
                id: row.get(0)?,
                from: row.get(1)?,
                timestamp: row.get::<_, i64>(2)? as u64,
                title: row.get(3)?,
                body: String::from_utf8_lossy(&row.get::<_, Vec<u8>>(4)?).to_string(),
                object: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Highest stored timestamp for a board (0 when empty).
    pub fn latest_forum_timestamp(&self, board: &str) -> Result<u64> {
        let value: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(timestamp) FROM forum_post WHERE board = ?1",
                params![board],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(value.unwrap_or(0) as u64)
    }

    /// Delete a channel message or forum post by object id.
    pub fn delete_object(&self, id: &[u8]) -> Result<bool> {
        let channel = self
            .conn
            .execute("DELETE FROM channel_message WHERE id = ?1", params![id])?;
        let forum = self
            .conn
            .execute("DELETE FROM forum_post WHERE id = ?1", params![id])?;
        Ok(channel + forum > 0)
    }

    /// Insert a file manifest; returns false when it already exists.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_manifest(
        &self,
        file_id: &[u8],
        owner: &str,
        name: &str,
        size: u64,
        manifest: &[u8],
        received_at: u64,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO file_manifest
                 (file_id, owner, name, size, manifest, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                file_id,
                owner,
                name,
                size as i64,
                manifest,
                received_at as i64
            ],
        )?;
        Ok(changed > 0)
    }

    /// Fetch a stored manifest by file id.
    pub fn manifest(&self, file_id: &[u8]) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT manifest FROM file_manifest WHERE file_id = ?1",
                params![file_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// List stored manifests, newest first.
    pub fn manifests(&self, limit: usize) -> Result<Vec<StoredManifest>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_id, owner, name, size, manifest, received_at
             FROM file_manifest ORDER BY received_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(StoredManifest {
                file_id: row.get(0)?,
                owner: row.get(1)?,
                name: row.get(2)?,
                size: row.get::<_, i64>(3)? as u64,
                manifest: row.get(4)?,
                received_at: row.get::<_, i64>(5)? as u64,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

/// Object ids are BLAKE3 over the canonical object bytes.
fn object_id(object: &[u8]) -> Vec<u8> {
    blake3::hash(object).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_messages_dedup_and_order() {
        let store = MessageStore::in_memory().unwrap();
        assert!(
            store
                .insert_channel_message("#g", "A", 10, b"one", b"obj1")
                .unwrap()
        );
        assert!(
            !store
                .insert_channel_message("#g", "A", 10, b"one", b"obj1")
                .unwrap()
        );
        store
            .insert_channel_message("#g", "B", 20, b"two", b"obj2")
            .unwrap();
        store
            .insert_channel_message("#other", "C", 30, b"three", b"obj3")
            .unwrap();

        let messages = store.channel_messages("#g", 0, 100).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].text, "one");
        assert_eq!(messages[1].from, "B");
        assert_eq!(store.channel_messages("#g", 10, 100).unwrap().len(), 1);
        assert_eq!(store.latest_channel_timestamp("#g").unwrap(), 20);
    }

    #[test]
    fn forum_posts_and_delete() {
        let store = MessageStore::in_memory().unwrap();
        store
            .insert_forum_post("bbs", "A", 5, "title", b"body", b"objA")
            .unwrap();
        store
            .insert_forum_post("bbs", "B", 6, "title2", b"body2", b"objB")
            .unwrap();

        let posts = store.forum_posts("bbs", 0, 10).unwrap();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[1].title, "title2");
        assert_eq!(store.latest_forum_timestamp("bbs").unwrap(), 6);

        let id = object_id(b"objA");
        assert!(store.delete_object(&id).unwrap());
        assert!(!store.delete_object(&id).unwrap());
        assert_eq!(store.forum_posts("bbs", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.sqlite");
        {
            let store = MessageStore::open(&path).unwrap();
            store
                .insert_channel_message("#g", "A", 1, b"hi", b"obj")
                .unwrap();
        }
        let store = MessageStore::open(&path).unwrap();
        assert_eq!(store.channel_messages("#g", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn manifests_roundtrip_and_dedup() {
        let store = MessageStore::in_memory().unwrap();
        assert!(
            store
                .insert_manifest(b"file-id", "OWNER", "secret.bin", 10, b"manifest", 5)
                .unwrap()
        );
        assert!(
            !store
                .insert_manifest(b"file-id", "OWNER", "secret.bin", 10, b"manifest", 5)
                .unwrap()
        );
        assert_eq!(
            store.manifest(b"file-id").unwrap().as_deref(),
            Some(&b"manifest"[..])
        );
        let manifests = store.manifests(10).unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].name, "secret.bin");
        assert_eq!(manifests[0].size, 10);
    }
}
