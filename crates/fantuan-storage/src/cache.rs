//! redb-backed chunk cache.
//!
//! Stores raw chunk bytes keyed by their content hash. Storage nodes only
//! ever hold `hash -> ciphertext`; the file key never reaches the cache.
//! A byte budget bounds how much of the disk can be filled.

use crate::error::{Result, StorageError};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

const CHUNKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunks");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const BYTES_USED: &str = "bytes_used";

/// Content-addressed chunk cache.
pub struct ChunkCache {
    db: Database,
    max_bytes: u64,
}

impl ChunkCache {
    /// Open (or create) a cache at `path` with a byte budget.
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(path).map_err(cache_err)?;
        let cache = Self { db, max_bytes };
        cache.ensure_tables()?;
        Ok(cache)
    }

    /// Ephemeral in-memory cache (tests, simulations).
    pub fn in_memory(max_bytes: u64) -> Result<Self> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(cache_err)?;
        let cache = Self { db, max_bytes };
        cache.ensure_tables()?;
        Ok(cache)
    }

    fn ensure_tables(&self) -> Result<()> {
        let txn = self.db.begin_write().map_err(cache_err)?;
        {
            let _ = txn.open_table(CHUNKS).map_err(cache_err)?;
            let _ = txn.open_table(META).map_err(cache_err)?;
        }
        txn.commit().map_err(cache_err)?;
        Ok(())
    }

    /// Insert chunk bytes; returns false when the hash is already present.
    pub fn insert(&self, hash: &[u8; 32], bytes: &[u8]) -> Result<bool> {
        let txn = self.db.begin_write().map_err(cache_err)?;
        let inserted = {
            let mut chunks = txn.open_table(CHUNKS).map_err(cache_err)?;
            if chunks.get(&hash[..]).map_err(cache_err)?.is_some() {
                false
            } else {
                let used = {
                    let meta = txn.open_table(META).map_err(cache_err)?;
                    meta.get(BYTES_USED)
                        .map_err(cache_err)?
                        .map(|value| value.value())
                        .unwrap_or(0)
                };
                if used.saturating_add(bytes.len() as u64) > self.max_bytes {
                    return Err(StorageError::CacheFull);
                }
                chunks.insert(&hash[..], bytes).map_err(cache_err)?;
                let mut meta = txn.open_table(META).map_err(cache_err)?;
                meta.insert(BYTES_USED, used + bytes.len() as u64)
                    .map_err(cache_err)?;
                true
            }
        };
        txn.commit().map_err(cache_err)?;
        Ok(inserted)
    }

    /// Fetch chunk bytes by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(cache_err)?;
        let table = txn.open_table(CHUNKS).map_err(cache_err)?;
        Ok(table
            .get(&hash[..])
            .map_err(cache_err)?
            .map(|value| value.value().to_vec()))
    }

    /// True when the hash is cached.
    pub fn contains(&self, hash: &[u8; 32]) -> Result<bool> {
        let txn = self.db.begin_read().map_err(cache_err)?;
        let table = txn.open_table(CHUNKS).map_err(cache_err)?;
        Ok(table.get(&hash[..]).map_err(cache_err)?.is_some())
    }

    /// Remove one chunk; returns true when it existed.
    pub fn remove(&self, hash: &[u8; 32]) -> Result<bool> {
        let txn = self.db.begin_write().map_err(cache_err)?;
        let removed = {
            let mut chunks = txn.open_table(CHUNKS).map_err(cache_err)?;
            let existing = chunks
                .get(&hash[..])
                .map_err(cache_err)?
                .map(|value| value.value().len() as u64);
            match existing {
                Some(size) => {
                    chunks.remove(&hash[..]).map_err(cache_err)?;
                    let used = {
                        let meta = txn.open_table(META).map_err(cache_err)?;
                        meta.get(BYTES_USED)
                            .map_err(cache_err)?
                            .map(|value| value.value())
                            .unwrap_or(0)
                    };
                    let mut meta = txn.open_table(META).map_err(cache_err)?;
                    meta.insert(BYTES_USED, used.saturating_sub(size))
                        .map_err(cache_err)?;
                    true
                }
                None => false,
            }
        };
        txn.commit().map_err(cache_err)?;
        Ok(removed)
    }

    /// Number of cached chunks.
    pub fn len(&self) -> Result<u64> {
        let txn = self.db.begin_read().map_err(cache_err)?;
        let table = txn.open_table(CHUNKS).map_err(cache_err)?;
        table.len().map_err(cache_err)
    }

    /// True when the cache is empty.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Bytes currently stored according to the accounting counter.
    pub fn total_bytes(&self) -> Result<u64> {
        let txn = self.db.begin_read().map_err(cache_err)?;
        let meta = txn.open_table(META).map_err(cache_err)?;
        Ok(meta
            .get(BYTES_USED)
            .map_err(cache_err)?
            .map(|value| value.value())
            .unwrap_or(0))
    }

    /// Remove every chunk.
    pub fn clear(&self) -> Result<()> {
        let txn = self.db.begin_write().map_err(cache_err)?;
        txn.delete_table(CHUNKS).map_err(cache_err)?;
        txn.delete_table(META).map_err(cache_err)?;
        txn.commit().map_err(cache_err)?;
        self.ensure_tables()
    }
}

fn cache_err(error: impl std::fmt::Display) -> StorageError {
    StorageError::Cache(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn insert_get_remove() {
        let cache = ChunkCache::in_memory(1024).expect("cache");
        assert!(cache.insert(&hash(1), b"one").expect("insert"));
        assert!(!cache.insert(&hash(1), b"one").expect("duplicate"));
        assert_eq!(cache.get(&hash(1)).unwrap().as_deref(), Some(&b"one"[..]));
        assert!(cache.contains(&hash(1)).unwrap());
        assert_eq!(cache.len().unwrap(), 1);
        assert_eq!(cache.total_bytes().unwrap(), 3);

        assert!(cache.remove(&hash(1)).unwrap());
        assert!(!cache.remove(&hash(1)).unwrap());
        assert!(cache.get(&hash(1)).unwrap().is_none());
        assert_eq!(cache.total_bytes().unwrap(), 0);
    }

    #[test]
    fn capacity_is_enforced() {
        let cache = ChunkCache::in_memory(10).expect("cache");
        assert!(cache.insert(&hash(1), &[0u8; 8]).is_ok());
        assert!(matches!(
            cache.insert(&hash(2), &[0u8; 8]),
            Err(StorageError::CacheFull)
        ));
        // Re-inserting an existing hash still succeeds.
        assert!(!cache.insert(&hash(1), &[0u8; 8]).expect("duplicate"));
    }

    #[test]
    fn clear_resets_everything() {
        let cache = ChunkCache::in_memory(1024).expect("cache");
        cache.insert(&hash(1), b"one").unwrap();
        cache.insert(&hash(2), b"two").unwrap();
        cache.clear().unwrap();
        assert_eq!(cache.len().unwrap(), 0);
        assert_eq!(cache.total_bytes().unwrap(), 0);
        assert!(cache.insert(&hash(3), b"three").is_ok());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chunks.redb");
        {
            let cache = ChunkCache::open(&path, 1024).expect("open");
            cache.insert(&hash(9), b"persisted").expect("insert");
        }
        let cache = ChunkCache::open(&path, 1024).expect("reopen");
        assert_eq!(
            cache.get(&hash(9)).unwrap().as_deref(),
            Some(&b"persisted"[..])
        );
    }
}
