//! File publishing, retrieval and chunk routing.
//!
//! Publishing splits and encrypts a file locally, stores the chunks, floods
//! them to connected peers and sends the manifest end-to-end encrypted to the
//! recipient. Retrieval asks the DHT-closest peers for missing chunks with
//! TTL-bound requests and a reverse-path so responses travel back.

use crate::relay::cert_bytes_for;
use crate::state::{NodeEvent, NodeState};
use crate::store::StoredManifest;
use anyhow::{Context, Result, bail};
use fantuan_core::time;
use fantuan_msg::{ChunkRequest, FileChunk, FileManifest, Object};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long `fetch_file` waits for all chunks.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(90);

fn hash_array(chunk: &FileChunk) -> [u8; 32] {
    chunk.hash.into_array()
}

fn load_cached_chunk(state: &Arc<NodeState>, hash: &[u8; 32]) -> Result<Option<FileChunk>> {
    let Some(bytes) = state.chunks.get(hash)? else {
        return Ok(None);
    };
    let object = Object::from_canonical_bytes(&bytes)?;
    match object {
        Object::FileChunk(chunk) => Ok(Some(chunk)),
        _ => Ok(None),
    }
}

fn store_chunk_object(state: &Arc<NodeState>, chunk: &FileChunk) -> Result<bool> {
    let bytes = Object::FileChunk(chunk.clone()).to_canonical_bytes()?;
    match state.chunks.insert(&hash_array(chunk), &bytes) {
        Ok(inserted) => Ok(inserted),
        Err(fantuan_storage::StorageError::CacheFull) => {
            tracing::warn!(
                "chunk cache full; not storing {}",
                hex::encode(&chunk.hash[..])
            );
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// Publish a file from disk. Returns the file id (hex).
pub fn publish_file(
    state: &Arc<NodeState>,
    path: &Path,
    recipient: Option<&str>,
) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file")
        .to_string();

    let (manifest, chunks) = fantuan_storage::build_chunks(&state.identity, &name, &data)?;
    for chunk in &chunks {
        store_chunk_object(state, chunk)?;
    }

    let manifest_bytes = Object::FileManifest(manifest.clone()).to_canonical_bytes()?;
    state
        .messages
        .lock()
        .map_err(|_| anyhow::anyhow!("message store poisoned"))?
        .insert_manifest(
            &manifest.file_id[..],
            &manifest.owner,
            &manifest.name,
            manifest.size,
            &manifest_bytes,
            time::now_unix(),
        )?;

    // Replicate chunks to connected peers.
    for chunk in &chunks {
        let bytes = Object::FileChunk(chunk.clone()).to_canonical_bytes()?;
        state.flood(None, bytes);
    }

    if let Some(recipient) = recipient {
        crate::relay::send_object(state, recipient, Object::FileManifest(manifest.clone()))?;
    }

    let file_id = hex::encode(&manifest.file_id[..]);
    state.emit(NodeEvent::FileAvailable {
        file_id: file_id.clone(),
        name: manifest.name.clone(),
        size: manifest.size,
        from: state.fingerprint(),
    });
    Ok(file_id)
}

/// Verify and store an incoming chunk; returns true when it was new.
pub fn handle_file_chunk(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    peer_cert: &[u8],
    chunk: FileChunk,
) -> Result<bool> {
    let cert_bytes = if chunk.owner == peer_fingerprint {
        peer_cert.to_vec()
    } else {
        cert_bytes_for(state, &chunk.owner)?
    };
    chunk.verify_cert_bytes(&cert_bytes)?;

    let hash = hash_array(&chunk);
    let object = Object::FileChunk(chunk.clone()).to_canonical_bytes()?;
    let stored = match state.chunks.insert(&hash, &object) {
        Ok(inserted) => inserted,
        Err(fantuan_storage::StorageError::CacheFull) => false,
        Err(error) => return Err(error.into()),
    };
    if stored {
        state.flood(Some(peer_fingerprint), object.clone());
    }

    // Forward toward any pending requesters via the recorded reverse path.
    for route in state.take_chunk_routes(&hash) {
        if route.requester == state.fingerprint() {
            continue;
        }
        let target = if state.pool.is_connected(&route.requester) {
            route.requester.clone()
        } else {
            route.via.clone()
        };
        if target != peer_fingerprint || !state.pool.is_connected(&route.requester) {
            let _ = state.pool.try_send(&target, object.clone());
        }
    }
    Ok(stored)
}

/// Answer or forward one chunk request.
pub fn handle_chunk_request(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    request: ChunkRequest,
) -> Result<()> {
    request.validate()?;
    let hash = request.hash.into_array();

    if let Some(bytes) = state.chunks.get(&hash)? {
        state.pool.try_send(peer_fingerprint, bytes)?;
        return Ok(());
    }
    if request.requester == state.fingerprint() {
        return Ok(());
    }
    if state.seen_request(&hash, &request.requester) {
        return Ok(());
    }

    state.remember_chunk_route(&hash, &request.requester, peer_fingerprint);
    let Some(forwarded) = request.forwarded() else {
        return Ok(());
    };
    let bytes = Object::ChunkRequest(forwarded).to_canonical_bytes()?;
    for target in state.closest_peers(&hash, 3) {
        if target == peer_fingerprint {
            continue;
        }
        let _ = state.pool.try_send(&target, bytes.clone());
    }
    Ok(())
}

/// Verify and store a manifest received inside a relay envelope.
pub fn handle_manifest(
    state: &Arc<NodeState>,
    manifest: FileManifest,
    from_fingerprint: &str,
    from_cert: &[u8],
) -> Result<bool> {
    let cert_bytes = if manifest.owner == from_fingerprint {
        from_cert.to_vec()
    } else {
        cert_bytes_for(state, &manifest.owner)?
    };
    manifest.verify_cert_bytes(&cert_bytes)?;

    let bytes = Object::FileManifest(manifest.clone()).to_canonical_bytes()?;
    let inserted = state
        .messages
        .lock()
        .map_err(|_| anyhow::anyhow!("message store poisoned"))?
        .insert_manifest(
            &manifest.file_id[..],
            &manifest.owner,
            &manifest.name,
            manifest.size,
            &bytes,
            time::now_unix(),
        )?;
    if inserted {
        state.emit(NodeEvent::FileAvailable {
            file_id: hex::encode(&manifest.file_id[..]),
            name: manifest.name.clone(),
            size: manifest.size,
            from: from_fingerprint.to_string(),
        });
    }
    Ok(inserted)
}

/// Load a stored manifest by file id.
pub fn load_manifest(state: &Arc<NodeState>, file_id: &[u8; 32]) -> Result<FileManifest> {
    let stored = state
        .messages
        .lock()
        .map_err(|_| anyhow::anyhow!("message store poisoned"))?
        .manifest(file_id)?;
    let Some(bytes) = stored else {
        bail!("unknown file {}", hex::encode(&file_id[..]));
    };
    match Object::from_canonical_bytes(&bytes)? {
        Object::FileManifest(manifest) => Ok(manifest),
        _ => bail!("stored object is not a manifest"),
    }
}

/// List stored manifests.
pub fn list_files(state: &Arc<NodeState>, limit: usize) -> Result<Vec<StoredManifest>> {
    let store = state
        .messages
        .lock()
        .map_err(|_| anyhow::anyhow!("message store poisoned"))?;
    store.manifests(limit)
}

/// Request missing chunks and write the assembled file to `out_path`.
pub async fn fetch_file(state: &Arc<NodeState>, file_id_hex: &str, out_path: &Path) -> Result<()> {
    let bytes = hex::decode(file_id_hex).context("file id must be hex")?;
    let file_id: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("file id must be 32 bytes"))?;
    let manifest = load_manifest(state, &file_id)?;
    manifest.validate()?;

    let mut have: BTreeMap<u32, FileChunk> = BTreeMap::new();
    let mut missing: Vec<(u32, [u8; 32])> = Vec::new();
    for (index, hash) in manifest.chunks.iter().enumerate() {
        let hash = hash.into_array();
        match load_cached_chunk(state, &hash)? {
            Some(chunk) => {
                have.insert(index as u32, chunk);
            }
            None => missing.push((index as u32, hash)),
        }
    }

    let deadline = Instant::now() + FETCH_TIMEOUT;
    while !missing.is_empty() && Instant::now() < deadline {
        for (index, hash) in &missing {
            let request = ChunkRequest::new(&manifest.file_id, *index, hash, &state.fingerprint());
            let bytes = Object::ChunkRequest(request).to_canonical_bytes()?;
            let mut targets = state.closest_peers(hash, 3);
            if targets.is_empty() {
                targets = state.pool.peers();
            }
            for target in targets {
                let _ = state.pool.try_send(&target, bytes.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        missing.retain(|(index, hash)| match load_cached_chunk(state, hash) {
            Ok(Some(chunk)) => {
                have.insert(*index, chunk);
                false
            }
            _ => true,
        });
    }

    if !missing.is_empty() {
        bail!("timed out with {} chunks missing", missing.len());
    }
    let data = fantuan_storage::assemble(&manifest, &have)?;
    std::fs::write(out_path, data)
        .with_context(|| format!("cannot write {}", out_path.display()))?;
    Ok(())
}
