//! Chunking, encryption and assembly.
//!
//! Layout of a published file:
//!
//! 1. a random 32-byte file key is generated;
//! 2. the plaintext is split into [`CHUNK_SIZE`] chunks;
//! 3. each chunk is encrypted with ChaCha20-Poly1305 using a random nonce and
//!    associated data `file_id || index`;
//! 4. chunks are content addressed by `BLAKE3(ciphertext)` and signed by the
//!    owner;
//! 5. the signed manifest carries the ordered hashes and the file key.

use crate::error::{Result, StorageError};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use fantuan_identity::Identity;
use fantuan_msg::{
    CHUNK_SIZE, FileChunk, FileManifest, MAX_FILE_CHUNKS, MAX_FILE_NAME_BYTES, MAX_FILE_SIZE,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Domain separator for file id derivation.
const FILE_ID_DOMAIN: &[u8] = b"fantuan-file-id-v1";

/// Derive a file id from owner, name, creation time and key.
fn derive_file_id(owner: &str, name: &str, created: u64, key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILE_ID_DOMAIN);
    for field in [owner, name] {
        hasher.update(&(field.len() as u32).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(&created.to_be_bytes());
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

fn chunk_aad(file_id: &[u8; 32], index: u32) -> [u8; 36] {
    let mut aad = [0u8; 36];
    aad[..32].copy_from_slice(file_id);
    aad[32..].copy_from_slice(&index.to_be_bytes());
    aad
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| StorageError::Crypto(format!("entropy failure: {error}")))?;
    Ok(bytes)
}

/// Split, encrypt and sign a file into chunks plus its manifest.
pub fn build_chunks(
    identity: &Identity,
    name: &str,
    data: &[u8],
) -> Result<(FileManifest, Vec<FileChunk>)> {
    if name.is_empty() || name.len() > MAX_FILE_NAME_BYTES {
        return Err(StorageError::Invalid(format!("invalid file name {name:?}")));
    }
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(StorageError::Invalid(format!(
            "file is {} bytes (limit {MAX_FILE_SIZE})",
            data.len()
        )));
    }
    let expected_chunks = data.len().div_ceil(CHUNK_SIZE);
    if expected_chunks > MAX_FILE_CHUNKS {
        return Err(StorageError::Invalid(format!(
            "file needs {expected_chunks} chunks (limit {MAX_FILE_CHUNKS})"
        )));
    }

    let key = Zeroizing::new(random_bytes::<32>()?);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let owner = identity.fingerprint_hex();
    let file_id = derive_file_id(&owner, name, created, &key);
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|error| StorageError::Crypto(error.to_string()))?;

    let mut chunks = Vec::with_capacity(expected_chunks);
    for (index, plaintext) in data.chunks(CHUNK_SIZE).enumerate() {
        let index = index as u32;
        let nonce = random_bytes::<12>()?;
        let aad = chunk_aad(&file_id, index);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|error| StorageError::Crypto(error.to_string()))?;
        chunks.push(FileChunk::create(
            identity, &file_id, index, &nonce, ciphertext,
        )?);
    }

    let hashes = chunks.iter().map(|chunk| chunk.hash.into_array()).collect();
    let manifest = FileManifest::create(
        identity,
        &file_id,
        name,
        data.len() as u64,
        CHUNK_SIZE as u32,
        hashes,
        &key,
        created,
    )?;
    Ok((manifest, chunks))
}

/// Verify and decrypt one chunk against its manifest.
pub fn decrypt_chunk(manifest: &FileManifest, chunk: &FileChunk) -> Result<Vec<u8>> {
    manifest.validate()?;
    chunk.validate()?;
    if chunk.file_id != manifest.file_id {
        return Err(StorageError::Invalid(
            "chunk belongs to another file".to_string(),
        ));
    }
    if manifest.chunk_hash(chunk.index) != Some(chunk.hash.into_array()) {
        return Err(StorageError::Invalid(format!(
            "chunk {} does not match the manifest",
            chunk.index
        )));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&manifest.key[..])
        .map_err(|error| StorageError::Crypto(error.to_string()))?;
    let aad = chunk_aad(&manifest.file_id, chunk.index);
    cipher
        .decrypt(
            Nonce::from_slice(&chunk.nonce[..]),
            Payload {
                msg: &chunk.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::Crypto("chunk decryption failed".to_string()))
}

/// Verify every chunk hash and decrypt, in order, producing the file.
pub fn assemble(manifest: &FileManifest, chunks: &BTreeMap<u32, FileChunk>) -> Result<Vec<u8>> {
    manifest.validate()?;
    let mut output = Vec::with_capacity(manifest.size as usize);
    for index in 0..manifest.chunks.len() as u32 {
        let chunk = chunks
            .get(&index)
            .ok_or(StorageError::MissingChunk(index))?;
        output.extend_from_slice(&decrypt_chunk(manifest, chunk)?);
    }
    if output.len() as u64 != manifest.size {
        return Err(StorageError::Invalid(format!(
            "assembled {} bytes but manifest declares {}",
            output.len(),
            manifest.size
        )));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_identity::keys::cert_from_bytes;

    fn identity(uid: &str) -> Identity {
        Identity::generate(uid, &format!("dest-{uid}")).expect("identity")
    }

    #[test]
    fn roundtrip_single_and_multi_chunk() {
        let alice = identity("alice");
        for data in [
            b"small file".to_vec(),
            vec![7u8; CHUNK_SIZE],
            vec![9u8; CHUNK_SIZE * 3 + 17],
            Vec::new(),
        ] {
            let (manifest, chunks) = build_chunks(&alice, "test.bin", &data).expect("build");
            assert_eq!(chunks.len(), manifest.chunks.len());
            let map: BTreeMap<u32, FileChunk> = chunks
                .into_iter()
                .map(|chunk| (chunk.index, chunk))
                .collect();
            let assembled = assemble(&manifest, &map).expect("assemble");
            assert_eq!(assembled, data);
        }
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let alice = identity("alice");
        let plaintext = b"THE-SECRET-MARKER-0123456789";
        let (_manifest, chunks) = build_chunks(&alice, "secret.txt", plaintext).expect("build");
        for chunk in &chunks {
            let haystack = chunk.ciphertext.to_vec();
            assert!(
                !haystack
                    .windows(plaintext.len())
                    .any(|window| window == plaintext),
                "ciphertext must not contain plaintext"
            );
        }
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let alice = identity("alice");
        let (manifest, chunks) = build_chunks(&alice, "f", b"hello world").expect("build");
        let mut tampered = chunks[0].clone();
        tampered.ciphertext = serde_bytes::ByteBuf::from(b"garbage".to_vec());
        assert!(decrypt_chunk(&manifest, &tampered).is_err());
    }

    #[test]
    fn wrong_index_or_key_fails() {
        let alice = identity("alice");
        let (manifest, chunks) =
            build_chunks(&alice, "f", &vec![1u8; CHUNK_SIZE * 2]).expect("build");

        // Swapping indices breaks the associated data / hash mapping.
        let mut moved = chunks[1].clone();
        moved.index = 0;
        assert!(decrypt_chunk(&manifest, &moved).is_err());

        // A different file key cannot decrypt.
        let mut wrong_key = manifest.clone();
        wrong_key.key = serde_bytes::ByteArray::new([0u8; 32]);
        assert!(decrypt_chunk(&wrong_key, &chunks[0]).is_err());
    }

    #[test]
    fn missing_chunk_is_reported() {
        let alice = identity("alice");
        let (manifest, chunks) =
            build_chunks(&alice, "f", &vec![1u8; CHUNK_SIZE + 1]).expect("build");
        let mut map = BTreeMap::new();
        map.insert(0u32, chunks[0].clone());
        assert!(matches!(
            assemble(&manifest, &map),
            Err(StorageError::MissingChunk(1))
        ));
    }

    #[test]
    fn owner_signature_verifies() {
        let alice = identity("alice");
        let (manifest, chunks) = build_chunks(&alice, "f", b"data").expect("build");
        let cert = cert_from_bytes(&alice.public_cert_bytes().unwrap()).unwrap();
        manifest.verify(&cert).expect("manifest signature");
        chunks[0].verify(&cert).expect("chunk signature");
    }
}
