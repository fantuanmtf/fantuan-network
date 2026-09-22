//! File sharing objects: chunks, manifests and chunk requests.
//!
//! A file is split into fixed-size plaintext chunks, each encrypted with
//! ChaCha20-Poly1305 under a random per-file key with the file id and chunk
//! index as associated data. Chunks are content addressed by
//! `BLAKE3(ciphertext)`, so storage nodes only ever hold hashes and
//! ciphertext. The manifest (which contains the file key) is only ever
//! transported end-to-end encrypted and is signed by the owner.

use crate::error::{MsgError, Result};
use fantuan_identity::Identity;
use fantuan_identity::keys::{cert_from_bytes, verify_detached};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use std::fmt;

/// Plaintext chunk size (32 KiB).
pub const CHUNK_SIZE: usize = 32 * 1024;
/// Maximum file name size.
pub const MAX_FILE_NAME_BYTES: usize = 256;
/// Maximum file size accepted (128 MiB).
pub const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;
/// Maximum number of chunks in one file.
pub const MAX_FILE_CHUNKS: usize = 4096;
/// Maximum forwarding TTL for chunk requests.
pub const MAX_REQUEST_TTL: u8 = 8;

/// Domain separator for chunk signatures.
pub const CHUNK_DOMAIN: &[u8] = b"fantuan-chunk-v1";
/// Domain separator for manifest signatures.
pub const FILE_DOMAIN: &[u8] = b"fantuan-file-v1";

/// Exact bytes covered by a chunk signature.
pub fn chunk_message(owner: &str, file_id: &[u8; 32], index: u32, hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHUNK_DOMAIN.len() + owner.len() + 80);
    message.extend_from_slice(CHUNK_DOMAIN);
    message.extend_from_slice(&(owner.len() as u32).to_be_bytes());
    message.extend_from_slice(owner.as_bytes());
    message.extend_from_slice(file_id);
    message.extend_from_slice(&index.to_be_bytes());
    message.extend_from_slice(hash);
    message
}

/// One encrypted, content-addressed file chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChunk {
    /// Manifest id this chunk belongs to.
    pub file_id: ByteArray<32>,
    /// Chunk index within the file.
    pub index: u32,
    /// `BLAKE3(ciphertext)`.
    pub hash: ByteArray<32>,
    /// ChaCha20-Poly1305 nonce.
    pub nonce: ByteArray<12>,
    /// Ciphertext (plaintext length + 16-byte tag).
    pub ciphertext: ByteBuf,
    /// Owner fingerprint (uppercase hex).
    pub owner: String,
    /// Detached OpenPGP signature over [`chunk_message`].
    pub signature: ByteBuf,
}

impl FileChunk {
    /// Build and sign a chunk from ciphertext.
    pub fn create(
        identity: &Identity,
        file_id: &[u8; 32],
        index: u32,
        nonce: &[u8; 12],
        ciphertext: Vec<u8>,
    ) -> Result<Self> {
        if index as usize >= MAX_FILE_CHUNKS {
            return Err(MsgError::TooLarge(format!(
                "chunk index {index} exceeds maximum"
            )));
        }
        if ciphertext.is_empty() || ciphertext.len() > CHUNK_SIZE + 16 {
            return Err(MsgError::TooLarge(format!(
                "chunk ciphertext is {} bytes",
                ciphertext.len()
            )));
        }
        let hash = *blake3::hash(&ciphertext).as_bytes();
        let owner = identity.fingerprint_hex();
        let signature = identity.sign_detached(&chunk_message(&owner, file_id, index, &hash))?;
        Ok(Self {
            file_id: ByteArray::new(*file_id),
            index,
            hash: ByteArray::new(hash),
            nonce: ByteArray::new(*nonce),
            ciphertext: ByteBuf::from(ciphertext),
            owner,
            signature: ByteBuf::from(signature),
        })
    }

    /// Validate sizes and the embedded hash.
    pub fn validate(&self) -> Result<()> {
        if self.index as usize >= MAX_FILE_CHUNKS {
            return Err(MsgError::TooLarge("chunk index out of range".to_string()));
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > CHUNK_SIZE + 16 {
            return Err(MsgError::TooLarge("chunk ciphertext size".to_string()));
        }
        if blake3::hash(&self.ciphertext).as_bytes() != &self.hash.into_array() {
            return Err(MsgError::Verification("chunk hash mismatch".to_string()));
        }
        Ok(())
    }

    /// Verify the owner signature and the embedded hash.
    pub fn verify(&self, owner_cert: &Cert) -> Result<()> {
        self.validate()?;
        let fingerprint = owner_cert.fingerprint().to_hex().to_uppercase();
        if fingerprint != self.owner {
            return Err(MsgError::Verification(
                "chunk owner does not match the certificate".to_string(),
            ));
        }
        verify_detached(
            owner_cert,
            &chunk_message(&self.owner, &self.file_id, self.index, &self.hash),
            &self.signature,
        )?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    file_id: ByteArray<32>,
    owner: String,
    name: String,
    size: u64,
    chunk_size: u32,
    chunks: Vec<ByteArray<32>>,
    key: ByteArray<32>,
    created: u64,
}

/// A signed file manifest.
///
/// Contains the file key, so it must only be transported end-to-end
/// encrypted and stored with owner-only permissions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileManifest {
    /// File id (content-independent, derived from owner, name and key).
    pub file_id: ByteArray<32>,
    /// Owner fingerprint (uppercase hex).
    pub owner: String,
    /// File name.
    pub name: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Plaintext chunk size.
    pub chunk_size: u32,
    /// Ordered chunk hashes.
    pub chunks: Vec<ByteArray<32>>,
    /// Per-file encryption key.
    pub key: ByteArray<32>,
    /// Creation time, Unix seconds.
    pub created: u64,
    /// Detached OpenPGP signature over the canonical body.
    pub signature: ByteBuf,
}

impl fmt::Debug for FileManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileManifest")
            .field("file_id", &self.file_id)
            .field("owner", &self.owner)
            .field("name", &self.name)
            .field("size", &self.size)
            .field("chunk_size", &self.chunk_size)
            .field("chunks", &self.chunks.len())
            .field("key", &"<redacted>")
            .field("created", &self.created)
            .finish()
    }
}

impl FileManifest {
    /// Build and sign a manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        identity: &Identity,
        file_id: &[u8; 32],
        name: &str,
        size: u64,
        chunk_size: u32,
        chunks: Vec<[u8; 32]>,
        key: &[u8; 32],
        created: u64,
    ) -> Result<Self> {
        let owner = identity.fingerprint_hex();
        let body = ManifestBody {
            file_id: ByteArray::new(*file_id),
            owner: owner.clone(),
            name: name.to_string(),
            size,
            chunk_size,
            chunks: chunks.into_iter().map(ByteArray::new).collect(),
            key: ByteArray::new(*key),
            created,
        };
        let body_bytes = manifest_body_bytes(&body)?;
        let signature = identity.sign_detached(&body_bytes)?;
        let manifest = Self {
            file_id: ByteArray::new(*file_id),
            owner,
            name: name.to_string(),
            size,
            chunk_size,
            chunks: body.chunks,
            key: ByteArray::new(*key),
            created,
            signature: ByteBuf::from(signature),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Recompute the signed body.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        manifest_body_bytes(&ManifestBody {
            file_id: self.file_id,
            owner: self.owner.clone(),
            name: self.name.clone(),
            size: self.size,
            chunk_size: self.chunk_size,
            chunks: self.chunks.clone(),
            key: self.key,
            created: self.created,
        })
    }

    /// Validate sizes and chunk bookkeeping.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > MAX_FILE_NAME_BYTES {
            return Err(MsgError::TooLarge("invalid file name".to_string()));
        }
        if self.size > MAX_FILE_SIZE {
            return Err(MsgError::TooLarge(format!(
                "file size {} exceeds limit",
                self.size
            )));
        }
        if self.chunk_size == 0 || self.chunk_size as usize > CHUNK_SIZE {
            return Err(MsgError::TooLarge("invalid chunk size".to_string()));
        }
        if self.chunks.len() > MAX_FILE_CHUNKS {
            return Err(MsgError::TooLarge("too many chunks".to_string()));
        }
        let expected = self.size.div_ceil(self.chunk_size as u64) as usize;
        if self.chunks.len() != expected {
            return Err(MsgError::Encoding(format!(
                "manifest lists {} chunks but size implies {expected}",
                self.chunks.len()
            )));
        }
        Ok(())
    }

    /// Verify the owner signature.
    pub fn verify(&self, owner_cert: &Cert) -> Result<()> {
        self.validate()?;
        let fingerprint = owner_cert.fingerprint().to_hex().to_uppercase();
        if fingerprint != self.owner {
            return Err(MsgError::Verification(
                "manifest owner does not match the certificate".to_string(),
            ));
        }
        verify_detached(owner_cert, &self.body_bytes()?, &self.signature)?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }

    /// Hash expected at `index`.
    pub fn chunk_hash(&self, index: u32) -> Option<[u8; 32]> {
        self.chunks
            .get(index as usize)
            .map(|hash| hash.into_array())
    }
}

/// A request for one chunk, forwarded toward the DHT-closest nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRequest {
    /// Manifest id.
    pub file_id: ByteArray<32>,
    /// Chunk index.
    pub index: u32,
    /// Expected chunk hash.
    pub hash: ByteArray<32>,
    /// Fingerprint of the node that originated the request.
    pub requester: String,
    /// Remaining forwarding hops.
    pub ttl: u8,
}

impl ChunkRequest {
    /// Create a request with the default TTL.
    pub fn new(file_id: &[u8; 32], index: u32, hash: &[u8; 32], requester: &str) -> Self {
        Self {
            file_id: ByteArray::new(*file_id),
            index,
            hash: ByteArray::new(*hash),
            requester: requester.to_string(),
            ttl: MAX_REQUEST_TTL,
        }
    }

    /// Validate the TTL and index.
    pub fn validate(&self) -> Result<()> {
        if self.ttl > MAX_REQUEST_TTL {
            return Err(MsgError::TooLarge(
                "chunk request TTL out of range".to_string(),
            ));
        }
        if self.index as usize >= MAX_FILE_CHUNKS {
            return Err(MsgError::TooLarge("chunk index out of range".to_string()));
        }
        Ok(())
    }

    /// One hop closer, if hops remain.
    pub fn forwarded(&self) -> Option<Self> {
        if self.ttl == 0 {
            return None;
        }
        let mut request = self.clone();
        request.ttl -= 1;
        Some(request)
    }
}

fn manifest_body_bytes(body: &ManifestBody) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(body, &mut encoded)
        .map_err(|e| MsgError::Encoding(format!("cbor encode failed: {e}")))?;
    let mut message = Vec::with_capacity(FILE_DOMAIN.len() + encoded.len());
    message.extend_from_slice(FILE_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_identity::keys::cert_from_bytes;

    fn identity(uid: &str) -> Identity {
        Identity::generate(uid, &format!("dest-{uid}")).expect("identity")
    }

    fn cert(identity: &Identity) -> Cert {
        cert_from_bytes(&identity.public_cert_bytes().unwrap()).unwrap()
    }

    #[test]
    fn chunk_roundtrip_and_tamper() {
        let alice = identity("alice");
        let file_id = [1u8; 32];
        let nonce = [2u8; 12];
        let chunk = FileChunk::create(&alice, &file_id, 0, &nonce, vec![9u8; 100]).expect("chunk");
        chunk.verify(&cert(&alice)).expect("verify");

        let mut tampered = chunk.clone();
        tampered.ciphertext = ByteBuf::from(vec![8u8; 100]);
        assert!(tampered.verify(&cert(&alice)).is_err());

        let mallory = identity("mallory");
        assert!(chunk.verify(&cert(&mallory)).is_err());
    }

    #[test]
    fn manifest_roundtrip_and_limits() {
        let alice = identity("alice");
        let file_id = [3u8; 32];
        let key = [4u8; 32];
        let manifest = FileManifest::create(
            &alice,
            &file_id,
            "hello.txt",
            10,
            CHUNK_SIZE as u32,
            vec![[5u8; 32]],
            &key,
            1000,
        )
        .expect("manifest");
        manifest.verify(&cert(&alice)).expect("verify");
        assert_eq!(manifest.chunk_hash(0), Some([5u8; 32]));
        assert_eq!(manifest.chunk_hash(1), None);

        // Inconsistent chunk count is rejected.
        assert!(
            FileManifest::create(
                &alice,
                &file_id,
                "bad.txt",
                10,
                CHUNK_SIZE as u32,
                vec![[5u8; 32], [6u8; 32]],
                &key,
                1000,
            )
            .is_err()
        );
        // Oversized file is rejected.
        assert!(
            FileManifest::create(
                &alice,
                &file_id,
                "big",
                MAX_FILE_SIZE + 1,
                CHUNK_SIZE as u32,
                vec![],
                &key,
                1000,
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_debug_redacts_key() {
        let alice = identity("alice");
        let key = [0xabu8; 32];
        let manifest =
            FileManifest::create(&alice, &[7u8; 32], "f", 1, 1, vec![[8u8; 32]], &key, 1)
                .expect("manifest");
        let debug = format!("{manifest:?}");
        assert!(debug.contains("redacted"));
        let key_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!debug.contains(&key_hex));
    }

    #[test]
    fn chunk_request_forwarding() {
        let request = ChunkRequest::new(&[1u8; 32], 0, &[2u8; 32], "OWNER");
        assert_eq!(request.ttl, MAX_REQUEST_TTL);
        let mut current = request;
        for expected in (0..MAX_REQUEST_TTL).rev() {
            current = current.forwarded().expect("forward");
            assert_eq!(current.ttl, expected);
        }
        assert!(current.forwarded().is_none());
    }
}
