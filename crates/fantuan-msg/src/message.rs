//! Signed application messages.
//!
//! Wire shape (see `docs/PROTOCOL.md` section 5):
//!
//! ```text
//! body = "fantuan-message-v1" || canonical CBOR of (sender, timestamp, payload)
//! id   = BLAKE3(body)
//! signature = OpenPGP detached signature over body
//! ```

use crate::error::{MsgError, Result};
use fantuan_core::time;
use fantuan_identity::Identity;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

/// Domain separator for message bodies.
pub const MESSAGE_DOMAIN: &[u8] = b"fantuan-message-v1";

/// Maximum payload size accepted (32 KiB).
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024;

/// Canonical body of a message: everything the signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageBody {
    sender: String,
    timestamp: u64,
    payload: ByteBuf,
}

impl MessageBody {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded)
            .map_err(|e| MsgError::Encoding(format!("cbor encode failed: {e}")))?;
        let mut out = Vec::with_capacity(MESSAGE_DOMAIN.len() + encoded.len());
        out.extend_from_slice(MESSAGE_DOMAIN);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}

/// A signed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// BLAKE3 digest of the signed body; serialized as a CBOR byte string.
    pub id: ByteArray<32>,
    /// Sender OpenPGP fingerprint (uppercase hex).
    pub sender: String,
    /// Creation time, Unix seconds.
    pub timestamp: u64,
    /// Application payload.
    pub payload: ByteBuf,
    /// Detached OpenPGP signature over the body.
    pub signature: ByteBuf,
}

impl Message {
    /// Build and sign a new message with the node identity.
    pub fn create(identity: &Identity, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(MsgError::TooLarge(format!(
                "payload is {} bytes (limit {MAX_PAYLOAD_BYTES})",
                payload.len()
            )));
        }
        let sender = identity.fingerprint_hex();
        let timestamp = time::now_unix();
        let body = MessageBody {
            sender: sender.clone(),
            timestamp,
            payload: ByteBuf::from(payload.to_vec()),
        };
        let body_bytes = body.canonical_bytes()?;
        let signature = identity.sign_detached(&body_bytes)?;
        let id = *blake3::hash(&body_bytes).as_bytes();

        Ok(Self {
            id: ByteArray::new(id),
            sender,
            timestamp,
            payload: ByteBuf::from(payload.to_vec()),
            signature: ByteBuf::from(signature),
        })
    }

    /// Recompute the signed body from the message fields.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        MessageBody {
            sender: self.sender.clone(),
            timestamp: self.timestamp,
            payload: self.payload.clone(),
        }
        .canonical_bytes()
    }

    /// Verify id, size limits and the OpenPGP signature against `cert`.
    pub fn verify(&self, cert: &Cert) -> Result<()> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(MsgError::TooLarge(format!(
                "payload is {} bytes (limit {MAX_PAYLOAD_BYTES})",
                self.payload.len()
            )));
        }
        let body = self.body_bytes()?;
        let expected_id = blake3::hash(&body);
        if expected_id.as_bytes() != &self.id.into_array() {
            return Err(MsgError::Verification(
                "message id does not match the signed body".to_string(),
            ));
        }
        fantuan_identity::keys::verify_detached(cert, &body, &self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_identity::keys::cert_from_bytes;

    fn identity() -> Identity {
        Identity::generate("alice", "dest-alice").expect("identity")
    }

    fn cert_of(identity: &Identity) -> Cert {
        cert_from_bytes(&identity.public_cert_bytes().unwrap()).unwrap()
    }

    #[test]
    fn create_verify_roundtrip() {
        let identity = identity();
        let message = Message::create(&identity, b"hello world").expect("create");
        message.verify(&cert_of(&identity)).expect("verify");
    }

    #[test]
    fn empty_payload_is_allowed() {
        let identity = identity();
        let message = Message::create(&identity, b"").expect("create");
        message.verify(&cert_of(&identity)).expect("verify");
    }

    #[test]
    fn tampered_payload_fails() {
        let identity = identity();
        let mut message = Message::create(&identity, b"original").expect("create");
        message.payload = ByteBuf::from(b"tampered".to_vec());
        assert!(message.verify(&cert_of(&identity)).is_err());
    }

    #[test]
    fn tampered_id_fails() {
        let identity = identity();
        let mut message = Message::create(&identity, b"original").expect("create");
        message.id = ByteArray::new([0u8; 32]);
        assert!(message.verify(&cert_of(&identity)).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let identity = identity();
        let mut message = Message::create(&identity, b"original").expect("create");
        let mut sig = message.signature.to_vec();
        sig[3] ^= 0xff;
        message.signature = ByteBuf::from(sig);
        assert!(message.verify(&cert_of(&identity)).is_err());
    }

    #[test]
    fn wrong_certificate_fails() {
        let alice = identity();
        let mallory = Identity::generate("mallory", "dest-mallory").expect("identity");
        let message = Message::create(&alice, b"hi").expect("create");
        assert!(message.verify(&cert_of(&mallory)).is_err());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let identity = identity();
        let payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert!(Message::create(&identity, &payload).is_err());
    }
}
