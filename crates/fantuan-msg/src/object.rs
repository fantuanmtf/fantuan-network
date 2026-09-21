//! Application object envelope.
//!
//! Objects are externally tagged CBOR values: a single-key map whose key is
//! the object tag (`message`, `ping`, `pong`, ...). Decoding enforces both a
//! size limit and canonical re-encoding, so unknown fields, duplicate keys
//! and trailing bytes are rejected.

use crate::error::{MsgError, Result};
use crate::message::Message;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

/// Maximum encoded object size (64 KiB), matching the session frame limit.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024;

/// An application object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Object {
    /// A signed chat message.
    Message(Message),
    /// Keepalive probe.
    Ping {
        /// Monotonic counter.
        nonce: u64,
        /// Sender clock, Unix seconds.
        timestamp: u64,
    },
    /// Keepalive reply.
    Pong {
        /// Echo of the ping timestamp.
        timestamp: u64,
    },
}

impl Object {
    /// Encode the object in canonical form.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded)
            .map_err(|e| MsgError::Encoding(format!("cbor encode failed: {e}")))?;
        if encoded.len() > MAX_OBJECT_BYTES {
            return Err(MsgError::TooLarge(format!(
                "object is {} bytes (limit {MAX_OBJECT_BYTES})",
                encoded.len()
            )));
        }
        Ok(encoded)
    }

    /// Decode an object, rejecting non-canonical or oversized encodings.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(MsgError::TooLarge(format!(
                "object is {} bytes (limit {MAX_OBJECT_BYTES})",
                bytes.len()
            )));
        }
        let object: Object = ciborium::from_reader(bytes)
            .map_err(|e| MsgError::Encoding(format!("cbor decode failed: {e}")))?;

        // Canonical check: the parsed object must re-encode to the exact
        // input. This rejects unknown fields, duplicate keys and trailing
        // data that a lenient decoder would silently drop.
        let reencoded = object.to_canonical_bytes()?;
        if reencoded != bytes {
            return Err(MsgError::Encoding("object is not canonical".to_string()));
        }
        Ok(object)
    }

    /// Verify the object's cryptographic material.
    pub fn verify(&self, cert: &Cert) -> Result<()> {
        match self {
            Object::Message(message) => message.verify(cert),
            Object::Ping { .. } | Object::Pong { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_identity::Identity;
    use fantuan_identity::keys::cert_from_bytes;

    fn message_object() -> (Identity, Object) {
        let identity = Identity::generate("bob", "dest-bob").expect("identity");
        let message = Message::create(&identity, b"payload").expect("message");
        (identity, Object::Message(message))
    }

    #[test]
    fn roundtrip_message() {
        let (_identity, object) = message_object();
        let bytes = object.to_canonical_bytes().expect("encode");
        let parsed = Object::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(parsed, object);
    }

    #[test]
    fn roundtrip_ping_pong() {
        for object in [
            Object::Ping {
                nonce: 7,
                timestamp: 1000,
            },
            Object::Pong { timestamp: 1000 },
        ] {
            let bytes = object.to_canonical_bytes().expect("encode");
            let parsed = Object::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(parsed, object);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let (_identity, object) = message_object();
        let mut bytes = object.to_canonical_bytes().expect("encode");
        bytes.push(0);
        assert!(Object::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_tag_is_rejected() {
        // {"forum_post": {}} — a known planned tag with no implementation
        // must not decode into an empty object.
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("forum_post".to_string()),
            ciborium::Value::Map(vec![]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).expect("encode");
        assert!(Object::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn oversized_object_is_rejected_on_decode() {
        let bytes = vec![0u8; MAX_OBJECT_BYTES + 1];
        assert!(Object::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn verify_message_object() {
        let (identity, object) = message_object();
        let cert = cert_from_bytes(&identity.public_cert_bytes().unwrap()).unwrap();
        object.verify(&cert).expect("verify");

        let mut tampered = object.clone();
        if let Object::Message(message) = &mut tampered {
            message.payload = serde_bytes::ByteBuf::from(b"evil".to_vec());
        }
        assert!(tampered.verify(&cert).is_err());
    }
}
