//! Application object envelope.
//!
//! Objects are externally tagged CBOR values: a single-key map whose key is
//! the object tag (`message`, `ping`, `pong`, ...). Decoding enforces both a
//! size limit and canonical re-encoding, so unknown fields, duplicate keys
//! and trailing bytes are rejected.

use crate::dcnet::{DcRoundShare, DcRoundStart};
use crate::error::{MsgError, Result};
use crate::file::{ChunkRequest, FileChunk, FileManifest};
use crate::gossip::Gossip;
use crate::message::Message;
use crate::post::{ChannelMessage, DeleteRequest, ForumPost, HistoryRequest, HistoryResponse};
use crate::relay::Relay;
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
    /// Peer descriptors and trust vouches.
    Gossip(Gossip),
    /// End-to-end encrypted relay envelope.
    Relay(Relay),
    /// A signed channel message.
    ChannelMessage(ChannelMessage),
    /// A signed forum post.
    ForumPost(ForumPost),
    /// A request for missing topic history.
    HistoryRequest(HistoryRequest),
    /// A history response with signed messages or posts.
    HistoryResponse(HistoryResponse),
    /// A signed request to delete one of the sender's objects.
    DeleteRequest(DeleteRequest),
    /// One encrypted, content-addressed file chunk.
    FileChunk(FileChunk),
    /// A signed file manifest (end-to-end encrypted only; contains the key).
    FileManifest(FileManifest),
    /// A chunk request forwarded toward DHT-closest nodes.
    ChunkRequest(ChunkRequest),
    /// DC-Net round announcement.
    DcRoundStart(DcRoundStart),
    /// DC-Net XOR share.
    DcRoundShare(DcRoundShare),
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

        if let Object::Gossip(gossip) = &object {
            gossip.validate_limits()?;
        }
        match &object {
            Object::HistoryRequest(request) => request.validate()?,
            Object::HistoryResponse(response) => response.validate()?,
            Object::ChannelMessage(message) => message.validate()?,
            Object::ForumPost(post) => post.validate()?,
            Object::FileChunk(chunk) => chunk.validate()?,
            Object::FileManifest(manifest) => manifest.validate()?,
            Object::ChunkRequest(request) => request.validate()?,
            Object::DcRoundStart(start) => start.validate()?,
            Object::DcRoundShare(share) => share.validate()?,
            _ => {}
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post::MAX_HISTORY_MESSAGES;
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
        // {"file_chunk": {}} — a known planned tag with no implementation
        // must not decode into an empty object.
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("file_chunk".to_string()),
            ciborium::Value::Map(vec![]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).expect("encode");
        assert!(Object::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn roundtrip_social_objects() {
        let identity = Identity::generate("social", "dest").expect("identity");

        let channel = Object::ChannelMessage(
            crate::post::ChannelMessage::create(&identity, "#general", "hi").expect("channel"),
        );
        let forum = Object::ForumPost(
            crate::post::ForumPost::create(&identity, "bbs", "title", "body").expect("forum"),
        );
        let request =
            Object::HistoryRequest(crate::post::HistoryRequest::new("#general", false, 1));
        let response = Object::HistoryResponse(crate::post::HistoryResponse::new(
            "#general",
            false,
            vec![],
            vec![],
        ));
        let delete = Object::DeleteRequest(
            crate::post::DeleteRequest::create(&identity, &[3u8; 32]).expect("delete"),
        );

        for object in [channel, forum, request, response, delete] {
            let bytes = object.to_canonical_bytes().expect("encode");
            let parsed = Object::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(parsed, object);
        }
    }

    #[test]
    fn oversized_history_response_is_rejected_on_decode() {
        let identity = Identity::generate("history", "dest").expect("identity");
        let messages: Vec<crate::post::ChannelMessage> = (0..=MAX_HISTORY_MESSAGES)
            .map(|i| {
                crate::post::ChannelMessage::create(&identity, "#g", &format!("m{i}"))
                    .expect("message")
            })
            .collect();
        let response = Object::HistoryResponse(crate::post::HistoryResponse::new(
            "#g",
            false,
            messages,
            vec![],
        ));
        // Encode without the decode-time validation to simulate a malicious
        // peer sending an over-limit response.
        let mut bytes = Vec::new();
        ciborium::into_writer(&response, &mut bytes).expect("encode");
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
        match &object {
            Object::Message(message) => message.verify(&cert).expect("verify"),
            other => panic!("unexpected object: {other:?}"),
        }

        let mut tampered = object.clone();
        if let Object::Message(message) = &mut tampered {
            message.payload = serde_bytes::ByteBuf::from(b"evil".to_vec());
        }
        match &tampered {
            Object::Message(message) => assert!(message.verify(&cert).is_err()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn roundtrip_gossip() {
        let gossip = Gossip {
            announcements: vec![crate::gossip::Announcement::new(vec![1, 2, 3], vec![4, 5])],
            vouches: vec![],
        };
        let object = Object::Gossip(gossip);
        let bytes = object.to_canonical_bytes().expect("encode");
        let parsed = Object::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(parsed, object);
    }

    #[test]
    fn roundtrip_relay() {
        let identity = Identity::generate("relay-origin", "dest").expect("identity");
        let relay =
            crate::relay::Relay::create(&identity, "DEST", 1, vec![9, 8, 7]).expect("relay");
        let object = Object::Relay(relay);
        let bytes = object.to_canonical_bytes().expect("encode");
        let parsed = Object::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(parsed, object);
    }
}
