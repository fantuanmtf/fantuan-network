//! Social objects: channel messages, forum posts, history sync and deletes.
//!
//! All content-bearing objects follow the same pattern as [`crate::Message`]:
//! a canonical CBOR body, a BLAKE3 id and a detached OpenPGP signature. The
//! body domain separators differ per object type.

use crate::error::{MsgError, Result};
use fantuan_core::time;
use fantuan_identity::Identity;
use fantuan_identity::keys::{cert_from_bytes, verify_detached};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

/// Domain separator for channel message bodies.
pub const CHANNEL_DOMAIN: &[u8] = b"fantuan-channel-v1";
/// Domain separator for forum post bodies.
pub const FORUM_DOMAIN: &[u8] = b"fantuan-forum-v1";
/// Domain separator for delete requests.
pub const DELETE_DOMAIN: &[u8] = b"fantuan-delete-v1";

/// Maximum channel text size.
pub const MAX_CHANNEL_TEXT_BYTES: usize = 8 * 1024;
/// Maximum forum title size.
pub const MAX_FORUM_TITLE_BYTES: usize = 256;
/// Maximum forum body size.
pub const MAX_FORUM_BODY_BYTES: usize = 32 * 1024;
/// Maximum topic (channel/board) name size.
pub const MAX_TOPIC_BYTES: usize = 64;
/// Maximum channel messages in one history response.
pub const MAX_HISTORY_MESSAGES: usize = 200;
/// Maximum forum posts in one history response.
pub const MAX_HISTORY_POSTS: usize = 100;

/// Topic names allow ASCII alphanumerics and `#-_. /`.
pub fn valid_topic(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOPIC_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'#' | b'-' | b'_' | b'.' | b'/'))
}

fn signed_body(domain: &[u8], encoded: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(domain.len() + encoded.len());
    body.extend_from_slice(domain);
    body.extend_from_slice(encoded);
    body
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelBody {
    sender: String,
    channel: String,
    timestamp: u64,
    text: ByteBuf,
}

/// A signed message posted to a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelMessage {
    /// BLAKE3 digest of the signed body.
    pub id: ByteArray<32>,
    /// Sender fingerprint (uppercase hex).
    pub sender: String,
    /// Channel name.
    pub channel: String,
    /// Creation time, Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub text: ByteBuf,
    /// Detached OpenPGP signature.
    pub signature: ByteBuf,
}

impl ChannelMessage {
    /// Build and sign a channel message.
    pub fn create(identity: &Identity, channel: &str, text: &str) -> Result<Self> {
        if !valid_topic(channel) {
            return Err(MsgError::Encoding(format!("invalid channel {channel:?}")));
        }
        if text.len() > MAX_CHANNEL_TEXT_BYTES {
            return Err(MsgError::TooLarge(format!(
                "channel text is {} bytes (limit {MAX_CHANNEL_TEXT_BYTES})",
                text.len()
            )));
        }
        let sender = identity.fingerprint_hex();
        let timestamp = time::now_unix();
        let body = ChannelBody {
            sender: sender.clone(),
            channel: channel.to_string(),
            timestamp,
            text: ByteBuf::from(text.as_bytes().to_vec()),
        };
        let body_bytes = encode_body(CHANNEL_DOMAIN, &body)?;
        let signature = identity.sign_detached(&body_bytes)?;
        Ok(Self {
            id: ByteArray::new(*blake3::hash(&body_bytes).as_bytes()),
            sender,
            channel: channel.to_string(),
            timestamp,
            text: ByteBuf::from(text.as_bytes().to_vec()),
            signature: ByteBuf::from(signature),
        })
    }

    /// Recompute the signed body.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        encode_body(
            CHANNEL_DOMAIN,
            &ChannelBody {
                sender: self.sender.clone(),
                channel: self.channel.clone(),
                timestamp: self.timestamp,
                text: self.text.clone(),
            },
        )
    }

    /// Validate sizes and topic names.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.channel) {
            return Err(MsgError::Encoding("invalid channel".to_string()));
        }
        if self.text.len() > MAX_CHANNEL_TEXT_BYTES {
            return Err(MsgError::TooLarge("channel text too large".to_string()));
        }
        Ok(())
    }

    /// Verify id and signature against the sender certificate.
    pub fn verify(&self, cert: &Cert) -> Result<()> {
        self.validate()?;
        let body = self.body_bytes()?;
        if blake3::hash(&body).as_bytes() != &self.id.into_array() {
            return Err(MsgError::Verification("channel id mismatch".to_string()));
        }
        verify_detached(cert, &body, &self.signature)?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForumBody {
    sender: String,
    board: String,
    title: String,
    body: ByteBuf,
    timestamp: u64,
}

/// A signed forum post.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForumPost {
    /// BLAKE3 digest of the signed body.
    pub id: ByteArray<32>,
    /// Sender fingerprint (uppercase hex).
    pub sender: String,
    /// Board name.
    pub board: String,
    /// Post title.
    pub title: String,
    /// Post body.
    pub body: ByteBuf,
    /// Creation time, Unix seconds.
    pub timestamp: u64,
    /// Detached OpenPGP signature.
    pub signature: ByteBuf,
}

impl ForumPost {
    /// Build and sign a forum post.
    pub fn create(identity: &Identity, board: &str, title: &str, body: &str) -> Result<Self> {
        if !valid_topic(board) {
            return Err(MsgError::Encoding(format!("invalid board {board:?}")));
        }
        if title.is_empty() || title.len() > MAX_FORUM_TITLE_BYTES {
            return Err(MsgError::TooLarge(format!(
                "title must be 1..={MAX_FORUM_TITLE_BYTES} bytes"
            )));
        }
        if body.len() > MAX_FORUM_BODY_BYTES {
            return Err(MsgError::TooLarge(format!(
                "body is {} bytes (limit {MAX_FORUM_BODY_BYTES})",
                body.len()
            )));
        }
        let sender = identity.fingerprint_hex();
        let timestamp = time::now_unix();
        let signed = ForumBody {
            sender: sender.clone(),
            board: board.to_string(),
            title: title.to_string(),
            body: ByteBuf::from(body.as_bytes().to_vec()),
            timestamp,
        };
        let body_bytes = encode_body(FORUM_DOMAIN, &signed)?;
        let signature = identity.sign_detached(&body_bytes)?;
        Ok(Self {
            id: ByteArray::new(*blake3::hash(&body_bytes).as_bytes()),
            sender,
            board: board.to_string(),
            title: title.to_string(),
            body: ByteBuf::from(body.as_bytes().to_vec()),
            timestamp,
            signature: ByteBuf::from(signature),
        })
    }

    /// Recompute the signed body.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        encode_body(
            FORUM_DOMAIN,
            &ForumBody {
                sender: self.sender.clone(),
                board: self.board.clone(),
                title: self.title.clone(),
                body: self.body.clone(),
                timestamp: self.timestamp,
            },
        )
    }

    /// Validate sizes and board name.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.board) {
            return Err(MsgError::Encoding("invalid board".to_string()));
        }
        if self.title.is_empty() || self.title.len() > MAX_FORUM_TITLE_BYTES {
            return Err(MsgError::TooLarge("forum title too large".to_string()));
        }
        if self.body.len() > MAX_FORUM_BODY_BYTES {
            return Err(MsgError::TooLarge("forum body too large".to_string()));
        }
        Ok(())
    }

    /// Verify id and signature against the sender certificate.
    pub fn verify(&self, cert: &Cert) -> Result<()> {
        self.validate()?;
        let body = self.body_bytes()?;
        if blake3::hash(&body).as_bytes() != &self.id.into_array() {
            return Err(MsgError::Verification("forum id mismatch".to_string()));
        }
        verify_detached(cert, &body, &self.signature)?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }
}

/// Request messages this node is missing for a topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    /// Channel or board name.
    pub topic: String,
    /// True when the topic is a forum board.
    pub is_board: bool,
    /// Return messages strictly newer than this Unix time.
    pub since: u64,
}

impl HistoryRequest {
    /// Create a request.
    pub fn new(topic: &str, is_board: bool, since: u64) -> Self {
        Self {
            topic: topic.to_string(),
            is_board,
            since,
        }
    }

    /// Validate the topic name.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.topic) {
            return Err(MsgError::Encoding("invalid history topic".to_string()));
        }
        Ok(())
    }
}

/// History response carrying signed messages or posts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponse {
    /// Channel or board name.
    pub topic: String,
    /// True when the topic is a forum board.
    pub is_board: bool,
    /// Channel messages, when `is_board` is false.
    pub messages: Vec<ChannelMessage>,
    /// Forum posts, when `is_board` is true.
    pub posts: Vec<ForumPost>,
}

impl HistoryResponse {
    /// Create a response.
    pub fn new(
        topic: &str,
        is_board: bool,
        messages: Vec<ChannelMessage>,
        posts: Vec<ForumPost>,
    ) -> Self {
        Self {
            topic: topic.to_string(),
            is_board,
            messages,
            posts,
        }
    }

    /// Enforce response limits.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.topic) {
            return Err(MsgError::Encoding("invalid history topic".to_string()));
        }
        if self.messages.len() > MAX_HISTORY_MESSAGES {
            return Err(MsgError::TooLarge(format!(
                "history has {} messages (limit {MAX_HISTORY_MESSAGES})",
                self.messages.len()
            )));
        }
        if self.posts.len() > MAX_HISTORY_POSTS {
            return Err(MsgError::TooLarge(format!(
                "history has {} posts (limit {MAX_HISTORY_POSTS})",
                self.posts.len()
            )));
        }
        Ok(())
    }
}

/// A signed request to delete one of the sender's own objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRequest {
    /// Sender fingerprint (uppercase hex).
    pub sender: String,
    /// Object id to delete.
    pub target: ByteArray<32>,
    /// Creation time, Unix seconds.
    pub timestamp: u64,
    /// Detached OpenPGP signature.
    pub signature: ByteBuf,
}

impl DeleteRequest {
    /// Build and sign a delete request.
    pub fn create(identity: &Identity, target: &[u8; 32]) -> Result<Self> {
        let sender = identity.fingerprint_hex();
        let timestamp = time::now_unix();
        let message = delete_message(&sender, target, timestamp);
        let signature = identity.sign_detached(&message)?;
        Ok(Self {
            sender,
            target: ByteArray::new(*target),
            timestamp,
            signature: ByteBuf::from(signature),
        })
    }

    /// Verify the signature against the sender certificate.
    pub fn verify(&self, cert: &Cert) -> Result<()> {
        let message = delete_message(&self.sender, &self.target, self.timestamp);
        verify_detached(cert, &message, &self.signature)?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }
}

/// Exact bytes covered by a delete signature.
pub fn delete_message(sender: &str, target: &[u8; 32], timestamp: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(DELETE_DOMAIN.len() + sender.len() + 48);
    message.extend_from_slice(DELETE_DOMAIN);
    message.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    message.extend_from_slice(sender.as_bytes());
    message.extend_from_slice(target);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message
}

fn encode_body<T: Serialize>(domain: &[u8], body: &T) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(body, &mut encoded)
        .map_err(|e| MsgError::Encoding(format!("cbor encode failed: {e}")))?;
    Ok(signed_body(domain, &encoded))
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
    fn channel_message_roundtrip_and_tamper() {
        let alice = identity("alice");
        let message = ChannelMessage::create(&alice, "#general", "hello").expect("create");
        message.verify(&cert(&alice)).expect("verify");

        let mut tampered = message.clone();
        tampered.text = ByteBuf::from(b"evil".to_vec());
        assert!(tampered.verify(&cert(&alice)).is_err());

        let mut tampered = message.clone();
        tampered.channel = "#other".to_string();
        assert!(tampered.verify(&cert(&alice)).is_err());
    }

    #[test]
    fn channel_message_rejects_bad_input() {
        let alice = identity("alice");
        assert!(ChannelMessage::create(&alice, "", "hi").is_err());
        assert!(ChannelMessage::create(&alice, "#bad channel", "hi").is_err());
        let long = "x".repeat(MAX_CHANNEL_TEXT_BYTES + 1);
        assert!(ChannelMessage::create(&alice, "#general", &long).is_err());
    }

    #[test]
    fn wrong_sender_certificate_is_rejected() {
        let alice = identity("alice");
        let mallory = identity("mallory");
        let message = ChannelMessage::create(&alice, "#general", "hi").expect("create");
        assert!(message.verify(&cert(&mallory)).is_err());
    }

    #[test]
    fn forum_post_roundtrip_and_limits() {
        let bob = identity("bob");
        let post = ForumPost::create(&bob, "bbs", "Welcome", "Hello everyone").expect("create");
        post.verify(&cert(&bob)).expect("verify");

        assert!(ForumPost::create(&bob, "bbs", "", "body").is_err());
        let long_body = "x".repeat(MAX_FORUM_BODY_BYTES + 1);
        assert!(ForumPost::create(&bob, "bbs", "t", &long_body).is_err());
        let long_title = "t".repeat(MAX_FORUM_TITLE_BYTES + 1);
        assert!(ForumPost::create(&bob, "bbs", &long_title, "body").is_err());
    }

    #[test]
    fn history_limits_are_enforced() {
        let alice = identity("alice");
        let messages: Vec<ChannelMessage> = (0..=MAX_HISTORY_MESSAGES)
            .map(|i| ChannelMessage::create(&alice, "#g", &format!("m{i}")).unwrap())
            .collect();
        let response = HistoryResponse::new("#g", false, messages, vec![]);
        assert!(response.validate().is_err());
        let ok = HistoryResponse::new("#g", false, vec![], vec![]);
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn delete_request_verify_and_tamper() {
        let alice = identity("alice");
        let target = [7u8; 32];
        let delete = DeleteRequest::create(&alice, &target).expect("delete");
        delete.verify(&cert(&alice)).expect("verify");

        let mut tampered = delete.clone();
        tampered.target = ByteArray::new([8u8; 32]);
        assert!(tampered.verify(&cert(&alice)).is_err());

        let mallory = identity("mallory");
        assert!(delete.verify(&cert(&mallory)).is_err());
    }
}
