//! Fantuan Network message layer.
//!
//! Canonical CBOR encoding of application objects, detached OpenPGP
//! signatures and strict size limits. See `docs/PROTOCOL.md` section 5.

pub mod error;
pub mod file;
pub mod gossip;
pub mod message;
pub mod object;
pub mod post;
pub mod relay;

pub use error::{MsgError, Result};
pub use file::{
    CHUNK_DOMAIN, CHUNK_SIZE, ChunkRequest, FILE_DOMAIN, FileChunk, FileManifest, MAX_FILE_CHUNKS,
    MAX_FILE_NAME_BYTES, MAX_FILE_SIZE, MAX_REQUEST_TTL,
};
pub use gossip::{Announcement, Gossip, MAX_ANNOUNCEMENTS, MAX_VOUCHES};
pub use message::{MAX_PAYLOAD_BYTES, Message};
pub use object::{MAX_OBJECT_BYTES, Object};
pub use post::{
    ChannelMessage, DeleteRequest, ForumPost, HistoryRequest, HistoryResponse,
    MAX_CHANNEL_TEXT_BYTES, MAX_FORUM_BODY_BYTES, MAX_FORUM_TITLE_BYTES, MAX_HISTORY_MESSAGES,
    MAX_HISTORY_POSTS, MAX_TOPIC_BYTES, valid_topic,
};
pub use relay::{RELAY_MAX_AGE_SECS, RELAY_MAX_HOPS, Relay};
