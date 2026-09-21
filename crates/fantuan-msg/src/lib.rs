//! Fantuan Network message layer.
//!
//! Canonical CBOR encoding of application objects, detached OpenPGP
//! signatures and strict size limits. See `docs/PROTOCOL.md` section 5.

pub mod error;
pub mod gossip;
pub mod message;
pub mod object;
pub mod relay;

pub use error::{MsgError, Result};
pub use gossip::{Announcement, Gossip, MAX_ANNOUNCEMENTS, MAX_VOUCHES};
pub use message::{MAX_PAYLOAD_BYTES, Message};
pub use object::{MAX_OBJECT_BYTES, Object};
pub use relay::{RELAY_MAX_AGE_SECS, RELAY_MAX_HOPS, Relay};
