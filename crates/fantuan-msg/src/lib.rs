//! Fantuan Network message layer.
//!
//! Canonical CBOR encoding of application objects, detached OpenPGP
//! signatures and strict size limits. See `docs/PROTOCOL.md` section 5.

pub mod error;
pub mod message;
pub mod object;

pub use error::{MsgError, Result};
pub use message::{MAX_PAYLOAD_BYTES, Message};
pub use object::{MAX_OBJECT_BYTES, Object};
