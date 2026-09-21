//! Gossip: verified peer descriptors and trust vouches.
//!
//! Gossip lists are exchanged with direct peers after a session is
//! established. Every descriptor carries its own OpenPGP signature and every
//! vouch is signed by its signer, so relays cannot forge third-party data.

use crate::error::{MsgError, Result};
use fantuan_identity::TrustVouch;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Maximum announcements accepted in one gossip object.
pub const MAX_ANNOUNCEMENTS: usize = 64;
/// Maximum vouches accepted in one gossip object.
pub const MAX_VOUCHES: usize = 256;

/// One peer descriptor with its detached self-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    /// Canonical descriptor CBOR.
    pub descriptor: ByteBuf,
    /// Detached OpenPGP signature over the descriptor.
    pub signature: ByteBuf,
}

impl Announcement {
    /// Build an announcement from descriptor bytes and signature.
    pub fn new(descriptor: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            descriptor: ByteBuf::from(descriptor),
            signature: ByteBuf::from(signature),
        }
    }
}

/// Descriptor and trust-vouch exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gossip {
    /// Known peer descriptors.
    pub announcements: Vec<Announcement>,
    /// Signed trust vouches.
    pub vouches: Vec<TrustVouch>,
}

impl Gossip {
    /// Create an empty gossip list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an announcement.
    pub fn push_announcement(&mut self, descriptor: Vec<u8>, signature: Vec<u8>) {
        self.announcements
            .push(Announcement::new(descriptor, signature));
    }

    /// Append a vouch.
    pub fn push_vouch(&mut self, vouch: TrustVouch) {
        self.vouches.push(vouch);
    }

    /// True when there is nothing to send.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty() && self.vouches.is_empty()
    }

    /// Enforce the per-object limits.
    pub fn validate_limits(&self) -> Result<()> {
        if self.announcements.len() > MAX_ANNOUNCEMENTS {
            return Err(MsgError::TooLarge(format!(
                "gossip has {} announcements (limit {MAX_ANNOUNCEMENTS})",
                self.announcements.len()
            )));
        }
        if self.vouches.len() > MAX_VOUCHES {
            return Err(MsgError::TooLarge(format!(
                "gossip has {} vouches (limit {MAX_VOUCHES})",
                self.vouches.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_gossip() {
        let gossip = Gossip::new();
        assert!(gossip.is_empty());
        assert!(gossip.validate_limits().is_ok());
    }

    #[test]
    fn limits_are_enforced() {
        let mut gossip = Gossip::new();
        for _ in 0..=MAX_ANNOUNCEMENTS {
            gossip.push_announcement(vec![1], vec![2]);
        }
        assert!(gossip.validate_limits().is_err());
    }
}
