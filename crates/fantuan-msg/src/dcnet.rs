//! DC-Net round wire objects.
//!
//! Rounds run as a mesh: the initiator broadcasts a start, every participant
//! (including the initiator, last) broadcasts one XOR share to all other
//! participants, and every node XORs all shares to extract the anonymous
//! message. See `docs/PROTOCOL.md` section 11.

use crate::error::{MsgError, Result};
use crate::post::valid_topic;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Domain separator for share signatures.
pub const DCNET_SHARE_DOMAIN: &[u8] = b"fantuan-dcnet-share-v1";
/// Maximum number of participants in one round.
pub const DCNET_MAX_PARTICIPANTS: usize = 16;
/// Default payload length (message capacity is `payload_len - 36`).
pub const DCNET_PAYLOAD_LEN: usize = 1024;
/// Maximum payload length accepted.
pub const DCNET_MAX_PAYLOAD_LEN: usize = 4096;
/// Maximum round deadline in seconds.
pub const DCNET_MAX_DEADLINE_SECS: u64 = 30;

/// Exact bytes covered by a share signature.
pub fn share_message(channel: &str, round_id: u64, share: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DCNET_SHARE_DOMAIN.len() + channel.len() + share.len() + 16);
    message.extend_from_slice(DCNET_SHARE_DOMAIN);
    message.extend_from_slice(&(channel.len() as u32).to_be_bytes());
    message.extend_from_slice(channel.as_bytes());
    message.extend_from_slice(&round_id.to_be_bytes());
    message.extend_from_slice(share);
    message
}

/// A round announcement broadcast by the initiator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcRoundStart {
    /// Channel label used to separate round streams.
    pub channel: String,
    /// Monotonic round id chosen by the initiator.
    pub round_id: u64,
    /// Initiator fingerprint (uppercase hex).
    pub initiator: String,
    /// Participant fingerprints, including the initiator.
    pub participants: Vec<String>,
    /// Round deadline in seconds.
    pub deadline_secs: u64,
    /// Length every share must have.
    pub payload_len: u32,
}

impl DcRoundStart {
    /// Build a start message.
    pub fn new(
        channel: &str,
        round_id: u64,
        initiator: &str,
        participants: &[String],
        deadline_secs: u64,
        payload_len: usize,
    ) -> Result<Self> {
        let start = Self {
            channel: channel.to_string(),
            round_id,
            initiator: initiator.to_string(),
            participants: participants.to_vec(),
            deadline_secs,
            payload_len: payload_len as u32,
        };
        start.validate()?;
        Ok(start)
    }

    /// Validate sizes, participant count and membership.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.channel) {
            return Err(MsgError::Encoding("invalid round channel".to_string()));
        }
        if self.participants.len() < 2 || self.participants.len() > DCNET_MAX_PARTICIPANTS {
            return Err(MsgError::TooLarge(format!(
                "round has {} participants (2..={DCNET_MAX_PARTICIPANTS})",
                self.participants.len()
            )));
        }
        if !self.participants.contains(&self.initiator) {
            return Err(MsgError::Encoding(
                "initiator is not a participant".to_string(),
            ));
        }
        if self.deadline_secs == 0 || self.deadline_secs > DCNET_MAX_DEADLINE_SECS {
            return Err(MsgError::TooLarge(
                "round deadline out of range".to_string(),
            ));
        }
        let payload_len = self.payload_len as usize;
        if !(36..=DCNET_MAX_PAYLOAD_LEN).contains(&payload_len) {
            return Err(MsgError::TooLarge(
                "round payload length out of range".to_string(),
            ));
        }
        let mut seen = self.participants.clone();
        seen.sort();
        seen.dedup();
        if seen.len() != self.participants.len() {
            return Err(MsgError::Encoding(
                "duplicate round participants".to_string(),
            ));
        }
        Ok(())
    }
}

/// One participant's XOR share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcRoundShare {
    /// Channel label.
    pub channel: String,
    /// Round id.
    pub round_id: u64,
    /// Sender fingerprint (uppercase hex).
    pub peer_uid: String,
    /// XOR share bytes.
    pub xored_payload: ByteBuf,
    /// Detached OpenPGP signature over [`share_message`].
    pub signature: ByteBuf,
}

impl DcRoundShare {
    /// Build a share object.
    pub fn new(
        channel: &str,
        round_id: u64,
        peer_uid: &str,
        xored_payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            channel: channel.to_string(),
            round_id,
            peer_uid: peer_uid.to_string(),
            xored_payload: ByteBuf::from(xored_payload),
            signature: ByteBuf::from(signature),
        }
    }

    /// Validate sizes and the channel name.
    pub fn validate(&self) -> Result<()> {
        if !valid_topic(&self.channel) {
            return Err(MsgError::Encoding("invalid round channel".to_string()));
        }
        if self.xored_payload.len() > DCNET_MAX_PAYLOAD_LEN {
            return Err(MsgError::TooLarge("round share too large".to_string()));
        }
        Ok(())
    }
}

/// Frame a message inside a fixed-length payload:
/// `[4-byte length][32-byte BLAKE3 checksum][message][zero pad]`.
pub fn pad_message(message: &[u8], payload_len: usize) -> Option<Vec<u8>> {
    let frame_len = 36 + message.len();
    if payload_len < frame_len {
        return None;
    }
    let mut padded = vec![0u8; payload_len];
    padded[..4].copy_from_slice(&(message.len() as u32).to_be_bytes());
    padded[4..36].copy_from_slice(blake3::hash(message).as_bytes());
    padded[36..36 + message.len()].copy_from_slice(message);
    Some(padded)
}

/// Extract a message from a padded payload, verifying the checksum.
pub fn unpad_message(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 36 {
        return None;
    }
    let len = u32::from_be_bytes(padded[..4].try_into().ok()?) as usize;
    if len > padded.len() - 36 {
        return None;
    }
    let message = &padded[36..36 + len];
    if blake3::hash(message).as_bytes() != &padded[4..36] {
        return None;
    }
    Some(message.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_start_validation() {
        let participants = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        assert!(DcRoundStart::new("#g", 1, "A", &participants, 10, 256).is_ok());
        // Initiator must participate.
        assert!(DcRoundStart::new("#g", 1, "D", &participants, 10, 256).is_err());
        // Too few participants.
        assert!(DcRoundStart::new("#g", 1, "A", &["A".to_string()], 10, 256).is_err());
        // Duplicates.
        let dup = vec!["A".to_string(), "A".to_string()];
        assert!(DcRoundStart::new("#g", 1, "A", &dup, 10, 256).is_err());
        // Bad payload length.
        assert!(DcRoundStart::new("#g", 1, "A", &participants, 10, 8).is_err());
    }

    #[test]
    fn share_message_binds_round_and_channel() {
        let first = share_message("#g", 1, b"share");
        assert_eq!(first, share_message("#g", 1, b"share"));
        assert_ne!(first, share_message("#g", 2, b"share"));
        assert_ne!(first, share_message("#other", 1, b"share"));
    }

    #[test]
    fn pad_unpad_roundtrip_and_corruption() {
        let padded = pad_message(b"hello dc-net", 128).expect("fit");
        assert_eq!(padded.len(), 128);
        assert_eq!(
            unpad_message(&padded).as_deref(),
            Some(&b"hello dc-net"[..])
        );

        let mut corrupted = padded.clone();
        corrupted[40] ^= 0xff;
        assert!(unpad_message(&corrupted).is_none());

        assert!(pad_message(&[0u8; 200], 64).is_none());
        assert!(unpad_message(&[0u8; 10]).is_none());
    }

    #[test]
    fn trailing_zeros_are_preserved() {
        let message = [1u8, 2, 0, 0, 0];
        let padded = pad_message(&message, 64).expect("fit");
        assert_eq!(unpad_message(&padded).unwrap(), message);
    }
}
