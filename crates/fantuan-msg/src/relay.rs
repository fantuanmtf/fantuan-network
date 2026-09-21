//! Relay envelopes.
//!
//! A relay envelope carries an end-to-end OpenPGP-encrypted payload toward a
//! destination fingerprint. Each hop decrypts nothing; it verifies the
//! originator's signature and forwards. Admission control (nonces, rate
//! limits, TOFU) lives in the node layer.

use crate::error::{MsgError, Result};
use fantuan_core::time;
use fantuan_identity::Identity;
use fantuan_identity::keys::{cert_from_bytes, verify_detached};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Domain separator for relay signatures.
pub const RELAY_DOMAIN: &[u8] = b"fantuan-relay-v1";

/// Maximum relay hops (loop bound).
pub const RELAY_MAX_HOPS: u8 = 8;

/// Accepted clock skew / freshness window in seconds.
pub const RELAY_MAX_AGE_SECS: u64 = 60;

/// Exact bytes covered by a relay signature.
///
/// `hops_left` is deliberately excluded so relays can decrement it without
/// invalidating the signature.
pub fn relay_message(
    origin: &str,
    to: &str,
    nonce: u64,
    timestamp: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(RELAY_DOMAIN.len() + origin.len() + to.len() + payload.len() + 32);
    message.extend_from_slice(RELAY_DOMAIN);
    for field in [origin, to] {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message.extend_from_slice(&nonce.to_be_bytes());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

/// A relayed, end-to-end encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// Originator fingerprint (uppercase hex).
    pub origin: String,
    /// Destination fingerprint (uppercase hex).
    pub to: String,
    /// Originator-monotonic nonce (anti-replay).
    pub nonce: u64,
    /// Creation time, Unix seconds (anti-expiry).
    pub timestamp: u64,
    /// Remaining hops; decremented by every relay.
    pub hops_left: u8,
    /// OpenPGP detached signature over the relay message.
    pub signature: ByteBuf,
    /// OpenPGP-encrypted inner object.
    pub payload: ByteBuf,
}

impl Relay {
    /// Create and sign a relay envelope with `hops_left = RELAY_MAX_HOPS`.
    pub fn create(identity: &Identity, to: &str, nonce: u64, payload: Vec<u8>) -> Result<Self> {
        Self::create_with_hops(
            identity,
            to,
            nonce,
            time::now_unix(),
            RELAY_MAX_HOPS,
            payload,
        )
    }

    /// Create a relay envelope with explicit timestamp and hop budget.
    pub fn create_with_hops(
        identity: &Identity,
        to: &str,
        nonce: u64,
        timestamp: u64,
        hops_left: u8,
        payload: Vec<u8>,
    ) -> Result<Self> {
        if hops_left > RELAY_MAX_HOPS {
            return Err(MsgError::Encoding(format!(
                "hops_left {hops_left} exceeds maximum {RELAY_MAX_HOPS}"
            )));
        }
        let origin = identity.fingerprint_hex();
        let message = relay_message(&origin, to, nonce, timestamp, &payload);
        let signature = identity.sign_detached(&message)?;
        Ok(Self {
            origin,
            to: to.to_string(),
            nonce,
            timestamp,
            hops_left,
            signature: ByteBuf::from(signature),
            payload: ByteBuf::from(payload),
        })
    }

    /// Verify origin fingerprint and signature against a certificate.
    pub fn verify(&self, origin_cert: &Cert) -> Result<()> {
        let fingerprint = origin_cert.fingerprint().to_hex().to_uppercase();
        if fingerprint != self.origin {
            return Err(MsgError::Verification(
                "relay origin does not match the certificate".to_string(),
            ));
        }
        let message = relay_message(
            &self.origin,
            &self.to,
            self.nonce,
            self.timestamp,
            &self.payload,
        );
        verify_detached(origin_cert, &message, &self.signature)?;
        Ok(())
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }

    /// True when the timestamp is outside the freshness window.
    pub fn is_expired(&self, now: u64, window_secs: u64) -> bool {
        now.abs_diff(self.timestamp) > window_secs
    }

    /// Forward one hop: every field except `hops_left` is unchanged.
    pub fn forwarded(&self) -> Result<Self> {
        if self.hops_left == 0 {
            return Err(MsgError::Encoding("relay has no hops left".to_string()));
        }
        let mut relay = self.clone();
        relay.hops_left -= 1;
        Ok(relay)
    }
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
    fn create_and_verify() {
        let alice = identity("alice");
        let relay = Relay::create(&alice, "B0B", 1, vec![1, 2, 3]).expect("relay");
        relay.verify(&cert(&alice)).expect("verify");
        assert_eq!(relay.hops_left, RELAY_MAX_HOPS);
    }

    #[test]
    fn tampering_is_rejected() {
        let alice = identity("alice");
        let mut relay = Relay::create(&alice, "B0B", 1, vec![1, 2, 3]).expect("relay");
        relay.payload = ByteBuf::from(vec![9, 9, 9]);
        assert!(relay.verify(&cert(&alice)).is_err());

        let mut relay = Relay::create(&alice, "B0B", 1, vec![1, 2, 3]).expect("relay");
        relay.to = "EVE".to_string();
        assert!(relay.verify(&cert(&alice)).is_err());
    }

    #[test]
    fn wrong_origin_certificate_is_rejected() {
        let alice = identity("alice");
        let mallory = identity("mallory");
        let relay = Relay::create(&alice, "B0B", 1, vec![1]).expect("relay");
        assert!(relay.verify(&cert(&mallory)).is_err());
    }

    #[test]
    fn hops_are_decremented_without_breaking_signature() {
        let alice = identity("alice");
        let relay = Relay::create(&alice, "B0B", 1, vec![1]).expect("relay");
        let forwarded = relay.forwarded().expect("forward");
        assert_eq!(forwarded.hops_left, relay.hops_left - 1);
        forwarded.verify(&cert(&alice)).expect("signature survives");
    }

    #[test]
    fn zero_hops_cannot_forward() {
        let alice = identity("alice");
        let mut relay = Relay::create(&alice, "B0B", 1, vec![1]).expect("relay");
        relay.hops_left = 0;
        assert!(relay.forwarded().is_err());
    }

    #[test]
    fn freshness_window() {
        let alice = identity("alice");
        let relay = Relay::create_with_hops(&alice, "B0B", 1, 1000, 8, vec![1]).expect("relay");
        assert!(!relay.is_expired(1030, RELAY_MAX_AGE_SECS));
        assert!(relay.is_expired(1100, RELAY_MAX_AGE_SECS));
    }

    #[test]
    fn excessive_hops_are_rejected() {
        let alice = identity("alice");
        assert!(
            Relay::create_with_hops(&alice, "B0B", 1, 1000, RELAY_MAX_HOPS + 1, vec![1]).is_err()
        );
    }
}
