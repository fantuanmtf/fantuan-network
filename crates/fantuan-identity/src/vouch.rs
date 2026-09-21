//! Signed trust vouches.
//!
//! A vouch is an OpenPGP-signed statement "signer trusts subject at level L".
//! Vouches are the gossiped input to the trust graph; they are verified
//! before being stored in the [`crate::trust::TrustStore`].

use crate::error::{IdentityError, Result};
use crate::keys::{Identity, cert_from_bytes, verify_detached};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Domain separator for vouch signatures.
pub const VOUCH_DOMAIN: &[u8] = b"fantuan-trust-vouch-v1";

/// A signed trust statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustVouch {
    /// Signer fingerprint (uppercase hex).
    pub signer: String,
    /// Subject fingerprint (uppercase hex).
    pub subject: String,
    /// Assigned trust level, 0..=3.
    pub level: u8,
    /// Creation time, Unix seconds.
    pub timestamp: u64,
    /// Detached OpenPGP signature over the vouch payload.
    pub signature: ByteBuf,
}

/// Exact bytes covered by a vouch signature.
pub fn vouch_message(signer: &str, subject: &str, level: u8, timestamp: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(VOUCH_DOMAIN.len() + signer.len() + subject.len() + 16);
    message.extend_from_slice(VOUCH_DOMAIN);
    for field in [signer, subject] {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message.push(level);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message
}

impl TrustVouch {
    /// Sign a new vouch with our identity key.
    pub fn create(identity: &Identity, subject: &str, level: u8, timestamp: u64) -> Result<Self> {
        if level > 3 {
            return Err(IdentityError::Trust(format!(
                "trust level {level} out of range 0..=3"
            )));
        }
        let signer = identity.fingerprint_hex();
        let message = vouch_message(&signer, subject, level, timestamp);
        let signature = identity.sign_detached(&message)?;
        Ok(Self {
            signer,
            subject: subject.to_string(),
            level,
            timestamp,
            signature: ByteBuf::from(signature),
        })
    }

    /// Verify the vouch against the signer's certificate.
    pub fn verify(&self, signer_cert: &Cert) -> Result<()> {
        if self.level > 3 {
            return Err(IdentityError::Verification(
                "vouch level out of range".to_string(),
            ));
        }
        let fingerprint = signer_cert.fingerprint().to_hex().to_uppercase();
        if fingerprint != self.signer {
            return Err(IdentityError::Verification(
                "vouch signer does not match the certificate".to_string(),
            ));
        }
        let message = vouch_message(&self.signer, &self.subject, self.level, self.timestamp);
        verify_detached(signer_cert, &message, &self.signature)
    }

    /// Verify against serialized certificate bytes.
    pub fn verify_cert_bytes(&self, cert_bytes: &[u8]) -> Result<()> {
        self.verify(&cert_from_bytes(cert_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(uid: &str) -> (Identity, String) {
        let identity = Identity::generate(uid, &format!("dest-{uid}")).expect("identity");
        let fingerprint = identity.fingerprint_hex();
        (identity, fingerprint)
    }

    #[test]
    fn vouch_roundtrip() {
        let (alice, alice_fp) = identity("alice");
        let (_bob, bob_fp) = identity("bob");
        let vouch = TrustVouch::create(&alice, &bob_fp, 2, 1000).expect("vouch");
        assert_eq!(vouch.signer, alice_fp);
        assert_eq!(vouch.subject, bob_fp);
        vouch
            .verify(&cert_from_bytes(&alice.public_cert_bytes().unwrap()).unwrap())
            .expect("verify");
    }

    #[test]
    fn wrong_certificate_is_rejected() {
        let (alice, _) = identity("alice");
        let (mallory, _) = identity("mallory");
        let vouch = TrustVouch::create(&alice, "SUBJECT", 2, 1000).expect("vouch");
        let mallory_cert = cert_from_bytes(&mallory.public_cert_bytes().unwrap()).unwrap();
        assert!(vouch.verify(&mallory_cert).is_err());
    }

    #[test]
    fn tampered_level_is_rejected() {
        let (alice, _) = identity("alice");
        let mut vouch = TrustVouch::create(&alice, "SUBJECT", 2, 1000).expect("vouch");
        vouch.level = 3;
        let cert = cert_from_bytes(&alice.public_cert_bytes().unwrap()).unwrap();
        assert!(vouch.verify(&cert).is_err());
    }

    #[test]
    fn out_of_range_level_is_rejected() {
        let (alice, _) = identity("alice");
        assert!(TrustVouch::create(&alice, "SUBJECT", 4, 1000).is_err());
    }
}
