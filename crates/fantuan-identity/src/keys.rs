//! Node identity: OpenPGP certificate hierarchy plus the Noise static key.
//!
//! On disk, an identity consists of:
//!
//! | File | Contents |
//! |------|----------|
//! | `cert.pgp` | public OpenPGP certificate |
//! | `secret.pgp` | secret key material (0600) |
//! | `noise.x25519` | raw X25519 static secret (0600) |
//! | `descriptor.cbor` | canonical descriptor |
//! | `descriptor.sig` | detached OpenPGP signature over the descriptor |
//!
//! The Noise static key is independent from the OpenPGP keys; the OpenPGP
//! signing key endorses its public half inside the descriptor.

use crate::descriptor::Descriptor;
use crate::error::{IdentityError, Result};
use crate::proto_id::{PROTO_ID_LEN, proto_id_from_cert};
use fantuan_core::{fs as secure_fs, time};
use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::types::SignatureType;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

/// File name of the public certificate.
pub const CERT_FILE: &str = "cert.pgp";
/// File name of the secret key material.
pub const SECRET_FILE: &str = "secret.pgp";
/// File name of the canonical descriptor.
pub const DESCRIPTOR_FILE: &str = "descriptor.cbor";
/// File name of the descriptor signature.
pub const DESCRIPTOR_SIG_FILE: &str = "descriptor.sig";
/// File name of the X25519 Noise static secret.
pub const NOISE_FILE: &str = "noise.x25519";

/// A node identity.
pub struct Identity {
    cert: Cert,
    noise_secret: [u8; 32],
    noise_public: [u8; 32],
    descriptor: Descriptor,
    descriptor_sig: Vec<u8>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.noise_secret.zeroize();
    }
}

impl Identity {
    /// Generate a fresh identity and descriptor.
    ///
    /// `uid` becomes the descriptor display name and the OpenPGP user id.
    /// `i2p_destination` is the node's published I2P destination.
    pub fn generate(uid: &str, i2p_destination: &str) -> Result<Self> {
        let (cert, _revocation) = CertBuilder::general_purpose([uid])
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

        let mut noise_secret = [0u8; 32];
        getrandom::fill(&mut noise_secret)
            .map_err(|e| IdentityError::OpenPgp(format!("entropy failure: {e}")))?;
        let noise_public = *X25519Public::from(&StaticSecret::from(noise_secret)).as_bytes();

        let cert_bytes = cert
            .to_vec()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        let descriptor = Descriptor {
            version: Descriptor::VERSION,
            uid: uid.to_string(),
            fingerprint: fingerprint_of_cert_bytes(&cert_bytes)?,
            proto_id: proto_id_from_cert(&cert)?,
            openpgp_cert: cert_bytes,
            noise_x25519_pub: noise_public,
            i2p_destination: i2p_destination.to_string(),
            capabilities: vec!["chat".to_string()],
            created: time::now_unix(),
        };

        let descriptor_sig = sign_with(&cert, &descriptor.canonical_bytes()?)?;

        Ok(Self {
            cert,
            noise_secret,
            noise_public,
            descriptor,
            descriptor_sig,
        })
    }

    /// Load an identity from a directory.
    ///
    /// The descriptor is verified against the certificate and the stored
    /// Noise secret before the identity is returned.
    pub fn load(dir: &Path) -> Result<Self> {
        let secret_bytes = secure_fs::read_file(&dir.join(SECRET_FILE))?;
        let cert =
            Cert::from_bytes(&secret_bytes).map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

        let noise_bytes = secure_fs::read_file(&dir.join(NOISE_FILE))?;
        let noise_secret: [u8; 32] = noise_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Descriptor("noise.x25519 must be 32 bytes".to_string()))?;
        let noise_public = *X25519Public::from(&StaticSecret::from(noise_secret)).as_bytes();

        let descriptor_bytes = secure_fs::read_file(&dir.join(DESCRIPTOR_FILE))?;
        let descriptor = Descriptor::from_canonical(&descriptor_bytes)?;
        let descriptor_sig = secure_fs::read_file(&dir.join(DESCRIPTOR_SIG_FILE))?;

        descriptor.verify(&descriptor_sig)?;
        let cert_bytes = cert
            .to_vec()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        let expected_fp = fingerprint_of_cert_bytes(&cert_bytes)?;
        if descriptor.fingerprint != expected_fp {
            return Err(IdentityError::Verification(
                "descriptor fingerprint does not match secret certificate".to_string(),
            ));
        }
        let expected_proto_id = proto_id_from_cert(&cert)?;
        if descriptor.proto_id != expected_proto_id {
            return Err(IdentityError::Verification(
                "descriptor proto_id does not match secret certificate".to_string(),
            ));
        }
        if descriptor.noise_x25519_pub != noise_public {
            return Err(IdentityError::Verification(
                "descriptor noise key does not match stored noise secret".to_string(),
            ));
        }

        Ok(Self {
            cert,
            noise_secret,
            noise_public,
            descriptor,
            descriptor_sig,
        })
    }

    /// Persist the identity into a directory (created if missing).
    pub fn save(&self, dir: &Path) -> Result<()> {
        secure_fs::ensure_dir_0700(dir)?;

        let public_cert = self
            .cert
            .to_vec()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        let secret_cert = self
            .cert
            .as_tsk()
            .to_vec()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

        secure_fs::write_private_file(&dir.join(CERT_FILE), &public_cert)?;
        secure_fs::write_private_file(&dir.join(SECRET_FILE), &secret_cert)?;
        secure_fs::write_private_file(&dir.join(NOISE_FILE), &self.noise_secret)?;
        secure_fs::write_private_file(
            &dir.join(DESCRIPTOR_FILE),
            &self.descriptor.canonical_bytes()?,
        )?;
        secure_fs::write_private_file(&dir.join(DESCRIPTOR_SIG_FILE), &self.descriptor_sig)?;
        Ok(())
    }

    /// OpenPGP fingerprint, uppercase hex.
    ///
    /// This is the *certificate* identifier (`cert_id`): it is used for
    /// OpenPGP-level lookups and evidence. Protocol namespaces, rosters and
    /// wire objects use [`Identity::proto_id`] instead.
    pub fn fingerprint_hex(&self) -> String {
        self.cert.fingerprint().to_hex().to_uppercase()
    }

    /// Protocol identity: 32 raw bytes derived from the primary public key
    /// packet body (see [`crate::proto_id`]).
    pub fn proto_id(&self) -> [u8; PROTO_ID_LEN] {
        self.descriptor.proto_id
    }

    /// Public certificate bytes (for sharing).
    pub fn public_cert_bytes(&self) -> Result<Vec<u8>> {
        self.cert
            .to_vec()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))
    }

    /// Clone of the full certificate (including secret key material).
    ///
    /// Use only for local cryptographic operations; never send this to peers.
    pub fn certificate(&self) -> Cert {
        self.cert.clone()
    }

    /// The node descriptor.
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Detached signature over the descriptor.
    pub fn descriptor_signature(&self) -> &[u8] {
        &self.descriptor_sig
    }

    /// Noise X25519 static public key.
    pub fn noise_public(&self) -> [u8; 32] {
        self.noise_public
    }

    /// Noise X25519 static secret.
    pub fn noise_secret(&self) -> [u8; 32] {
        self.noise_secret
    }

    /// Sign a message with the signing subkey (detached, binary).
    pub fn sign_detached(&self, message: &[u8]) -> Result<Vec<u8>> {
        sign_with(&self.cert, message)
    }
}

/// Sign `message` with the certificate's signing subkey.
pub fn sign_with(cert: &Cert, message: &[u8]) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let signing_key = cert
        .keys()
        .with_policy(&policy, None)
        .secret()
        .for_signing()
        .next()
        .ok_or_else(|| IdentityError::OpenPgp("certificate has no signing key".to_string()))?;
    let mut signer = signing_key
        .key()
        .clone()
        .into_keypair()
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

    let signature = SignatureBuilder::new(SignatureType::Binary)
        .sign_message(&mut signer, message)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

    signature
        .to_vec()
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))
}

/// Verify a detached signature against any signing-capable key of `cert`.
///
/// Returns Ok only when at least one signing-capable key verifies the
/// signature. Callers must ensure `cert` is the certificate they intend to
/// trust (for example by comparing fingerprints).
pub fn verify_detached(cert: &Cert, message: &[u8], signature: &[u8]) -> Result<()> {
    let policy = StandardPolicy::new();
    let signature = Signature::from_bytes(signature)
        .map_err(|e| IdentityError::Verification(format!("bad signature encoding: {e}")))?;

    for key in cert.keys().with_policy(&policy, None).for_signing() {
        if signature.verify_message(key.key(), message).is_ok() {
            return Ok(());
        }
    }
    Err(IdentityError::Verification(
        "no signing key of the certificate verified the signature".to_string(),
    ))
}

/// Parse a certificate from bytes.
pub fn cert_from_bytes(bytes: &[u8]) -> Result<Cert> {
    Cert::from_bytes(bytes).map_err(|e| IdentityError::OpenPgp(e.to_string()))
}

/// Compute the uppercase hex fingerprint of a serialized certificate.
pub fn fingerprint_of_cert_bytes(bytes: &[u8]) -> Result<String> {
    let cert = cert_from_bytes(bytes)?;
    Ok(cert.fingerprint().to_hex().to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_and_verify() {
        let identity = Identity::generate("alice", "dest-alice").expect("identity");
        let message = b"hello fantuan";
        let signature = identity.sign_detached(message).expect("sign");
        let cert = cert_from_bytes(&identity.public_cert_bytes().unwrap()).unwrap();
        verify_detached(&cert, message, &signature).expect("verify");

        // Tampered message must fail.
        assert!(verify_detached(&cert, b"tampered", &signature).is_err());
        // Tampered signature must fail.
        let mut bad = signature.clone();
        bad[10] ^= 0xff;
        assert!(verify_detached(&cert, message, &bad).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Identity::generate("bob", "dest-bob").expect("identity");
        identity.save(dir.path()).expect("save");

        let loaded = Identity::load(dir.path()).expect("load");
        assert_eq!(loaded.fingerprint_hex(), identity.fingerprint_hex());
        assert_eq!(loaded.noise_public(), identity.noise_public());
        assert_eq!(loaded.descriptor().uid, "bob");
        assert_eq!(
            loaded.descriptor_signature(),
            identity.descriptor_signature()
        );
    }

    #[test]
    fn load_rejects_tampered_descriptor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Identity::generate("carol", "dest-carol").expect("identity");
        identity.save(dir.path()).expect("save");

        let descriptor_path = dir.path().join(DESCRIPTOR_FILE);
        let mut bytes = std::fs::read(&descriptor_path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&descriptor_path, &bytes).expect("write");

        let result = Identity::load(dir.path());
        assert!(result.is_err(), "tampered descriptor must be rejected");
    }

    #[test]
    fn signing_key_differs_from_primary() {
        let identity = Identity::generate("dave", "dest-dave").expect("identity");
        let cert = cert_from_bytes(&identity.public_cert_bytes().unwrap()).unwrap();
        assert!(cert.keys().count() >= 3, "primary + signing + encryption");
    }
}
