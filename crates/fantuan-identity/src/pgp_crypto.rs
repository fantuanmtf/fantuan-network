//! OpenPGP payload encryption for relayed messages.
//!
//! Relay hops must never see message plaintext, so relay payloads are
//! encrypted to the destination's OpenPGP encryption subkey. The transport
//! layer's Noise session protects each hop; this module protects the
//! end-to-end payload.

use crate::error::{IdentityError, Result};
use crate::keys::Identity;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::{PKESK, SKESK};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient};
use sequoia_openpgp::types::SymmetricAlgorithm;
use std::io::{Read, Write};

/// Encrypt `plaintext` so that only holders of `cert`'s secret key can read
/// it. Fails when the certificate has no encryption-capable subkey.
pub fn encrypt_for(cert: &Cert, plaintext: &[u8]) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let recipients: Vec<Recipient<'_>> = cert
        .keys()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .map(Recipient::from)
        .collect();
    if recipients.is_empty() {
        return Err(IdentityError::OpenPgp(
            "certificate has no transport-encryption subkey".to_string(),
        ));
    }

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let encryptor = Encryptor::for_recipients(message, recipients)
            .build()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        let mut writer = LiteralWriter::new(encryptor)
            .build()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        writer
            .write_all(plaintext)
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
        writer
            .finalize()
            .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
    }
    Ok(sink)
}

/// Decrypt an OpenPGP message addressed to our identity.
pub fn decrypt(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let helper = DecryptHelper {
        cert: identity.certificate(),
    };
    let policy = StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?
        .with_policy(&policy, None, helper)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
    Ok(plaintext)
}

/// Decrypt with an explicit certificate (tests and imported identities).
pub fn decrypt_with_cert(cert: &Cert, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let helper = DecryptHelper { cert: cert.clone() };
    let policy = StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?
        .with_policy(&policy, None, helper)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .map_err(|e| IdentityError::OpenPgp(e.to_string()))?;
    Ok(plaintext)
}

struct DecryptHelper {
    cert: Cert,
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        // Encryption is authenticated by the Noise session and application
        // signatures; no embedded signature verification is needed here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for DecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        let policy = StandardPolicy::new();
        for key in self
            .cert
            .keys()
            .with_policy(&policy, None)
            .secret()
            .for_transport_encryption()
        {
            let mut keypair = match key.key().clone().into_keypair() {
                Ok(keypair) => keypair,
                Err(_) => continue,
            };
            for pkesk in pkesks {
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .map(|(algorithm, session_key)| decrypt(algorithm, &session_key))
                    .unwrap_or(false)
                {
                    return Ok(Some(self.cert.clone()));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(uid: &str) -> Identity {
        Identity::generate(uid, &format!("dest-{uid}")).expect("identity")
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = identity("alice");
        let message = b"relay payload secret";
        let ciphertext = encrypt_for(&alice.certificate(), message).expect("encrypt");
        assert_ne!(&ciphertext, message);
        let plaintext = decrypt(&alice, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, message);
    }

    #[test]
    fn third_party_cannot_decrypt() {
        let alice = identity("alice");
        let mallory = identity("mallory");
        let ciphertext = encrypt_for(&alice.certificate(), b"for alice only").expect("encrypt");
        assert!(decrypt(&mallory, &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let alice = identity("alice");
        let mut ciphertext = encrypt_for(&alice.certificate(), b"payload").expect("encrypt");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        assert!(decrypt(&alice, &ciphertext).is_err());
    }

    #[test]
    fn binary_payloads_roundtrip() {
        let alice = identity("alice");
        let payload = [0u8, 1, 2, 0xff, 0, 0x7f];
        let ciphertext = encrypt_for(&alice.certificate(), &payload).expect("encrypt");
        assert_eq!(decrypt(&alice, &ciphertext).expect("decrypt"), payload);
    }
}
