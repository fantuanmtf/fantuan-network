//! Session identity binding.
//!
//! After a Noise handshake completes, each side sends a binding that ties its
//! OpenPGP fingerprint (through the descriptor's certificate) to the exact
//! Noise session. See `docs/PROTOCOL.md` section 3.1.
//!
//! ```text
//! binding_message = "fantuan-identity-binding-v1"
//!                   || handshake_hash (32)
//!                   || noise_static_pub (32)
//!                   || BLAKE3(canonical_descriptor) (32)
//! ```

use crate::descriptor::Descriptor;
use crate::error::{IdentityError, Result};
use crate::keys::{Identity, cert_from_bytes, verify_detached};
use ciborium::Value;

/// Domain separator for binding signatures.
pub const BINDING_DOMAIN: &[u8] = b"fantuan-identity-binding-v1";

/// Upper bound for an encoded binding: descriptor (64 KiB) plus signature.
pub const MAX_BINDING_BYTES: usize = 128 * 1024;

/// Build the exact message covered by a binding signature.
pub fn binding_message(
    handshake_hash: &[u8; 32],
    noise_static_pub: &[u8; 32],
    descriptor_cbor: &[u8],
) -> Vec<u8> {
    let descriptor_hash = blake3::hash(descriptor_cbor);
    let mut message = Vec::with_capacity(BINDING_DOMAIN.len() + 96);
    message.extend_from_slice(BINDING_DOMAIN);
    message.extend_from_slice(handshake_hash);
    message.extend_from_slice(noise_static_pub);
    message.extend_from_slice(descriptor_hash.as_bytes());
    message
}

/// Create the encoded binding for `identity` on this session.
pub fn create_binding(identity: &Identity, handshake_hash: &[u8; 32]) -> Result<Vec<u8>> {
    let descriptor_cbor = identity.descriptor().canonical_bytes()?;
    let message = binding_message(handshake_hash, &identity.noise_public(), &descriptor_cbor);
    let signature = identity.sign_detached(&message)?;
    encode(&descriptor_cbor, &signature)
}

/// Verify an encoded binding and return the authenticated descriptor.
///
/// `peer_noise_static` must be the static key observed during the Noise
/// handshake, and `handshake_hash` the local handshake hash.
pub fn verify_binding(
    bytes: &[u8],
    handshake_hash: &[u8; 32],
    peer_noise_static: &[u8; 32],
) -> Result<Descriptor> {
    let (descriptor_cbor, signature) = decode(bytes)?;
    let descriptor = Descriptor::from_canonical(&descriptor_cbor)?;

    if descriptor.noise_x25519_pub != *peer_noise_static {
        return Err(IdentityError::Verification(
            "descriptor noise key does not match the session static key".to_string(),
        ));
    }
    descriptor.verify_fingerprint()?;

    let message = binding_message(handshake_hash, peer_noise_static, &descriptor_cbor);
    let cert = cert_from_bytes(&descriptor.openpgp_cert)?;
    verify_detached(&cert, &message, &signature)?;
    Ok(descriptor)
}

fn encode(descriptor_cbor: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let fields = vec![
        (
            Value::Integer(1.into()),
            Value::Bytes(descriptor_cbor.to_vec()),
        ),
        (Value::Integer(2.into()), Value::Bytes(signature.to_vec())),
    ];
    let mut encoded = Vec::new();
    ciborium::into_writer(&Value::Map(fields), &mut encoded)
        .map_err(|e| IdentityError::Descriptor(format!("cbor encode failed: {e}")))?;
    if encoded.len() > MAX_BINDING_BYTES {
        return Err(IdentityError::Descriptor(format!(
            "binding exceeds {MAX_BINDING_BYTES} bytes"
        )));
    }
    Ok(encoded)
}

fn decode(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if bytes.len() > MAX_BINDING_BYTES {
        return Err(IdentityError::Descriptor(format!(
            "binding exceeds {MAX_BINDING_BYTES} bytes"
        )));
    }
    let value: Value = ciborium::from_reader(bytes)
        .map_err(|e| IdentityError::Descriptor(format!("cbor decode failed: {e}")))?;

    let mut reencoded = Vec::new();
    ciborium::into_writer(&value, &mut reencoded)
        .map_err(|e| IdentityError::Descriptor(format!("cbor encode failed: {e}")))?;
    if reencoded != bytes {
        return Err(IdentityError::Descriptor(
            "binding is not canonical".to_string(),
        ));
    }

    let Value::Map(fields) = value else {
        return Err(IdentityError::Descriptor(
            "binding must be a map".to_string(),
        ));
    };
    let mut descriptor: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for (key, value) in fields {
        let Value::Integer(key) = key else {
            return Err(IdentityError::Descriptor(
                "binding keys must be integers".to_string(),
            ));
        };
        match i128::from(key) {
            1 => {
                let Value::Bytes(bytes) = value else {
                    return Err(IdentityError::Descriptor(
                        "descriptor field must be bytes".to_string(),
                    ));
                };
                descriptor = Some(bytes);
            }
            2 => {
                let Value::Bytes(bytes) = value else {
                    return Err(IdentityError::Descriptor(
                        "signature field must be bytes".to_string(),
                    ));
                };
                signature = Some(bytes);
            }
            other => {
                return Err(IdentityError::Descriptor(format!(
                    "unknown binding field {other}"
                )));
            }
        }
    }
    let descriptor =
        descriptor.ok_or_else(|| IdentityError::Descriptor("missing descriptor".to_string()))?;
    let signature =
        signature.ok_or_else(|| IdentityError::Descriptor("missing signature".to_string()))?;
    Ok((descriptor, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(uid: &str) -> Identity {
        Identity::generate(uid, &format!("dest-{uid}")).expect("identity")
    }

    #[test]
    fn binding_roundtrip() {
        let alice = identity("alice");
        let hash = [7u8; 32];
        let bytes = create_binding(&alice, &hash).expect("create");
        let descriptor = verify_binding(&bytes, &hash, &alice.noise_public()).expect("verify");
        assert_eq!(&descriptor, alice.descriptor());
    }

    #[test]
    fn wrong_handshake_hash_is_rejected() {
        let alice = identity("alice");
        let bytes = create_binding(&alice, &[1u8; 32]).expect("create");
        assert!(verify_binding(&bytes, &[2u8; 32], &alice.noise_public()).is_err());
    }

    #[test]
    fn wrong_static_key_is_rejected() {
        let alice = identity("alice");
        let mallory = identity("mallory");
        let hash = [7u8; 32];
        let bytes = create_binding(&alice, &hash).expect("create");
        assert!(verify_binding(&bytes, &hash, &mallory.noise_public()).is_err());
    }

    #[test]
    fn tampered_descriptor_is_rejected() {
        let alice = identity("alice");
        let hash = [7u8; 32];
        let bytes = create_binding(&alice, &hash).expect("create");

        let (mut descriptor, signature) = decode(&bytes).expect("decode");
        let last = descriptor.len() - 1;
        descriptor[last] ^= 0xff;
        let tampered = encode(&descriptor, &signature).expect("encode");
        assert!(verify_binding(&tampered, &hash, &alice.noise_public()).is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let alice = identity("alice");
        let hash = [7u8; 32];
        let bytes = create_binding(&alice, &hash).expect("create");

        let (descriptor, mut signature) = decode(&bytes).expect("decode");
        let last = signature.len() - 1;
        signature[last] ^= 0xff;
        let tampered = encode(&descriptor, &signature).expect("encode");
        assert!(verify_binding(&tampered, &hash, &alice.noise_public()).is_err());
    }

    #[test]
    fn non_canonical_binding_is_rejected() {
        let alice = identity("alice");
        let hash = [7u8; 32];
        let mut bytes = create_binding(&alice, &hash).expect("create");
        bytes.push(0);
        assert!(verify_binding(&bytes, &hash, &alice.noise_public()).is_err());
    }
}
