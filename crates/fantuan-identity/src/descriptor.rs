//! Canonical node descriptor.
//!
//! The descriptor is a canonical CBOR map with integer keys (see
//! `docs/PROTOCOL.md` section 2). Canonical means: fixed key order, definite
//! lengths, no duplicate or unknown keys, no trailing bytes. Decoding
//! re-encodes the parsed value and rejects anything that does not round
//! back to the input byte-for-byte.

use crate::error::{IdentityError, Result};
use crate::keys::{cert_from_bytes, fingerprint_of_cert_bytes, verify_detached};
use crate::proto_id::{PROTO_ID_LEN, proto_id_from_cert_bytes};
use ciborium::Value;

/// Hard upper bound for an encoded descriptor (64 KiB).
pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// Maximum number of capabilities accepted.
pub const MAX_CAPABILITIES: usize = 32;

/// A signed node descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// Descriptor format version.
    pub version: u16,
    /// Human-readable node name.
    pub uid: String,
    /// Uppercase hex OpenPGP fingerprint.
    pub fingerprint: String,
    /// Public OpenPGP certificate.
    pub openpgp_cert: Vec<u8>,
    /// Noise X25519 static public key.
    pub noise_x25519_pub: [u8; 32],
    /// I2P destination (base64).
    pub i2p_destination: String,
    /// Advertised capabilities.
    pub capabilities: Vec<String>,
    /// Protocol identity: 32 raw bytes derived from the primary public key
    /// packet body. The self-signature covers this field, and every ingest
    /// recomputes it from the embedded certificate.
    pub proto_id: [u8; PROTO_ID_LEN],
    /// Creation time, Unix seconds.
    pub created: u64,
}

impl Descriptor {
    /// Current descriptor format version.
    ///
    /// Version 2 added the `proto_id` field (key 9); version 1 descriptors are
    /// rejected rather than migrated.
    pub const VERSION: u16 = 2;

    /// Encode the descriptor in canonical form.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.uid.len() > 256 {
            return Err(IdentityError::Descriptor("uid too long".to_string()));
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(IdentityError::Descriptor(
                "too many capabilities".to_string(),
            ));
        }

        let capabilities: Vec<Value> = self
            .capabilities
            .iter()
            .map(|c| Value::Text(c.clone()))
            .collect();

        let fields = vec![
            (
                Value::Integer(1.into()),
                Value::Integer(self.version.into()),
            ),
            (Value::Integer(2.into()), Value::Text(self.uid.clone())),
            (
                Value::Integer(3.into()),
                Value::Text(self.fingerprint.clone()),
            ),
            (
                Value::Integer(4.into()),
                Value::Bytes(self.openpgp_cert.clone()),
            ),
            (
                Value::Integer(5.into()),
                Value::Bytes(self.noise_x25519_pub.to_vec()),
            ),
            (
                Value::Integer(6.into()),
                Value::Text(self.i2p_destination.clone()),
            ),
            (Value::Integer(7.into()), Value::Array(capabilities)),
            (
                Value::Integer(8.into()),
                Value::Integer(self.created.into()),
            ),
            (
                Value::Integer(9.into()),
                Value::Bytes(self.proto_id.to_vec()),
            ),
        ];

        let encoded = encode_value(&Value::Map(fields))?;
        if encoded.len() > MAX_DESCRIPTOR_BYTES {
            return Err(IdentityError::Descriptor(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_BYTES} bytes"
            )));
        }
        Ok(encoded)
    }

    /// Decode a canonical descriptor.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(IdentityError::Descriptor(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_BYTES} bytes"
            )));
        }
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|e| IdentityError::Descriptor(format!("cbor decode failed: {e}")))?;

        // Canonical form check: re-encoding must reproduce the input.
        let reencoded = encode_value(&value)?;
        if reencoded != bytes {
            return Err(IdentityError::Descriptor(
                "descriptor is not canonical".to_string(),
            ));
        }

        let Value::Map(fields) = value else {
            return Err(IdentityError::Descriptor(
                "descriptor must be a map".to_string(),
            ));
        };

        let mut version: Option<u16> = None;
        let mut uid: Option<String> = None;
        let mut fingerprint: Option<String> = None;
        let mut openpgp_cert: Option<Vec<u8>> = None;
        let mut noise_x25519_pub: Option<[u8; 32]> = None;
        let mut i2p_destination: Option<String> = None;
        let mut capabilities: Option<Vec<String>> = None;
        let mut created: Option<u64> = None;
        let mut proto_id: Option<[u8; PROTO_ID_LEN]> = None;
        let mut last_key: i128 = 0;

        for (key, value) in fields {
            let Value::Integer(key) = key else {
                return Err(IdentityError::Descriptor("non-integer key".to_string()));
            };
            let key = i128::from(key);
            // Canonical CBOR: small integer keys must appear in ascending
            // order, so a reordered encoding is rejected here.
            if key <= last_key {
                return Err(IdentityError::Descriptor(
                    "descriptor keys are not in canonical order".to_string(),
                ));
            }
            last_key = key;
            match key {
                1 => version = Some(as_u64(&value, "version")?.try_into().map_err(bad_uint)?),
                2 => uid = Some(as_text(&value, "uid")?),
                3 => fingerprint = Some(as_text(&value, "fingerprint")?),
                4 => openpgp_cert = Some(as_bytes(&value, "openpgp_cert")?),
                5 => {
                    let raw = as_bytes(&value, "noise_x25519_pub")?;
                    noise_x25519_pub = Some(
                        raw.as_slice()
                            .try_into()
                            .map_err(|_| IdentityError::Descriptor("noise key length".into()))?,
                    );
                }
                6 => i2p_destination = Some(as_text(&value, "i2p_destination")?),
                7 => {
                    let Value::Array(items) = value else {
                        return Err(IdentityError::Descriptor(
                            "capabilities must be an array".to_string(),
                        ));
                    };
                    if items.len() > MAX_CAPABILITIES {
                        return Err(IdentityError::Descriptor(
                            "too many capabilities".to_string(),
                        ));
                    }
                    let mut caps = Vec::with_capacity(items.len());
                    for item in items {
                        caps.push(as_text(&item, "capability")?);
                    }
                    capabilities = Some(caps);
                }
                8 => created = Some(as_u64(&value, "created")?),
                9 => {
                    let raw = as_bytes(&value, "proto_id")?;
                    proto_id = Some(raw.as_slice().try_into().map_err(|_| {
                        IdentityError::Descriptor(format!("proto_id must be {PROTO_ID_LEN} bytes"))
                    })?);
                }
                other => {
                    return Err(IdentityError::Descriptor(format!("unknown field {other}")));
                }
            }
        }

        let descriptor = Descriptor {
            version: version
                .ok_or_else(|| IdentityError::Descriptor("missing version".to_string()))?,
            uid: uid.ok_or_else(|| IdentityError::Descriptor("missing uid".to_string()))?,
            fingerprint: fingerprint
                .ok_or_else(|| IdentityError::Descriptor("missing fingerprint".to_string()))?,
            openpgp_cert: openpgp_cert
                .ok_or_else(|| IdentityError::Descriptor("missing openpgp_cert".to_string()))?,
            noise_x25519_pub: noise_x25519_pub
                .ok_or_else(|| IdentityError::Descriptor("missing noise key".to_string()))?,
            i2p_destination: i2p_destination
                .ok_or_else(|| IdentityError::Descriptor("missing i2p destination".to_string()))?,
            capabilities: capabilities
                .ok_or_else(|| IdentityError::Descriptor("missing capabilities".to_string()))?,
            created: created
                .ok_or_else(|| IdentityError::Descriptor("missing created".to_string()))?,
            proto_id: proto_id
                .ok_or_else(|| IdentityError::Descriptor("missing proto_id".to_string()))?,
        };

        if descriptor.version != Self::VERSION {
            return Err(IdentityError::Descriptor(format!(
                "unsupported descriptor version {}",
                descriptor.version
            )));
        }
        Ok(descriptor)
    }

    /// Verify the descriptor's embedded certificate fingerprint.
    pub fn verify_fingerprint(&self) -> Result<()> {
        let expected = fingerprint_of_cert_bytes(&self.openpgp_cert)?;
        if expected != self.fingerprint {
            return Err(IdentityError::Verification(
                "fingerprint does not match certificate".to_string(),
            ));
        }
        Ok(())
    }

    /// Recompute the protocol identity from the embedded certificate and
    /// compare it with the signed field.
    ///
    /// A valid self-signature is not sufficient on its own: it proves the key
    /// signed the value, not that the value follows from the certificate. The
    /// recomputation is what binds `proto_id` to the key material.
    pub fn verify_proto_id(&self) -> Result<()> {
        let expected = proto_id_from_cert_bytes(&self.openpgp_cert)?;
        if expected != self.proto_id {
            return Err(IdentityError::Verification(
                "proto_id does not match the certificate".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify a detached signature over the canonical descriptor bytes.
    pub fn verify(&self, signature: &[u8]) -> Result<()> {
        self.verify_fingerprint()?;
        self.verify_proto_id()?;
        let cert = cert_from_bytes(&self.openpgp_cert)?;
        verify_detached(&cert, &self.canonical_bytes()?, signature)
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .map_err(|e| IdentityError::Descriptor(format!("cbor encode failed: {e}")))?;
    Ok(out)
}

fn as_u64(value: &Value, field: &str) -> Result<u64> {
    match value {
        Value::Integer(i) => u64::try_from(*i)
            .map_err(|_| IdentityError::Descriptor(format!("{field} must be unsigned"))),
        _ => Err(IdentityError::Descriptor(format!(
            "{field} must be an integer"
        ))),
    }
}

fn as_text(value: &Value, field: &str) -> Result<String> {
    match value {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(IdentityError::Descriptor(format!("{field} must be text"))),
    }
}

fn as_bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(IdentityError::Descriptor(format!("{field} must be bytes"))),
    }
}

fn bad_uint(e: std::num::TryFromIntError) -> IdentityError {
    IdentityError::Descriptor(format!("integer out of range: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    fn sample() -> (Identity, Descriptor, Vec<u8>) {
        let identity = Identity::generate("alice", "dest-alice").expect("identity");
        let descriptor = identity.descriptor().clone();
        let signature = identity.descriptor_signature().to_vec();
        (identity, descriptor, signature)
    }

    #[test]
    fn canonical_roundtrip() {
        let (_identity, descriptor, _sig) = sample();
        let bytes = descriptor.canonical_bytes().expect("encode");
        let parsed = Descriptor::from_canonical(&bytes).expect("decode");
        assert_eq!(parsed, descriptor);
        assert_eq!(parsed.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn signature_verifies_and_tampering_fails() {
        let (_identity, descriptor, signature) = sample();
        descriptor.verify(&signature).expect("verify");

        let mut tampered = descriptor.clone();
        tampered.uid = "mallory".to_string();
        assert!(tampered.verify(&signature).is_err());

        let mut bad_sig = signature.clone();
        bad_sig[5] ^= 0xff;
        assert!(descriptor.verify(&bad_sig).is_err());
    }

    #[test]
    fn rejects_trailing_and_unknown_fields() {
        let (_identity, descriptor, _sig) = sample();
        let mut bytes = descriptor.canonical_bytes().unwrap();
        bytes.push(0);
        assert!(Descriptor::from_canonical(&bytes).is_err());

        let with_unknown = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(99.into()), Value::Integer(0.into())),
        ]);
        let encoded = encode_value(&with_unknown).unwrap();
        assert!(Descriptor::from_canonical(&encoded).is_err());
    }

    #[test]
    fn rejects_reordered_fields() {
        let (_identity, descriptor, _sig) = sample();
        let bytes = descriptor.canonical_bytes().unwrap();
        let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(mut fields) = value else {
            panic!("map expected");
        };
        fields.reverse();
        let reordered = encode_value(&Value::Map(fields)).unwrap();
        assert!(Descriptor::from_canonical(&reordered).is_err());
    }

    #[test]
    fn rejects_fingerprint_mismatch() {
        let (_identity, mut descriptor, signature) = sample();
        descriptor.fingerprint = "00".repeat(20);
        assert!(descriptor.verify(&signature).is_err());
    }

    /// T-ID-BINDING: `proto_id` must follow from the certificate, not merely
    /// be signed. A tampered value that is re-signed with the same key is
    /// still rejected, because the recomputation disagrees.
    #[test]
    fn id_binding_rejects_a_signed_but_wrong_proto_id() {
        let (identity, mut descriptor, _sig) = sample();

        // Round trip the honest value first.
        descriptor
            .verify_proto_id()
            .expect("honest proto_id verifies");

        descriptor.proto_id = [0x42u8; PROTO_ID_LEN];
        let resigned = crate::keys::sign_with(
            &identity.certificate(),
            &descriptor.canonical_bytes().expect("encode"),
        )
        .expect("re-sign");
        let error = descriptor
            .verify(&resigned)
            .expect_err("a valid signature over a wrong proto_id must still fail");
        assert!(
            format!("{error}").contains("proto_id"),
            "rejection must be attributed to proto_id, got: {error}"
        );
        assert!(
            descriptor.verify_proto_id().is_err(),
            "the recomputation is what rejects it"
        );
    }

    /// A descriptor without the `proto_id` field, or with a wrongly sized one,
    /// must not decode.
    #[test]
    fn id_binding_requires_a_fixed_width_proto_id_field() {
        let (_identity, descriptor, _sig) = sample();
        let bytes = descriptor.canonical_bytes().expect("encode");
        let value: Value = ciborium::from_reader(bytes.as_slice()).expect("decode");
        let Value::Map(fields) = value else {
            panic!("map expected");
        };

        let without: Vec<_> = fields
            .iter()
            .filter(|(key, _)| *key != Value::Integer(9.into()))
            .cloned()
            .collect();
        let encoded = encode_value(&Value::Map(without)).expect("encode");
        assert!(
            Descriptor::from_canonical(&encoded).is_err(),
            "a descriptor without proto_id must be rejected"
        );

        let short: Vec<_> = fields
            .into_iter()
            .map(|(key, value)| {
                if key == Value::Integer(9.into()) {
                    (key, Value::Bytes(vec![0u8; PROTO_ID_LEN - 1]))
                } else {
                    (key, value)
                }
            })
            .collect();
        let encoded = encode_value(&Value::Map(short)).expect("encode");
        assert!(
            Descriptor::from_canonical(&encoded).is_err(),
            "a wrongly sized proto_id must be rejected"
        );
    }
}
