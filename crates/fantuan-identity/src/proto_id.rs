//! Protocol identity (`proto_id`).
//!
//! `proto_id` is the identity the protocol uses: round namespaces, rosters,
//! ACK fields, KDF inputs and wire objects. It is derived from the primary
//! public key packet **body** only, so a certificate's mutable metadata — user
//! ids, subkeys, self-signatures, expirations — cannot move it. Replacing the
//! primary key is an identity change, not a metadata change, and does move it.
//!
//! Frozen derivation (`docs/PROTOCOL.md` section 2):
//!
//! ```text
//! proto_id = BLAKE3("fantuan-proto-id-v1" ‖ canonical_primary_public_key_packet_body)[0..32]
//! ```
//!
//! The canonical body is the OpenPGP public-key packet body of the primary key
//! as serialized by sequoia — `version ‖ creation time ‖ algorithm ‖ key
//! material` for v4 keys, whatever that version defines otherwise — **without**
//! the packet tag/length header. The whole certificate is never hashed.
//!
//! `T-ID-TESTVECTOR` pins the derivation against a fixed certificate, and
//! `body_layout_is_the_public_key_packet_body` pins what "packet body" means
//! for the version this project generates.

use crate::error::{IdentityError, Result};
use crate::keys::cert_from_bytes;
use sequoia_openpgp::Cert;
use sequoia_openpgp::serialize::MarshalInto;

/// Domain separator for the protocol identity derivation.
pub const PROTO_ID_DOMAIN: &[u8] = b"fantuan-proto-id-v1";

/// Wire width of a protocol identity, in bytes.
pub const PROTO_ID_LEN: usize = 32;

/// Derive the protocol identity of a certificate.
pub fn proto_id_from_cert(cert: &Cert) -> Result<[u8; PROTO_ID_LEN]> {
    let body = canonical_primary_public_key_packet_body(cert)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROTO_ID_DOMAIN);
    hasher.update(&body);
    let mut proto_id = [0u8; PROTO_ID_LEN];
    proto_id.copy_from_slice(&hasher.finalize().as_bytes()[..PROTO_ID_LEN]);
    Ok(proto_id)
}

/// Derive the protocol identity of a serialized certificate.
pub fn proto_id_from_cert_bytes(bytes: &[u8]) -> Result<[u8; PROTO_ID_LEN]> {
    proto_id_from_cert(&cert_from_bytes(bytes)?)
}

/// The canonical primary public key packet body that `proto_id` hashes.
///
/// Exposed so tests and review tooling can pin the exact bytes.
pub fn canonical_primary_public_key_packet_body(cert: &Cert) -> Result<Vec<u8>> {
    cert.primary_key().key().to_vec().map_err(|error| {
        IdentityError::OpenPgp(format!("cannot serialize primary key packet body: {error}"))
    })
}

/// Uppercase hex form, for logs, diagnostics and UI display only.
///
/// Never use this as a protocol key, a namespace or a lookup key: wire objects
/// carry the raw 32 bytes.
pub fn proto_id_hex(proto_id: &[u8; PROTO_ID_LEN]) -> String {
    let mut hex = String::with_capacity(PROTO_ID_LEN * 2);
    for byte in proto_id {
        hex.push_str(&format!("{byte:02X}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;
    use sequoia_openpgp::packet::{Packet, UserID};
    use std::time::UNIX_EPOCH;

    #[test]
    fn body_layout_is_the_public_key_packet_body() {
        // Pins what "primary public key packet body" means: the v4 layout
        // version ‖ creation time ‖ algorithm ‖ key material, with no packet
        // tag/length header in front.
        let identity = Identity::generate("alice", "dest-alice").expect("identity");
        let cert = cert_from_bytes(&identity.public_cert_bytes().expect("bytes")).expect("cert");
        let body = canonical_primary_public_key_packet_body(&cert).expect("body");

        assert!(
            body.len() > 6,
            "a public key body is longer than its header"
        );
        assert_eq!(body[0], 4, "generated keys are v4");
        let created = cert
            .primary_key()
            .key()
            .creation_time()
            .duration_since(UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs() as u32;
        assert_eq!(
            &body[1..5],
            &created.to_be_bytes(),
            "creation time follows the version, big endian"
        );
        assert_eq!(
            body[5], 22,
            "the primary key is Ed25519 (EdDSA, algorithm 22); the Cv25519 key is a subkey"
        );
    }

    /// T-ID-STABILITY: metadata changes must not move the protocol identity;
    /// replacing the primary key must.
    #[test]
    fn id_stability_across_metadata_changes() {
        let alice = Identity::generate("alice", "dest-alice").expect("identity");
        let bob = Identity::generate("bob", "dest-bob").expect("identity");
        let alice_cert = cert_from_bytes(&alice.public_cert_bytes().expect("bytes")).expect("cert");
        let before = proto_id_from_cert(&alice_cert).expect("proto_id");

        // Serialization round trip.
        let reparsed = cert_from_bytes(&alice_cert.to_vec().expect("bytes")).expect("cert");
        assert_eq!(proto_id_from_cert(&reparsed).expect("proto_id"), before);

        // Extra user id: metadata, so the identity must not move.
        let (with_uid, _) = alice_cert
            .clone()
            .insert_packets([UserID::from("alice@elsewhere")])
            .expect("insert user id");
        assert_ne!(
            with_uid.to_vec().expect("bytes").len(),
            alice_cert.to_vec().expect("bytes").len(),
            "the certificate really changed"
        );
        assert_eq!(
            proto_id_from_cert(&with_uid).expect("proto_id"),
            before,
            "an added user id must not move proto_id"
        );

        // Extra subkey (borrowed from another identity, so the packet really
        // is a subkey packet): still metadata.
        let bob_cert = cert_from_bytes(&bob.public_cert_bytes().expect("bytes")).expect("cert");
        let subkey_packet = bob_cert
            .keys()
            .subkeys()
            .next()
            .map(|subkey| Packet::from(subkey.key().clone()))
            .expect("bob has a subkey");
        let (with_subkey, _) = alice_cert
            .clone()
            .insert_packets([subkey_packet])
            .expect("insert subkey");
        assert_eq!(
            proto_id_from_cert(&with_subkey).expect("proto_id"),
            before,
            "an added subkey must not move proto_id"
        );

        // Replacing the primary key is an identity change.
        let other = proto_id_from_cert(&bob_cert).expect("proto_id");
        assert_ne!(
            other, before,
            "a different primary key is a different identity"
        );
    }

    /// T-ID-WIRE-1: the protocol identity is exactly 32 raw bytes, and the
    /// descriptor carries those bytes rather than a hex string.
    #[test]
    fn id_wire_width_is_32_raw_bytes() {
        let identity = Identity::generate("carol", "dest-carol").expect("identity");
        let proto_id = proto_id_from_cert(
            &cert_from_bytes(&identity.public_cert_bytes().expect("bytes")).expect("cert"),
        )
        .expect("proto_id");
        assert_eq!(proto_id.len(), PROTO_ID_LEN);

        let encoded = identity.descriptor().canonical_bytes().expect("encode");
        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).expect("decode");
        let ciborium::Value::Map(fields) = value else {
            panic!("descriptor must be a map");
        };
        let field = fields
            .iter()
            .find(|(key, _)| *key == ciborium::Value::Integer(9.into()))
            .map(|(_, value)| value)
            .expect("descriptor carries field 9");
        let ciborium::Value::Bytes(raw) = field else {
            panic!("proto_id must be encoded as bytes, not text");
        };
        assert_eq!(
            raw.len(),
            PROTO_ID_LEN,
            "proto_id is fixed width on the wire"
        );

        let hex = proto_id_hex(&proto_id);
        assert!(
            !encoded
                .windows(hex.len())
                .any(|window| window == hex.as_bytes()),
            "the hex form must never appear in the encoded descriptor"
        );
    }

    /// T-ID-TESTVECTOR: a fixed certificate and its expected protocol identity.
    ///
    /// Any change to the domain separator, the packet-body extraction or the
    /// hash construction breaks this vector.
    #[test]
    fn id_testvector() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/proto_id_testvector.pgp"
        ))
        .expect("fixture is checked in");
        let cert = cert_from_bytes(&bytes).expect("fixture certificate parses");
        let proto_id = proto_id_from_cert(&cert).expect("proto_id");
        assert_eq!(
            proto_id_hex(&proto_id),
            EXPECTED_PROTO_ID,
            "proto_id derivation changed"
        );
    }

    /// Fixed certificate and the protocol identity it must derive to.
    ///
    /// Regenerate with the `print_fixture_vector` helper below and update both
    /// the fixture file and this constant in the same commit.
    const EXPECTED_PROTO_ID: &str =
        "458A2FB67E7FBD4947733835A14E61933F57F68D4DEAF88D68B1E1EE8A9EE815";

    /// Prints a fresh fixture (certificate hex) and its protocol identity.
    ///
    /// Never writes into the repository: run with
    /// `cargo test -p fantuan-identity --lib print_fixture_vector -- --ignored --nocapture`.
    #[test]
    #[ignore = "fixture regeneration helper; prints only"]
    fn print_fixture_vector() {
        let identity = Identity::generate("vector", "dest-vector").expect("identity");
        let bytes = identity.public_cert_bytes().expect("bytes");
        eprintln!("CERT_HEX={}", {
            let mut hex = String::with_capacity(bytes.len() * 2);
            for byte in &bytes {
                hex.push_str(&format!("{byte:02x}"));
            }
            hex
        });
        eprintln!("PROTO_ID={}", proto_id_hex(&identity.proto_id()));
    }
}
