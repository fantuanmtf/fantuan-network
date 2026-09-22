//! Pairwise share derivation and share authentication.
//!
//! DC-Net shares come from the per-node X25519 static keys that already back
//! Noise sessions and are endorsed by OpenPGP descriptors. For each unordered
//! pair `(a, b)` both sides derive the same pseudorandom block from
//! `ECDH(static_a, static_b)` and the round id; XOR-ing every participant's
//! shares cancels all pairwise blocks and reveals only the message.

use crate::error::{AnonError, Result};
use fantuan_identity::Identity;
use fantuan_identity::keys::{cert_from_bytes, verify_detached};
use fantuan_msg::{DCNET_MAX_PAYLOAD_LEN, pad_message, share_message};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

/// Domain separator for pair-share derivation.
pub const PAIR_DOMAIN: &[u8] = b"fantuan-dcnet-pair-v1";

/// Derive the pairwise block for one round.
///
/// `a` and `b` are fingerprints; they are sorted internally so both ends
/// derive identical bytes.
pub fn derive_pair_share(
    local_secret: &[u8; 32],
    peer_public: &[u8; 32],
    round_id: u64,
    a: &str,
    b: &str,
    len: usize,
) -> Result<Vec<u8>> {
    let (low, high) = if a <= b { (a, b) } else { (b, a) };
    let secret = StaticSecret::from(*local_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(AnonError::Share(
            "peer X25519 key is not contributory".to_string(),
        ));
    }

    let mut info = Vec::with_capacity(PAIR_DOMAIN.len() + 8 + low.len() + high.len() + 8);
    info.extend_from_slice(PAIR_DOMAIN);
    info.extend_from_slice(&round_id.to_be_bytes());
    for uid in [low, high] {
        info.extend_from_slice(&(uid.len() as u32).to_be_bytes());
        info.extend_from_slice(uid.as_bytes());
    }

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut output = Vec::with_capacity(len);
    let mut block: u8 = 0;
    while output.len() < len {
        let mut block_info = info.clone();
        block_info.push(block);
        let mut okm = [0u8; 32];
        hk.expand(&block_info, &mut okm)
            .map_err(|error| AnonError::Share(format!("hkdf expand failed: {error}")))?;
        output.extend_from_slice(&okm);
        block = block.wrapping_add(1);
    }
    output.truncate(len);
    Ok(output)
}

/// XOR `other` into `target` byte-wise.
pub fn xor_in_place(target: &mut [u8], other: &[u8]) {
    for (target_byte, other_byte) in target.iter_mut().zip(other.iter()) {
        *target_byte ^= *other_byte;
    }
}

/// XOR a set of equal-length shares together.
pub fn xor_all(shares: &[Vec<u8>], payload_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; payload_len];
    for share in shares {
        xor_in_place(&mut output, share);
    }
    output
}

/// Compute one participant's share for a round.
///
/// Every other participant needs a known X25519 static key; participation is
/// refused when any key is missing rather than falling back to weaker shares.
pub fn compute_xor_share(
    local_secret: &[u8; 32],
    my_uid: &str,
    participants: &[String],
    peer_noise: &HashMap<String, [u8; 32]>,
    message: Option<&[u8]>,
    payload_len: usize,
    round_id: u64,
) -> Result<Vec<u8>> {
    if participants.len() < 2 {
        return Err(AnonError::Round(
            "need at least two participants".to_string(),
        ));
    }
    if !participants.iter().any(|participant| participant == my_uid) {
        return Err(AnonError::Round(
            "not a participant of this round".to_string(),
        ));
    }
    if !(36..=DCNET_MAX_PAYLOAD_LEN).contains(&payload_len) {
        return Err(AnonError::Round("payload length out of range".to_string()));
    }

    let mut output = vec![0u8; payload_len];
    for other in participants {
        if other == my_uid {
            continue;
        }
        let peer_public = peer_noise.get(other).ok_or_else(|| {
            AnonError::Share(format!("missing X25519 key for participant {other}"))
        })?;
        let share = derive_pair_share(
            local_secret,
            peer_public,
            round_id,
            my_uid,
            other,
            payload_len,
        )?;
        xor_in_place(&mut output, &share);
    }

    if let Some(message) = message {
        let padded = pad_message(message, payload_len)
            .ok_or_else(|| AnonError::Share("message does not fit the payload".to_string()))?;
        xor_in_place(&mut output, &padded);
    }
    Ok(output)
}

/// Sign a share with the node identity (OpenPGP detached signature).
pub fn sign_share(
    identity: &Identity,
    channel: &str,
    round_id: u64,
    share: &[u8],
) -> Result<Vec<u8>> {
    Ok(identity.sign_detached(&share_message(channel, round_id, share))?)
}

/// Verify a share signature against the sender's certificate bytes.
pub fn verify_share(
    cert_bytes: &[u8],
    channel: &str,
    round_id: u64,
    share: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(cert) = cert_from_bytes(cert_bytes) else {
        return false;
    };
    verify_detached(&cert, &share_message(channel, round_id, share), signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fantuan_msg::unpad_message;
    use x25519_dalek::StaticSecret;

    struct Pair {
        uid: String,
        secret: [u8; 32],
        public: [u8; 32],
    }

    fn participant(uid: &str) -> Pair {
        let secret = StaticSecret::random();
        let public = *PublicKey::from(&secret).as_bytes();
        Pair {
            uid: uid.to_string(),
            secret: secret.to_bytes(),
            public,
        }
    }

    fn keymap(pairs: &[&Pair]) -> HashMap<String, [u8; 32]> {
        pairs
            .iter()
            .map(|pair| (pair.uid.clone(), pair.public))
            .collect()
    }

    #[test]
    fn pair_share_is_symmetric() {
        let alice = participant("alice");
        let bob = participant("bob");
        let from_alice =
            derive_pair_share(&alice.secret, &bob.public, 7, "alice", "bob", 64).expect("alice");
        let from_bob =
            derive_pair_share(&bob.secret, &alice.public, 7, "bob", "alice", 64).expect("bob");
        assert_eq!(from_alice, from_bob);
        assert_eq!(from_alice.len(), 64);

        let other_round =
            derive_pair_share(&alice.secret, &bob.public, 8, "alice", "bob", 64).expect("round 8");
        assert_ne!(from_alice, other_round);
    }

    #[test]
    fn three_party_shares_cancel_to_message() {
        let (alice, bob, carol) = (
            participant("alice"),
            participant("bob"),
            participant("carol"),
        );
        let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];
        let message = b"anonymous hello";

        let a = compute_xor_share(
            &alice.secret,
            &alice.uid,
            &participants,
            &keymap(&[&bob, &carol]),
            Some(message),
            256,
            42,
        )
        .expect("alice share");
        let b = compute_xor_share(
            &bob.secret,
            &bob.uid,
            &participants,
            &keymap(&[&alice, &carol]),
            None,
            256,
            42,
        )
        .expect("bob share");
        let c = compute_xor_share(
            &carol.secret,
            &carol.uid,
            &participants,
            &keymap(&[&alice, &bob]),
            None,
            256,
            42,
        )
        .expect("carol share");

        let global = xor_all(&[a, b, c], 256);
        assert_eq!(unpad_message(&global).as_deref(), Some(&message[..]));
    }

    #[test]
    fn missing_peer_key_refuses_to_participate() {
        let (alice, bob, carol) = (
            participant("alice"),
            participant("bob"),
            participant("carol"),
        );
        let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];
        let partial = keymap(&[&bob]); // carol missing
        assert!(
            compute_xor_share(
                &alice.secret,
                &alice.uid,
                &participants,
                &partial,
                None,
                256,
                1
            )
            .is_err()
        );
    }

    #[test]
    fn non_contributory_peer_key_is_rejected() {
        let alice = participant("alice");
        assert!(derive_pair_share(&alice.secret, &[0u8; 32], 1, "alice", "eve", 32).is_err());
    }

    #[test]
    fn share_signature_binds_channel_round_and_share() {
        let identity = Identity::generate("signer", "dest").expect("identity");
        let share = vec![9u8; 64];
        let signature = sign_share(&identity, "#g", 3, &share).expect("sign");
        let cert = identity.public_cert_bytes().expect("cert");

        assert!(verify_share(&cert, "#g", 3, &share, &signature));
        assert!(!verify_share(&cert, "#other", 3, &share, &signature));
        assert!(!verify_share(&cert, "#g", 4, &share, &signature));
        assert!(!verify_share(&cert, "#g", 3, &[8u8; 64], &signature));
        assert!(!verify_share(&cert, "#g", 3, &share, &[0u8; 4]));
    }

    /// Attack: with N-1 colluders the remaining sender can be attributed.
    ///
    /// The message itself is public to anyone who sees every share (that is
    /// DC-Net extraction); what colluders gain is the ability to recompute
    /// the non-colluder's share and thereby prove that the message came from
    /// that share.
    #[test]
    fn colluding_majority_can_attribute_the_sender() {
        let victim = participant("victim");
        let c1 = participant("colluder1");
        let c2 = participant("colluder2");
        let c3 = participant("colluder3");
        let participants = vec![
            victim.uid.clone(),
            c1.uid.clone(),
            c2.uid.clone(),
            c3.uid.clone(),
        ];
        let message = b"anonymous but not unlinkable from a majority";
        let payload_len = 256;
        let round_id = 9;

        let victim_share = compute_xor_share(
            &victim.secret,
            &victim.uid,
            &participants,
            &keymap(&[&c1, &c2, &c3]),
            Some(message),
            payload_len,
            round_id,
        )
        .expect("victim share");
        let colluder_shares: Vec<Vec<u8>> = [&c1, &c2, &c3]
            .iter()
            .map(|colluder| {
                let others: Vec<&Pair> = [&victim, &c1, &c2, &c3]
                    .into_iter()
                    .filter(|pair| pair.uid != colluder.uid)
                    .collect();
                compute_xor_share(
                    &colluder.secret,
                    &colluder.uid,
                    &participants,
                    &keymap(&others),
                    None,
                    payload_len,
                    round_id,
                )
                .expect("colluder share")
            })
            .collect();

        // Public extraction: XOR every observed share.
        let mut observed = vec![victim_share.clone()];
        observed.extend(colluder_shares.iter().cloned());
        let padded_message = xor_all(&observed, payload_len);
        assert_eq!(
            unpad_message(&padded_message).as_deref(),
            Some(&message[..])
        );

        // Colluders know every pairwise block the victim has (they are its
        // only counterparts), so they can recompute the victim's share and
        // compare it with the observed one.
        let mut recomputed = padded_message.clone();
        for colluder in [&c1, &c2, &c3] {
            let block = derive_pair_share(
                &colluder.secret,
                &victim.public,
                round_id,
                &colluder.uid,
                &victim.uid,
                payload_len,
            )
            .expect("pair block");
            xor_in_place(&mut recomputed, &block);
        }
        assert_eq!(
            recomputed, victim_share,
            "a colluding majority reproduces the sender's share"
        );
    }

    /// Attack: a minority of colluders cannot attribute the sender because
    /// unknown pairwise blocks remain in the recomputation.
    #[test]
    fn colluding_minority_cannot_attribute_the_sender() {
        let victim = participant("victim");
        let c1 = participant("colluder1");
        let c2 = participant("colluder2");
        let bystander = participant("bystander");
        let participants = vec![
            victim.uid.clone(),
            c1.uid.clone(),
            c2.uid.clone(),
            bystander.uid.clone(),
        ];
        let message = b"still unlinkable from a minority";
        let payload_len = 256;
        let round_id = 11;

        let victim_share = compute_xor_share(
            &victim.secret,
            &victim.uid,
            &participants,
            &keymap(&[&c1, &c2, &bystander]),
            Some(message),
            payload_len,
            round_id,
        )
        .expect("victim share");
        let shares: Vec<Vec<u8>> = [&c1, &c2, &bystander]
            .iter()
            .map(|participant| {
                let others: Vec<&Pair> = [&victim, &c1, &c2, &bystander]
                    .into_iter()
                    .filter(|pair| pair.uid != participant.uid)
                    .collect();
                compute_xor_share(
                    &participant.secret,
                    &participant.uid,
                    &participants,
                    &keymap(&others),
                    None,
                    payload_len,
                    round_id,
                )
                .expect("share")
            })
            .collect();

        let mut observed = vec![victim_share.clone()];
        observed.extend(shares.iter().cloned());
        let padded_message = xor_all(&observed, payload_len);

        // The victim's block with the bystander is unknown to the colluders.
        let mut recomputed = padded_message.clone();
        for colluder in [&c1, &c2] {
            let block = derive_pair_share(
                &colluder.secret,
                &victim.public,
                round_id,
                &colluder.uid,
                &victim.uid,
                payload_len,
            )
            .expect("pair block");
            xor_in_place(&mut recomputed, &block);
        }
        assert_ne!(
            recomputed, victim_share,
            "a minority must not reproduce the sender's share"
        );
    }
}
