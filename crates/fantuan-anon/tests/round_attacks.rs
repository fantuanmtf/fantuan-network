//! Adversarial reproductions for round integrity and attribution.
//!
//! Findings A0, R8 and R11 of `docs/ROUND_SYNC_REVIEW.md`. Like the N−1
//! collusion test in `fantuan-anon`, these document current behaviour —
//! including the weaknesses — and must be updated deliberately when the
//! design changes.

use fantuan_anon::{DriverContext, RoundDriver, compute_xor_share, sign_share, verify_share};
use fantuan_identity::Identity;
use fantuan_msg::{DCNET_PAYLOAD_LEN, DcRoundShare, Object};
use std::collections::HashMap;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

struct TestNode {
    identity: Identity,
    uid: String,
    secret: [u8; 32],
    public: [u8; 32],
}

fn node(uid: &str) -> TestNode {
    let identity = Identity::generate(uid, &format!("dest-{uid}")).expect("identity");
    let secret = StaticSecret::random();
    let public = *PublicKey::from(&secret).as_bytes();
    TestNode {
        uid: uid.to_string(),
        identity,
        secret: secret.to_bytes(),
        public,
    }
}

fn maps(nodes: &[&TestNode]) -> (HashMap<String, [u8; 32]>, HashMap<String, Vec<u8>>) {
    let mut noise = HashMap::new();
    let mut certs = HashMap::new();
    for node in nodes {
        noise.insert(node.uid.clone(), node.public);
        certs.insert(
            node.uid.clone(),
            node.identity.public_cert_bytes().expect("cert"),
        );
    }
    (noise, certs)
}

fn context<'a>(
    node: &'a TestNode,
    noise: &'a HashMap<String, [u8; 32]>,
    certs: &'a HashMap<String, Vec<u8>>,
) -> DriverContext<'a> {
    DriverContext {
        identity: &node.identity,
        my_uid: &node.uid,
        noise_secret: &node.secret,
        peer_noise: noise,
        peer_certs: certs,
    }
}

/// A0: the round carries exactly one message, and only the initiator can
/// attach it. A participant's share is byte-for-byte the neutral value, so
/// every participant can attribute the extracted text to the initiator named
/// in the start — with certainty, and without any collusion.
#[test]
fn only_the_initiator_contributes_message_material() {
    let alice = node("alice");
    let bob = node("bob");
    let (noise, certs) = maps(&[&alice, &bob]);
    let ctx_a = context(&alice, &noise, &certs);
    let ctx_b = context(&bob, &noise, &certs);
    let participants = vec![alice.uid.clone(), bob.uid.clone()];

    let mut driver_a = RoundDriver::new();
    let mut driver_b = RoundDriver::new();
    let mut pending = driver_a
        .initiate("#anon", "from alice", &participants, &ctx_a)
        .expect("initiate");
    let round_id = driver_a.current_round_id();

    let mut bob_share: Option<DcRoundShare> = None;
    for _ in 0..16 {
        if pending.is_empty() {
            break;
        }
        let (uid, object) = pending.remove(0);
        let is_alice = uid == alice.uid;
        if let Object::DcRoundShare(share) = &object
            && share.peer_uid == bob.uid
        {
            bob_share = Some(share.clone());
        }
        let driver = if is_alice {
            &mut driver_a
        } else {
            &mut driver_b
        };
        let ctx = if is_alice { &ctx_a } else { &ctx_b };
        let action = driver.handle(&object, ctx);
        pending.extend(action.outgoing);
        pending.extend(driver.drain_pending_outgoing());
    }

    let bob_share = bob_share.expect("bob contributed a share");
    verify_share(
        certs.get(&bob.uid).expect("cert"),
        "#anon",
        round_id,
        &bob_share.xored_payload,
        &bob_share.signature,
    );
    let neutral = compute_xor_share(
        &bob.secret,
        &bob.uid,
        &participants,
        &noise,
        None,
        DCNET_PAYLOAD_LEN,
        round_id,
    )
    .expect("neutral share");
    assert_eq!(
        bob_share.xored_payload.to_vec(),
        neutral,
        "a participant's share is the neutral value: no message material"
    );
}

/// R8: a participant that answers with corrupted bytes jams the round, and is
/// never blamed — the collector completes, the checksum fails, and no share
/// is missing, so no strike is ever attributed.
#[test]
fn a_corrupt_share_jams_the_round_unpunished() {
    let alice = node("alice");
    let bob = node("bob");
    let (noise, certs) = maps(&[&alice, &bob]);
    let ctx_a = context(&alice, &noise, &certs);
    let participants = vec![alice.uid.clone(), bob.uid.clone()];

    let mut driver_a = RoundDriver::new();
    driver_a.set_deadline_secs(1);
    let _ = driver_a
        .initiate("#anon", "jammed", &participants, &ctx_a)
        .expect("initiate");
    let round_id = driver_a.current_round_id();

    let mut corrupted = compute_xor_share(
        &bob.secret,
        &bob.uid,
        &participants,
        &noise,
        None,
        DCNET_PAYLOAD_LEN,
        round_id,
    )
    .expect("neutral share");
    corrupted[0] ^= 0xff;
    let signature =
        sign_share(&bob.identity, "#anon", round_id, &corrupted).expect("sign corrupted share");
    let share = DcRoundShare::new("#anon", round_id, &bob.uid, corrupted, signature);

    let action = driver_a.handle(&Object::DcRoundShare(share), &ctx_a);
    assert!(
        action.extracted.is_empty(),
        "the frame checksum catches the jam: nothing is extracted"
    );

    std::thread::sleep(Duration::from_millis(1_200));
    let failures = driver_a.tick(&ctx_a);
    assert!(
        failures.is_empty(),
        "the jammer is not blamed: every expected share arrived, the bytes were just wrong"
    );
}

/// R11: retry objects are queued into the driver's pending buffer, which only
/// `handle` drains. The node's scheduler tick calls `tick` and
/// `initiate_next` but never `drain_pending_outgoing`, so in a quiet network a
/// retry never reaches the wire.
#[test]
fn retry_objects_are_stranded_until_inbound_traffic_arrives() {
    let alice = node("alice");
    let bob = node("bob");
    let carol = node("carol");
    let (noise, certs) = maps(&[&alice, &bob, &carol]);
    let ctx_a = context(&alice, &noise, &certs);
    let ctx_b = context(&bob, &noise, &certs);
    let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];

    let mut driver_a = RoundDriver::new();
    driver_a.set_deadline_secs(1);
    let mut driver_b = RoundDriver::new();
    let mut pending = driver_a
        .initiate("#anon", "carol stays silent", &participants, &ctx_a)
        .expect("initiate");
    let first_id = driver_a.current_round_id();

    // Bob answers; carol does not, so the round expires as a partial response.
    let mut rounds = 0;
    while !pending.is_empty() && rounds < 16 {
        rounds += 1;
        let (uid, object) = pending.remove(0);
        let is_alice = uid == alice.uid;
        let driver = if is_alice {
            &mut driver_a
        } else {
            &mut driver_b
        };
        let ctx = if is_alice { &ctx_a } else { &ctx_b };
        let action = driver.handle(&object, ctx);
        pending.extend(action.outgoing);
        pending.extend(driver.drain_pending_outgoing());
    }
    drop(pending);

    std::thread::sleep(Duration::from_millis(1_200));
    let failures = driver_a.tick(&ctx_a);
    assert_eq!(
        failures
            .iter()
            .map(|f| f.missing.clone())
            .collect::<Vec<_>>(),
        vec![vec![carol.uid.clone()]],
        "the silent participant is reported"
    );
    assert!(
        driver_a.current_round_id() > first_id,
        "a retry round was started"
    );

    // `tick` returns no objects: the retry start is sitting in the driver's
    // pending buffer. Only `handle` drains that buffer, and the node's
    // scheduler (`anon::tick`) never calls it.
    let flushed = driver_a.handle(&Object::Pong { timestamp: 0 }, &ctx_a);
    assert!(
        !flushed.outgoing.is_empty(),
        "the retry start leaves the driver only when an inbound object arrives"
    );
    assert!(
        driver_a.drain_pending_outgoing().is_empty(),
        "those objects were the retry: the buffer is empty afterwards"
    );
}
