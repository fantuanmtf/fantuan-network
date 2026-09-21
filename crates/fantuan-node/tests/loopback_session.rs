//! Local end-to-end session tests over in-memory duplex streams.
//!
//! These exercise the same handshake, identity binding and object loop the
//! node uses on real I2P connections.

use fantuan_identity::Identity;
use fantuan_msg::{Message, Object};
use fantuan_node::peer;
use std::time::Duration;

/// Generate an identity and return it with its fingerprint.
fn identity(uid: &str) -> (Identity, String) {
    let identity = Identity::generate(uid, &format!("dest-{uid}")).expect("identity");
    let fingerprint = identity.fingerprint_hex();
    (identity, fingerprint)
}

#[tokio::test]
async fn handshake_binding_and_message_roundtrip() {
    let (alice, alice_fingerprint) = identity("alice");
    let (bob, _bob_fingerprint) = identity("bob");
    let (mut client, mut server) = tokio::io::duplex(256 * 1024);

    let server_task = tokio::spawn(async move {
        let mut peer = peer::handshake_server(&mut server, &bob, Duration::from_secs(5))
            .await
            .expect("server handshake");
        assert_eq!(peer.uid(), "alice");
        assert_eq!(peer.fingerprint(), alice_fingerprint);

        let bytes = peer.session.recv(&mut server).await.expect("receive");
        match Object::from_canonical_bytes(&bytes).expect("decode") {
            Object::Message(message) => {
                message.verify(&peer.cert).expect("message verifies");
                String::from_utf8_lossy(&message.payload).to_string()
            }
            other => panic!("unexpected object: {other:?}"),
        }
    });

    let mut peer = peer::handshake_client(&mut client, &alice, Duration::from_secs(5))
        .await
        .expect("client handshake");
    assert_eq!(peer.uid(), "bob");

    let message = Message::create(&alice, b"hello over noise").expect("message");
    let bytes = Object::Message(message)
        .to_canonical_bytes()
        .expect("encode");
    peer.session.send(&mut client, &bytes).await.expect("send");

    let text = server_task.await.expect("server task");
    assert_eq!(text, "hello over noise");
}

#[tokio::test]
async fn ping_is_answered_with_pong() {
    let (alice, _alice_fingerprint) = identity("alice");
    let (bob, _bob_fingerprint) = identity("bob");
    let (mut client, mut server) = tokio::io::duplex(256 * 1024);

    let server_task = tokio::spawn(async move {
        let mut peer = peer::handshake_server(&mut server, &bob, Duration::from_secs(5))
            .await
            .expect("server handshake");
        let bytes = peer.session.recv(&mut server).await.expect("receive");
        match Object::from_canonical_bytes(&bytes).expect("decode") {
            Object::Ping { timestamp, .. } => {
                let pong = Object::Pong { timestamp }
                    .to_canonical_bytes()
                    .expect("encode");
                peer.session.send(&mut server, &pong).await.expect("send");
                timestamp
            }
            other => panic!("unexpected object: {other:?}"),
        }
    });

    let mut peer = peer::handshake_client(&mut client, &alice, Duration::from_secs(5))
        .await
        .expect("client handshake");
    let timestamp = 1_234_567u64;
    let ping = Object::Ping {
        nonce: 9,
        timestamp,
    }
    .to_canonical_bytes()
    .expect("encode");
    peer.session.send(&mut client, &ping).await.expect("send");

    let reply = peer.session.recv(&mut client).await.expect("receive");
    match Object::from_canonical_bytes(&reply).expect("decode") {
        Object::Pong { timestamp: echoed } => assert_eq!(echoed, timestamp),
        other => panic!("unexpected reply: {other:?}"),
    }
    assert_eq!(server_task.await.expect("server task"), timestamp);
}

#[tokio::test]
async fn message_signed_by_a_third_party_is_rejected() {
    let (alice, _) = identity("alice");
    let (bob, _) = identity("bob");
    let (mallory, _) = identity("mallory");
    let (mut client, mut server) = tokio::io::duplex(256 * 1024);

    let server_task = tokio::spawn(async move {
        let mut peer = peer::handshake_server(&mut server, &bob, Duration::from_secs(5))
            .await
            .expect("server handshake");
        let bytes = peer.session.recv(&mut server).await.expect("receive");
        match Object::from_canonical_bytes(&bytes).expect("decode") {
            Object::Message(message) => message.verify(&peer.cert).is_err(),
            other => panic!("unexpected object: {other:?}"),
        }
    });

    let mut peer = peer::handshake_client(&mut client, &alice, Duration::from_secs(5))
        .await
        .expect("client handshake");
    // Alice's session, but the message is signed by Mallory.
    let forged = Message::create(&mallory, b"not alice").expect("message");
    let bytes = Object::Message(forged)
        .to_canonical_bytes()
        .expect("encode");
    peer.session.send(&mut client, &bytes).await.expect("send");

    assert!(
        server_task.await.expect("server task"),
        "a message signed by a third party must fail verification"
    );
}
