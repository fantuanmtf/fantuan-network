//! Real I2P integration tests: nodes connect over SAM, exchange signed
//! messages and relay through a middle node.
//!
//! Requires a local i2pd with SAM enabled. Run with:
//!
//! ```text
//! cargo test -p fantuan-node --features i2p-integration -- --ignored
//! ```

#![cfg(feature = "i2p-integration")]

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_msg::{Message, Object};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::{connection, peer};
use fantuan_transport::sam::{SamConfig, SamSession, generate_destination};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

fn sam() -> SamConfig {
    SamConfig::from_addr(&NodeConfig::default().sam_addr).expect("sam config")
}

#[tokio::test]
#[ignore = "requires a local i2pd router with SAM enabled"]
async fn two_nodes_exchange_a_signed_message_over_i2p() {
    let pid = std::process::id();
    let base = sam();

    // Server destination + identity.
    let init = SamConfig {
        nickname: format!("fantuan-it-init-{pid}"),
        ..base.clone()
    };
    let (server_destination, server_key) = generate_destination(&init)
        .await
        .expect("generate destination");
    let (server_identity, _) = identity("i2p-server", &server_destination);

    // Server session accepts one connection.
    let server_config = SamConfig {
        nickname: format!("fantuan-it-server-{pid}"),
        publish: true,
        ..base.clone()
    };
    let server_task = tokio::spawn(async move {
        let mut session = SamSession::open(&server_config, Some(&server_key))
            .await
            .expect("server session");
        let mut stream = session.accept().await.expect("accept");
        let mut peer =
            peer::handshake_server(&mut stream, &server_identity, Duration::from_secs(180))
                .await
                .expect("server handshake");
        let bytes = peer.session.recv(&mut stream).await.expect("receive");
        match Object::from_canonical_bytes(&bytes).expect("decode") {
            Object::Message(message) => {
                message.verify(&peer.cert).expect("verify");
                String::from_utf8_lossy(&message.payload).to_string()
            }
            other => panic!("unexpected object: {other:?}"),
        }
    });

    // Client session connects out, retrying while the server's lease set
    // propagates and its tunnels are built.
    let (client_identity, _) = identity("i2p-client", "unused");
    let client_config = SamConfig {
        nickname: format!("fantuan-it-client-{pid}"),
        publish: false,
        ..base
    };
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut session = SamSession::open(&client_config, None)
        .await
        .expect("client session");
    let mut stream = connect_with_retry(&mut session, &server_destination).await;
    let mut peer = peer::handshake_client(&mut stream, &client_identity, Duration::from_secs(180))
        .await
        .expect("client handshake");

    let message = Message::create(&client_identity, b"hello over real i2p").expect("message");
    let bytes = Object::Message(message)
        .to_canonical_bytes()
        .expect("encode");
    peer.session.send(&mut stream, &bytes).await.expect("send");

    let received = tokio::time::timeout(Duration::from_secs(60), server_task)
        .await
        .expect("server task timeout")
        .expect("server task");
    assert_eq!(received, "hello over real i2p");
}

fn identity(uid: &str, destination: &str) -> (Identity, String) {
    let identity = Identity::generate(uid, destination).expect("identity");
    let fingerprint = identity.fingerprint_hex();
    (identity, fingerprint)
}

/// Retry `STREAM CONNECT` until the server becomes reachable.
async fn connect_with_retry(session: &mut SamSession, destination: &str) -> yosemite::Stream {
    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    loop {
        let error = match session.connect(destination).await {
            Ok(stream) => return stream,
            Err(error) => error,
        };
        tracing::warn!("connect attempt failed: {error}");
        if std::time::Instant::now() >= deadline {
            panic!("i2p connect never succeeded: {error:?}");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn node_state(
    uid: &str,
) -> (
    Arc<NodeState>,
    tempfile::TempDir,
    mpsc::UnboundedReceiver<NodeEvent>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = Arc::new(Identity::generate(uid, &format!("dest-{uid}")).expect("identity"));
    let trust = TrustStore::open(&dir.path().join("trust.sqlite")).expect("trust");
    let (events_tx, events) = mpsc::unbounded_channel();
    let config = NodeConfig {
        handshake_timeout_secs: 180,
        idle_timeout_secs: 120,
        ..NodeConfig::default()
    };
    (
        NodeState::new(identity, config, trust, events_tx),
        dir,
        events,
    )
}

fn pin(state: &Arc<NodeState>, peer: &peer::BoundPeer) {
    let store = state.trust.lock().expect("trust lock");
    store
        .upsert_peer(
            peer.fingerprint(),
            peer.uid(),
            &peer.public_key_hex(),
            fantuan_core::time::now_unix(),
        )
        .expect("pin peer");
}

fn connect_node(
    state: Arc<NodeState>,
    destination: String,
    base: SamConfig,
    label: String,
    pid: u32,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let config = SamConfig {
            nickname: format!("fantuan-{label}-{pid}"),
            publish: false,
            ..base
        };
        let mut session = SamSession::open(&config, None).await.expect("session");
        let mut stream = connect_with_retry(&mut session, &destination).await;
        let peer = peer::handshake_client(&mut stream, &state.identity, Duration::from_secs(180))
            .await
            .expect("handshake");
        pin(&state, &peer);
        if let Err(error) = connection::run(state, stream, peer).await {
            tracing::warn!("i2p connection ended: {error:#}");
        }
    })
}

async fn wait_for_route(state: &Arc<NodeState>, destination: &str, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while state.next_hop(destination).is_none() {
        assert!(
            Instant::now() < deadline,
            "{label} never learned a route to {destination}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Three nodes over real I2P: A and C connect to B, learn each other through
/// gossip, and A relays an end-to-end encrypted message to C.
#[tokio::test]
#[ignore = "requires a local i2pd router with SAM enabled"]
async fn three_nodes_relay_over_i2p() {
    let pid = std::process::id();
    let base = sam();

    let (alice_state, _alice_dir, _alice_events) = node_state("i2p3-alice");
    let (bob_state, _bob_dir, _bob_events) = node_state("i2p3-bob");
    let (carol_state, _carol_dir, mut carol_events) = node_state("i2p3-carol");
    let alice_fp = alice_state.fingerprint();
    let carol_fp = carol_state.fingerprint();

    // Bob accepts inbound connections.
    let mut bob_session = SamSession::open(
        &SamConfig {
            nickname: format!("fantuan-it3-bob-{pid}"),
            publish: true,
            ..base.clone()
        },
        None,
    )
    .await
    .expect("bob session");
    let bob_destination = bob_session.destination().to_string();

    let bob_accept_state = bob_state.clone();
    let bob_accept = tokio::spawn(async move {
        loop {
            let Ok(mut stream) = bob_session.accept().await else {
                break;
            };
            let state = bob_accept_state.clone();
            tokio::spawn(async move {
                let Ok(peer) =
                    peer::handshake_server(&mut stream, &state.identity, Duration::from_secs(180))
                        .await
                else {
                    return;
                };
                pin(&state, &peer);
                let _ = connection::run(state, stream, peer).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
    let alice_task = connect_node(
        alice_state.clone(),
        bob_destination.clone(),
        base.clone(),
        "it3-alice".to_string(),
        pid,
    );
    let carol_task = connect_node(
        carol_state.clone(),
        bob_destination.clone(),
        base,
        "it3-carol".to_string(),
        pid,
    );

    wait_for_route(&alice_state, &carol_fp, "alice").await;
    wait_for_route(&carol_state, &alice_fp, "carol").await;

    fantuan_node::relay::send_message(&alice_state, &carol_fp, "hello over i2p via bob")
        .expect("send relay");

    let event = tokio::time::timeout(Duration::from_secs(120), carol_events.recv())
        .await
        .expect("delivery timeout")
        .expect("event channel");
    match event {
        NodeEvent::Message { from, text } => {
            assert_eq!(from, alice_fp);
            assert_eq!(text, "hello over i2p via bob");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    alice_task.abort();
    carol_task.abort();
    bob_accept.abort();
}
