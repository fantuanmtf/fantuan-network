//! Relay resilience: a restarted sender, and rejections that must not close
//! the session.
//!
//! These are the Phase 7 exit tests for findings D1 and D2
//! (`docs/ROADMAP.md` §4.2). Both use duplex streams instead of I2P so they
//! run in CI without a router, and both drive the real connection loop.

use fantuan_core::config::NodeConfig;
use fantuan_core::time;
use fantuan_identity::{Identity, TrustStore, encrypt_for, keys::cert_from_bytes};
use fantuan_msg::{Message, Object, RELAY_MAX_HOPS, Relay};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::store::MessageStore;
use fantuan_node::{connection, peer, relay};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A node whose identity and data directory survive a restart.
struct Restartable {
    dir: TempDir,
    identity: Arc<Identity>,
    fingerprint: String,
    nonce_path: PathBuf,
    config: NodeConfig,
}

impl Restartable {
    fn new(uid: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Arc::new(Identity::generate(uid, &format!("dest-{uid}")).expect("identity"));
        let fingerprint = identity.fingerprint_hex();
        let config = NodeConfig {
            handshake_timeout_secs: 5,
            idle_timeout_secs: 30,
            ..NodeConfig::default()
        };
        let nonce_path = dir.path().join("relay.nonce");
        Self {
            dir,
            identity,
            fingerprint,
            nonce_path,
            config,
        }
    }

    /// Start one incarnation of the process: fresh runtime state, same
    /// identity, same data directory, same nonce reservation file.
    fn start(&self) -> TestNode {
        let trust = TrustStore::open(&self.dir.path().join("trust.sqlite")).expect("trust");
        let messages = MessageStore::in_memory().expect("messages");
        let chunks = fantuan_storage::ChunkCache::in_memory(1 << 20).expect("chunks");
        let (events_tx, events) = mpsc::unbounded_channel();
        let state = NodeState::new(
            self.identity.clone(),
            self.config.clone(),
            trust,
            messages,
            chunks,
            events_tx,
            Some(self.nonce_path.clone()),
        );
        TestNode { state, events }
    }
}

struct TestNode {
    state: Arc<NodeState>,
    events: mpsc::UnboundedReceiver<NodeEvent>,
}

fn connect(left: &TestNode, right: &TestNode) -> Vec<JoinHandle<()>> {
    let (left_side, right_side) = tokio::io::duplex(1 << 20);
    let left_state = left.state.clone();
    let right_state = right.state.clone();
    vec![
        tokio::spawn(async move {
            let mut stream = left_side;
            let peer =
                peer::handshake_client(&mut stream, &left_state.identity, Duration::from_secs(5))
                    .await
                    .expect("client handshake");
            let _ = connection::run(left_state, stream, peer).await;
        }),
        tokio::spawn(async move {
            let mut stream = right_side;
            let peer =
                peer::handshake_server(&mut stream, &right_state.identity, Duration::from_secs(5))
                    .await
                    .expect("server handshake");
            let _ = connection::run(right_state, stream, peer).await;
        }),
    ]
}

async fn wait_for_route(node: &TestNode, destination: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.state.next_hop(destination).is_none() {
        assert!(
            Instant::now() < deadline,
            "node never learned a route to {destination}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait for a delivered message; panics on timeout.
async fn recv_text(node: &mut TestNode) -> String {
    let event = tokio::time::timeout(Duration::from_secs(5), node.events.recv())
        .await
        .expect("delivery timeout")
        .expect("event channel");
    match event {
        NodeEvent::Message { text, .. } => text,
        other => panic!("unexpected event: {other:?}"),
    }
}

/// True when no event arrives within the quiet window.
async fn quiet(node: &mut TestNode) -> bool {
    tokio::time::timeout(Duration::from_millis(400), node.events.recv())
        .await
        .is_err()
}

/// Build the exact bytes of one relay envelope.
fn relay_bytes(
    sender: &TestNode,
    recipient: &Restartable,
    text: &str,
    nonce: u64,
    timestamp: u64,
) -> Vec<u8> {
    let cert = cert_from_bytes(&recipient.identity.descriptor().openpgp_cert).expect("cert");
    let inner =
        Object::Message(Message::create(&sender.state.identity, text.as_bytes()).expect("message"))
            .to_canonical_bytes()
            .expect("inner");
    let payload = encrypt_for(&cert, &inner).expect("encrypt");
    let envelope = Relay::create_with_hops(
        &sender.state.identity,
        &recipient.fingerprint,
        nonce,
        timestamp,
        RELAY_MAX_HOPS,
        payload,
    )
    .expect("relay");
    Object::Relay(envelope).to_canonical_bytes().expect("bytes")
}

#[tokio::test]
async fn relay_survives_a_sender_restart() {
    let alice = Restartable::new("alice");
    let bob = Restartable::new("bob");
    let mut bob_node = bob.start();

    let first = alice.start();
    let tasks = connect(&first, &bob_node);
    wait_for_route(&first, &bob.fingerprint).await;
    relay::send_message(&first.state, &bob.fingerprint, "before restart").expect("relay");
    assert_eq!(recv_text(&mut bob_node).await, "before restart");

    // Alice restarts; Bob stays up, so the nonce high-water mark he recorded
    // for Alice is whatever her first incarnation reached.
    for task in tasks {
        task.abort();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let second = alice.start();
    let _tasks = connect(&second, &bob_node);
    wait_for_route(&second, &bob.fingerprint).await;
    relay::send_message(&second.state, &bob.fingerprint, "after restart").expect("relay");
    assert_eq!(
        recv_text(&mut bob_node).await,
        "after restart",
        "a restarted node must not be mistaken for a replayer"
    );
}

#[tokio::test]
async fn rejected_relays_keep_the_session_alive() {
    let alice = Restartable::new("alice");
    let bob = Restartable::new("bob");
    let mut bob_node = bob.start();
    let alice_node = alice.start();
    let _tasks = connect(&alice_node, &bob_node);
    wait_for_route(&alice_node, &bob.fingerprint).await;

    // An envelope outside the freshness window: rejected, dropped, session up.
    let expired = relay_bytes(
        &alice_node,
        &bob,
        "expired",
        alice_node.state.next_relay_nonce(),
        time::now_unix() - 3600,
    );
    alice_node
        .state
        .pool
        .try_send(&bob.fingerprint, expired)
        .expect("send expired");
    assert!(
        quiet(&mut bob_node).await,
        "an expired relay must be dropped"
    );

    // A valid envelope, then the identical bytes again: the second is a
    // replay and must be dropped too.
    let bytes = relay_bytes(
        &alice_node,
        &bob,
        "first",
        alice_node.state.next_relay_nonce(),
        time::now_unix(),
    );
    alice_node
        .state
        .pool
        .try_send(&bob.fingerprint, bytes.clone())
        .expect("send first");
    assert_eq!(recv_text(&mut bob_node).await, "first");
    alice_node
        .state
        .pool
        .try_send(&bob.fingerprint, bytes)
        .expect("replay");
    assert!(
        quiet(&mut bob_node).await,
        "a replayed relay must be dropped"
    );

    // The session survived both rejections, which is the point: before this
    // fix either one tore the connection down.
    relay::send_message(&alice_node.state, &bob.fingerprint, "after rejections").expect("relay");
    assert_eq!(recv_text(&mut bob_node).await, "after rejections");
}
