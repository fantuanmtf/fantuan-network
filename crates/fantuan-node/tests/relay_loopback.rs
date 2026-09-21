//! In-memory three-node test: A and C connect through B, learn each other
//! through gossip, then A relays an end-to-end encrypted message to C.
//!
//! Uses duplex streams instead of I2P so it runs in CI without a router.

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::{connection, peer, relay};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .try_init();
    });
}

struct TestNode {
    state: Arc<NodeState>,
    events: mpsc::UnboundedReceiver<NodeEvent>,
    fingerprint: String,
    _dir: TempDir,
}

impl TestNode {
    fn new(uid: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Arc::new(Identity::generate(uid, &format!("dest-{uid}")).expect("identity"));
        let fingerprint = identity.fingerprint_hex();
        let trust = TrustStore::open(&dir.path().join("trust.sqlite")).expect("trust");
        let (events_tx, events) = mpsc::unbounded_channel();
        let config = NodeConfig {
            handshake_timeout_secs: 5,
            idle_timeout_secs: 30,
            ..NodeConfig::default()
        };
        let state = NodeState::new(identity, config, trust, events_tx);
        Self {
            state,
            events,
            fingerprint,
            _dir: dir,
        }
    }
}

fn spawn_client(state: Arc<NodeState>, mut stream: tokio::io::DuplexStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        let peer = peer::handshake_client(&mut stream, &state.identity, Duration::from_secs(5))
            .await
            .expect("client handshake");
        if let Err(error) = connection::run(state, stream, peer).await {
            tracing::debug!("client connection ended: {error:#}");
        }
    })
}

fn spawn_server(state: Arc<NodeState>, mut stream: tokio::io::DuplexStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        let peer = peer::handshake_server(&mut stream, &state.identity, Duration::from_secs(5))
            .await
            .expect("server handshake");
        if let Err(error) = connection::run(state, stream, peer).await {
            tracing::debug!("server connection ended: {error:#}");
        }
    })
}

async fn wait_for_route(node: &TestNode, destination: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.state.next_hop(destination).is_none() {
        assert!(
            Instant::now() < deadline,
            "node never learned a route to {destination}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn three_nodes_relay_message_through_middle() {
    init_tracing();
    let alice = TestNode::new("alice");
    let bob = TestNode::new("bob");
    let mut carol = TestNode::new("carol");
    // A <-> B and C <-> B.
    let (alice_side, bob_side_a) = tokio::io::duplex(1 << 20);
    let (carol_side, bob_side_c) = tokio::io::duplex(1 << 20);
    let tasks = vec![
        spawn_client(alice.state.clone(), alice_side),
        spawn_server(bob.state.clone(), bob_side_a),
        spawn_client(carol.state.clone(), carol_side),
        spawn_server(bob.state.clone(), bob_side_c),
    ];

    // Gossip must give Alice a route to Carol (via Bob).
    wait_for_route(&alice, &carol.fingerprint).await;
    wait_for_route(&carol, &alice.fingerprint).await;

    relay::send_message(&alice.state, &carol.fingerprint, "hello carol via bob")
        .expect("send relay");

    let event = tokio::time::timeout(Duration::from_secs(5), carol.events.recv())
        .await
        .expect("delivery timeout")
        .expect("event channel");
    match event {
        NodeEvent::Message { from, text } => {
            assert_eq!(from, alice.fingerprint);
            assert_eq!(text, "hello carol via bob");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn relay_without_route_fails() {
    let alice = TestNode::new("alice");
    let result = relay::send_message(
        &alice.state,
        "0000000000000000000000000000000000000000",
        "nope",
    );
    assert!(result.is_err(), "unknown destination must not be relayed");
}

#[tokio::test]
async fn gossip_descriptors_are_signature_verified() {
    let alice = TestNode::new("alice");
    let bob = TestNode::new("bob");
    let (alice_side, bob_side) = tokio::io::duplex(1 << 20);
    let tasks = vec![
        spawn_client(alice.state.clone(), alice_side),
        spawn_server(bob.state.clone(), bob_side),
    ];

    wait_for_route(&alice, &bob.fingerprint).await;
    wait_for_route(&bob, &alice.fingerprint).await;

    // Both stores now hold the other side's signed descriptor.
    {
        let store = alice.state.trust.lock().unwrap();
        let (descriptor, signature) = store
            .descriptor_of(&bob.fingerprint)
            .expect("query")
            .expect("bob descriptor stored");
        let parsed = fantuan_identity::Descriptor::from_canonical(&descriptor).expect("parse");
        parsed
            .verify(&signature)
            .expect("descriptor self-signature");
    }

    for task in tasks {
        task.abort();
    }
}
