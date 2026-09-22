//! Offline delivery: a node that was disconnected catches up on channel
//! messages and forum posts through history sync when it reconnects.

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::store::MessageStore;
use fantuan_node::{connection, peer, social};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
        let messages = MessageStore::in_memory().expect("messages");
        let chunks = fantuan_storage::ChunkCache::in_memory(1 << 20).expect("chunks");
        let (events_tx, events) = mpsc::unbounded_channel();
        let config = NodeConfig {
            channels: vec!["#general".to_string()],
            boards: vec!["bbs".to_string()],
            handshake_timeout_secs: 5,
            idle_timeout_secs: 30,
            ..NodeConfig::default()
        };
        let state = NodeState::new(identity, config, trust, messages, chunks, events_tx);
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
async fn offline_messages_are_delivered_on_reconnect() {
    let alice = TestNode::new("alice");
    let bob = TestNode::new("bob");
    let mut carol = TestNode::new("carol");

    // A <-> B and C <-> B.
    let (alice_side, bob_side_a) = tokio::io::duplex(1 << 20);
    let (carol_side, bob_side_c) = tokio::io::duplex(1 << 20);
    let first_tasks = vec![
        spawn_client(alice.state.clone(), alice_side),
        spawn_server(bob.state.clone(), bob_side_a),
        spawn_client(carol.state.clone(), carol_side),
        spawn_server(bob.state.clone(), bob_side_c),
    ];
    wait_for_route(&alice, &bob.fingerprint).await;
    wait_for_route(&alice, &carol.fingerprint).await;

    // Carol goes offline.
    first_tasks[2].abort();
    first_tasks[3].abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Traffic happens while Carol is away.
    social::publish_channel(&alice.state, "#general", "while you were away").expect("channel");
    social::publish_forum(&alice.state, "bbs", "Offline", "posted while you were out")
        .expect("forum");

    // Carol reconnects; history sync must deliver both.
    let (carol_side2, bob_side_c2) = tokio::io::duplex(1 << 20);
    let second_tasks = vec![
        spawn_client(carol.state.clone(), carol_side2),
        spawn_server(bob.state.clone(), bob_side_c2),
    ];

    let mut saw_channel = false;
    let mut saw_forum = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !(saw_channel && saw_forum) {
        let event = tokio::time::timeout_at(deadline, carol.events.recv())
            .await
            .expect("history delivery timeout")
            .expect("event channel");
        match event {
            NodeEvent::Channel { text, .. } => {
                assert_eq!(text, "while you were away");
                saw_channel = true;
            }
            NodeEvent::Forum { title, .. } => {
                assert_eq!(title, "Offline");
                saw_forum = true;
            }
            _ => {}
        }
    }

    for task in first_tasks {
        task.abort();
    }
    for task in second_tasks {
        task.abort();
    }
}
