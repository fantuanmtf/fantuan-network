//! Full-mesh DC-Net rounds: three nodes each extract the anonymous message.

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::store::MessageStore;
use fantuan_node::{anon, connection, peer};
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

async fn connect_pair(left: &TestNode, right: &TestNode) -> Vec<JoinHandle<()>> {
    let (left_side, right_side) = tokio::io::duplex(1 << 20);
    vec![
        spawn_client(left.state.clone(), left_side),
        spawn_server(right.state.clone(), right_side),
    ]
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
async fn three_node_full_mesh_extracts_anonymous_message() {
    let mut alice = TestNode::new("alice");
    let mut bob = TestNode::new("bob");
    let mut carol = TestNode::new("carol");

    let mut tasks = Vec::new();
    tasks.extend(connect_pair(&alice, &bob).await);
    tasks.extend(connect_pair(&alice, &carol).await);
    tasks.extend(connect_pair(&bob, &carol).await);

    wait_for_route(&alice, &bob.fingerprint).await;
    wait_for_route(&alice, &carol.fingerprint).await;
    wait_for_route(&bob, &carol.fingerprint).await;

    anon::queue(&alice.state, "#anon", "anonymous hello").expect("queue");

    // Drive the scheduler manually until all three nodes deliver.
    let mut bob_text: Option<String> = None;
    let mut carol_text: Option<String> = None;
    let mut alice_text: Option<String> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while (alice_text.is_none() || bob_text.is_none() || carol_text.is_none())
        && tokio::time::Instant::now() < deadline
    {
        anon::tick(&alice.state).expect("alice tick");
        anon::tick(&bob.state).expect("bob tick");
        anon::tick(&carol.state).expect("carol tick");

        for (receiver, slot) in [
            (&mut alice.events, &mut alice_text),
            (&mut bob.events, &mut bob_text),
            (&mut carol.events, &mut carol_text),
        ] {
            while let Ok(event) = receiver.try_recv() {
                if let NodeEvent::Anonymous { text, .. } = event {
                    *slot = Some(text);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(alice_text.as_deref(), Some("anonymous hello"));
    assert_eq!(bob_text.as_deref(), Some("anonymous hello"));
    assert_eq!(carol_text.as_deref(), Some("anonymous hello"));

    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn evicted_peer_is_excluded_from_rounds() {
    let alice = TestNode::new("alice");
    let bob = TestNode::new("bob");
    let carol = TestNode::new("carol");

    let mut tasks = Vec::new();
    tasks.extend(connect_pair(&alice, &bob).await);
    tasks.extend(connect_pair(&alice, &carol).await);
    wait_for_route(&alice, &bob.fingerprint).await;
    wait_for_route(&alice, &carol.fingerprint).await;

    assert!(anon::participants(&alice.state).contains(&carol.fingerprint));

    {
        let mut reputation = alice.state.reputation.lock().expect("reputation");
        for _ in 0..fantuan_anon::MAX_STRIKES {
            reputation.penalize(&carol.fingerprint);
        }
    }
    let participants = anon::participants(&alice.state);
    assert!(!participants.contains(&carol.fingerprint));
    assert!(participants.contains(&alice.fingerprint));
    assert!(participants.contains(&bob.fingerprint));

    for task in tasks {
        task.abort();
    }
}
