//! DC-Net rounds in a network that is *not* a full mesh.
//!
//! Topology: alice, bob and carol form a triangle; dave is attached to alice
//! only. Rounds are mesh-only (shares are never relayed), so a round runs
//! among a connected subset — and a node that observes none of those rounds
//! must still be able to start one of its own afterwards.
//!
//! That last property is the Phase 7 exit test for finding D3
//! (`docs/ROADMAP.md` §4.2): with a `current + 1` round counter, dave sits at
//! round 0 while alice is at round *n*, every start he sends is rejected as
//! stale, and he can never initiate again for the life of the process.

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
        let state = NodeState::new(identity, config, trust, messages, chunks, events_tx, None);
        Self {
            state,
            events,
            fingerprint,
            _dir: dir,
        }
    }

    /// Drain anonymous messages extracted so far.
    fn drain_anonymous(&mut self) -> Vec<String> {
        let mut texts = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            if let NodeEvent::Anonymous { text, .. } = event {
                texts.push(text);
            }
        }
        texts
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

fn connect_pair(left: &TestNode, right: &TestNode) -> Vec<JoinHandle<()>> {
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
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn a_node_outside_the_rounds_can_still_initiate() {
    let mut alice = TestNode::new("alice");
    let mut bob = TestNode::new("bob");
    let mut carol = TestNode::new("carol");
    let mut dave = TestNode::new("dave");

    let mut tasks = Vec::new();
    tasks.extend(connect_pair(&alice, &bob));
    tasks.extend(connect_pair(&alice, &carol));
    tasks.extend(connect_pair(&bob, &carol));
    tasks.extend(connect_pair(&alice, &dave));

    for (node, other) in [
        (&alice, &bob),
        (&alice, &carol),
        (&alice, &dave),
        (&bob, &carol),
    ] {
        wait_for_route(node, &other.fingerprint).await;
    }

    // Phase A: bob starts a round among the triangle. Dave is connected to
    // alice but is not a participant, so he sees none of it.
    anon::queue(&bob.state, "#anon", "from bob").expect("queue");
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut alice_text, mut bob_text, mut carol_text) = (None, None, None);
    while (alice_text.is_none() || bob_text.is_none() || carol_text.is_none())
        && Instant::now() < deadline
    {
        for state in [&alice.state, &bob.state, &carol.state, &dave.state] {
            anon::tick(state).expect("tick");
        }
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
    assert_eq!(alice_text.as_deref(), Some("from bob"), "triangle member");
    assert_eq!(bob_text.as_deref(), Some("from bob"), "initiator");
    assert_eq!(carol_text.as_deref(), Some("from bob"), "triangle member");
    assert!(
        dave.drain_anonymous().is_empty(),
        "a node outside the participant set must not receive the round"
    );

    // Phase B: dave, who has observed no round at all, starts one with his own
    // participant set. Alice must accept it: a lagging node is not a stale one.
    anon::queue(&dave.state, "#anon", "from dave").expect("queue");
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut dave_text, mut alice_second) = (None, None);
    while (dave_text.is_none() || alice_second.is_none()) && Instant::now() < deadline {
        for state in [&alice.state, &bob.state, &carol.state, &dave.state] {
            anon::tick(state).expect("tick");
        }
        for (receiver, slot) in [
            (&mut dave.events, &mut dave_text),
            (&mut alice.events, &mut alice_second),
        ] {
            while let Ok(event) = receiver.try_recv() {
                if let NodeEvent::Anonymous { text, .. } = event {
                    *slot = Some(text);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(dave_text.as_deref(), Some("from dave"), "lagging initiator");
    assert_eq!(
        alice_second.as_deref(),
        Some("from dave"),
        "a peer that observed the earlier rounds must still accept the start"
    );
    assert!(
        bob.drain_anonymous().is_empty(),
        "bob is not in dave's participant set"
    );
    assert!(
        carol.drain_anonymous().is_empty(),
        "carol is not in dave's participant set"
    );

    for task in tasks {
        task.abort();
    }
}
