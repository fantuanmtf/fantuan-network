//! Control socket end-to-end tests: two clients chat, post and read through
//! the same node.

use fantuan_client::control::{ControlClient, Event};
use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::state::NodeState;
use fantuan_node::store::MessageStore;
use fantuan_node::{control, social};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};

struct TestNode {
    state: Arc<NodeState>,
    dir: TempDir,
}

impl TestNode {
    fn new(channels: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Arc::new(Identity::generate("control-node", "dest").expect("identity"));
        let trust = TrustStore::open(&dir.path().join("trust.sqlite")).expect("trust");
        let messages = MessageStore::in_memory().expect("messages");
        let chunks = fantuan_storage::ChunkCache::in_memory(1 << 20).expect("chunks");
        let (events_tx, _events) = mpsc::unbounded_channel();
        let config = NodeConfig {
            channels: channels.iter().map(|c| c.to_string()).collect(),
            ..NodeConfig::default()
        };
        let state = NodeState::new(identity, config, trust, messages, chunks, events_tx);
        Self { state, dir }
    }
}

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("control socket was never created");
}

#[tokio::test]
async fn two_clients_chat_and_read() {
    let node = TestNode::new(&["#general"]);
    let socket = node.dir.path().join("control.sock");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let serve_socket = socket.clone();
    let serve_state = node.state.clone();
    tokio::spawn(async move {
        let _ = control::serve(serve_state, serve_socket, shutdown_rx).await;
    });
    wait_for_socket(&socket).await;

    let mut alice = ControlClient::connect(&socket).await.expect("alice");
    let mut bob = ControlClient::connect(&socket).await.expect("bob");

    let status = alice.status().await.expect("status");
    assert!(status.channels.contains(&"#general".to_string()));

    bob.subscribe_events().await.expect("subscribe");
    alice
        .post("#general", "hello from alice")
        .await
        .expect("post");

    let event = tokio::time::timeout(Duration::from_secs(5), bob.next_event())
        .await
        .expect("event timeout")
        .expect("event");
    match event {
        Event::Channel { channel, text, .. } => {
            assert_eq!(channel, "#general");
            assert_eq!(text, "hello from alice");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    let messages = alice.read("#general", 50).await.expect("read");
    assert!(
        messages
            .iter()
            .any(|message| message.text == "hello from alice"),
        "stored history must contain the message"
    );

    // Forum posts are readable too.
    alice
        .forum("bbs", "Welcome", "Hello everyone")
        .await
        .expect("forum");
    let posts = alice.read_forum("bbs", 50).await.expect("read forum");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].title, "Welcome");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn status_and_peers_reflect_state() {
    let node = TestNode::new(&["#tech"]);
    let socket = node.dir.path().join("control.sock");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let serve_socket = socket.clone();
    let serve_state = node.state.clone();
    tokio::spawn(async move {
        let _ = control::serve(serve_state, serve_socket, shutdown_rx).await;
    });
    wait_for_socket(&socket).await;

    let mut client = ControlClient::connect(&socket).await.expect("client");
    let status = client.status().await.expect("status");
    assert_eq!(status.uid, "control-node");
    assert_eq!(status.channels, vec!["#tech".to_string()]);
    assert!(client.peers().await.expect("peers").is_empty());
}

#[tokio::test]
async fn direct_publish_helpers_store_locally() {
    let node = TestNode::new(&["#general"]);
    social::publish_channel(&node.state, "#general", "direct").expect("publish");
    let store = node.state.messages.lock().unwrap();
    let messages = store.channel_messages("#general", 0, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, "direct");
}
