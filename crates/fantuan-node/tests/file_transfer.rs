//! Three-node file transfer: A publishes, chunks replicate to B and C, then
//! C retrieves the file after its own cache is cleared, proving the data is
//! served from B and that nodes only ever hold hashes and ciphertext.

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::store::MessageStore;
use fantuan_node::{connection, files, peer, relay};
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
        let chunks = fantuan_storage::ChunkCache::in_memory(8 << 20).expect("chunks");
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

async fn wait_for_chunks(node: &TestNode, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let count = node.state.chunks.len().expect("cache len");
        if count >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} only stored {count}/{expected} chunks",
            node.state.identity.descriptor().uid
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn sample_bytes() -> Vec<u8> {
    // Deterministic multi-chunk content with a marker that must never appear
    // in stored ciphertext.
    let mut data = Vec::with_capacity(100 * 1024);
    data.extend_from_slice(b"FANTUAN-PLAINTEXT-MARKER-START");
    for index in 0..100 * 1024u32 {
        data.push(((index * 31 + 7) % 251) as u8);
    }
    data
}

#[tokio::test]
async fn three_nodes_publish_and_retrieve_file() {
    let alice = TestNode::new("alice");
    let bob = TestNode::new("bob");
    let mut carol = TestNode::new("carol");

    let (alice_side, bob_side_a) = tokio::io::duplex(1 << 20);
    let (carol_side, bob_side_c) = tokio::io::duplex(1 << 20);
    let tasks = vec![
        spawn_client(alice.state.clone(), alice_side),
        spawn_server(bob.state.clone(), bob_side_a),
        spawn_client(carol.state.clone(), carol_side),
        spawn_server(bob.state.clone(), bob_side_c),
    ];
    wait_for_route(&alice, &carol.fingerprint).await;
    wait_for_route(&carol, &alice.fingerprint).await;

    // Alice publishes a file addressed to Carol.
    let dir = tempfile::tempdir().expect("tempdir");
    let source_path = dir.path().join("secret.bin");
    let data = sample_bytes();
    std::fs::write(&source_path, &data).expect("write source");
    let file_id =
        files::publish_file(&alice.state, &source_path, Some(&carol.fingerprint)).expect("publish");
    assert_eq!(file_id.len(), 64);

    let expected_chunks = (data.len() as u64).div_ceil(fantuan_msg::CHUNK_SIZE as u64);
    wait_for_chunks(&bob, expected_chunks).await;
    wait_for_chunks(&carol, expected_chunks).await;

    // Carol sees the manifest and the availability event.
    let event = tokio::time::timeout(Duration::from_secs(5), carol.events.recv())
        .await
        .expect("manifest event timeout")
        .expect("event");
    match event {
        NodeEvent::FileAvailable { file_id: seen, .. } => assert_eq!(seen, file_id),
        other => panic!("unexpected event: {other:?}"),
    }

    // Only hashes and ciphertext are stored: the marker must not appear.
    let marker = b"FANTUAN-PLAINTEXT-MARKER-START";
    let reference =
        files::load_manifest(&alice.state, &hex_to_array(&file_id)).expect("alice manifest");
    // Carol received the manifest through the relay; Bob only has chunks.
    files::load_manifest(&carol.state, &hex_to_array(&file_id)).expect("carol manifest");
    for node in [&alice, &bob, &carol] {
        for hash in &reference.chunks {
            let stored = node
                .state
                .chunks
                .get(&hash.into_array())
                .expect("cache get")
                .expect("chunk stored");
            assert!(
                !stored.windows(marker.len()).any(|window| window == marker),
                "stored chunk must not contain plaintext"
            );
        }
    }

    // Clear Alice's and Carol's caches: only Bob has the chunks left.
    alice.state.chunks.clear().expect("clear alice");
    carol.state.chunks.clear().expect("clear carol");
    assert_eq!(carol.state.chunks.len().unwrap(), 0);

    let out_path = dir.path().join("retrieved.bin");
    files::fetch_file(&carol.state, &file_id, &out_path)
        .await
        .expect("fetch");
    let retrieved = std::fs::read(&out_path).expect("read retrieved");
    assert_eq!(retrieved, data, "retrieved bytes must match the original");

    // The relay delivered the manifest end-to-end encrypted.
    assert!(relay::cert_bytes_for(&carol.state, &alice.fingerprint).is_ok());

    for task in tasks {
        task.abort();
    }
}

fn hex_to_array(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("hex");
    bytes.as_slice().try_into().expect("32 bytes")
}
