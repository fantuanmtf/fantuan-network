//! IRC bridge tests: two IRC clients join a channel and chat through the
//! node, and the message is stored.

use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_node::irc;
use fantuan_node::state::NodeState;
use fantuan_node::store::MessageStore;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

struct TestNode {
    state: Arc<NodeState>,
    _dir: TempDir,
}

fn test_node() -> TestNode {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = Arc::new(Identity::generate("irc-node", "dest").expect("identity"));
    let trust = TrustStore::open(&dir.path().join("trust.sqlite")).expect("trust");
    let messages = MessageStore::in_memory().expect("messages");
    let (events_tx, _events) = mpsc::unbounded_channel();
    let config = NodeConfig::default();
    TestNode {
        state: NodeState::new(identity, config, trust, messages, events_tx),
        _dir: dir,
    }
}

struct IrcClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl IrcClient {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (read, write) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            writer: write,
        }
    }

    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("write");
        self.writer.flush().await.expect("flush");
    }

    async fn read_until(&mut self, needle: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout_at(deadline, self.reader.read_line(&mut line))
                .await
                .expect("read timeout")
                .expect("read");
            assert!(read > 0, "connection closed while waiting for {needle:?}");
            if line.contains(needle) {
                return line;
            }
        }
    }
}

#[tokio::test]
async fn irc_clients_chat_through_the_bridge() {
    let node = test_node();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(irc::serve_on(listener, node.state.clone(), shutdown_rx));

    let mut alice = IrcClient::connect(addr).await;
    let mut bob = IrcClient::connect(addr).await;

    alice.send("NICK alice").await;
    alice.send("USER alice 0 * :Alice").await;
    alice.send("JOIN #general").await;
    alice.read_until("JOIN #general").await;

    bob.send("NICK bob").await;
    bob.send("USER bob 0 * :Bob").await;
    bob.send("JOIN #general").await;
    bob.read_until("JOIN #general").await;

    alice.send("PRIVMSG #general :hello irc").await;
    let line = bob.read_until("hello irc").await;
    assert!(line.contains("PRIVMSG #general"), "unexpected line: {line}");

    let messages = node
        .state
        .messages
        .lock()
        .expect("store")
        .channel_messages("#general", 0, 10)
        .expect("query");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, "hello irc");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn irc_ping_is_answered() {
    let node = test_node();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(irc::serve_on(listener, node.state.clone(), shutdown_rx));

    let mut client = IrcClient::connect(addr).await;
    client.send("PING :token123").await;
    let line = client.read_until("PONG").await;
    assert!(line.contains("token123"));
}
