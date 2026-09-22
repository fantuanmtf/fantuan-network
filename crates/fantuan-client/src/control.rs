//! Client side of the local control protocol.
//!
//! The node exposes a Unix socket with newline-delimited JSON requests. This
//! module wraps it with typed helpers used by the TUI.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Node status summary.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    /// Node uid.
    pub uid: String,
    /// Node fingerprint.
    pub fingerprint: String,
    /// Connected peer count.
    pub peers: usize,
    /// Known route count.
    pub routes: usize,
    /// Subscribed channels.
    #[serde(default)]
    pub channels: Vec<String>,
    /// Subscribed boards.
    #[serde(default)]
    pub boards: Vec<String>,
}

/// One stored channel message.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageRow {
    /// Sender fingerprint.
    pub from: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub text: String,
}

/// One stored forum post.
#[derive(Debug, Clone, Deserialize)]
pub struct PostRow {
    /// Sender fingerprint.
    pub from: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Post title.
    pub title: String,
    /// Post body.
    pub body: String,
}

/// One known peer.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerRow {
    /// Peer fingerprint.
    pub fingerprint: String,
    /// Peer uid.
    pub uid: String,
    /// Cached trust score.
    pub trust: f64,
}

/// One stored file manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct FileRow {
    /// File id (hex).
    pub file_id: String,
    /// Owner fingerprint.
    pub owner: String,
    /// File name.
    pub name: String,
    /// Plaintext size.
    pub size: u64,
}

/// An event pushed by the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A channel message.
    Channel {
        /// Channel name.
        channel: String,
        /// Sender fingerprint.
        from: String,
        /// Message text.
        text: String,
        /// Unix seconds.
        timestamp: u64,
    },
    /// A forum post.
    Forum {
        /// Board name.
        board: String,
        /// Sender fingerprint.
        from: String,
        /// Post title.
        title: String,
        /// Post body.
        body: String,
        /// Unix seconds.
        timestamp: u64,
    },
    /// A direct message.
    Message {
        /// Sender fingerprint.
        from: String,
        /// Message text.
        text: String,
    },
    /// A relay envelope delivered to us.
    Relay {
        /// Origin fingerprint.
        from: String,
    },
    /// A file became available.
    FileAvailable {
        /// File id (hex).
        file_id: String,
        /// File name.
        name: String,
        /// Plaintext size.
        size: u64,
        /// Sender fingerprint.
        from: String,
    },
    /// An anonymous DC-Net message.
    Anonymous {
        /// Channel label.
        channel: String,
        /// Extracted text.
        text: String,
        /// Round id.
        round_id: u64,
    },
    /// A peer was evicted from DC-Net rounds.
    PeerEvicted {
        /// Evicted fingerprint.
        fingerprint: String,
    },
}

/// Control socket client.
pub struct ControlClient {
    write: OwnedWriteHalf,
    read: BufReader<OwnedReadHalf>,
    streaming: bool,
}

impl ControlClient {
    /// Connect to a node control socket.
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await?;
        let (read, write) = stream.into_split();
        Ok(Self {
            write,
            read: BufReader::new(read),
            streaming: false,
        })
    }

    /// Send one request and read one JSON response line.
    pub async fn request(&mut self, request: Value) -> Result<Value> {
        if self.streaming {
            bail!("client is in event streaming mode");
        }
        let mut line = request.to_string();
        line.push('\n');
        self.write.write_all(line.as_bytes()).await?;
        self.write.flush().await?;

        let mut response = String::new();
        let read = self.read.read_line(&mut response).await?;
        if read == 0 {
            bail!("control socket closed");
        }
        let value: Value = serde_json::from_str(&response).context("invalid control response")?;
        if value["ok"] != Value::Bool(true) {
            bail!(
                "control error: {}",
                value["error"].as_str().unwrap_or("unknown")
            );
        }
        Ok(value)
    }

    /// Fetch node status.
    pub async fn status(&mut self) -> Result<Status> {
        let value = self.request(json!({"cmd": "status"})).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Publish a channel message.
    pub async fn post(&mut self, channel: &str, text: &str) -> Result<()> {
        self.request(json!({"cmd": "post", "channel": channel, "text": text}))
            .await?;
        Ok(())
    }

    /// Publish a forum post.
    pub async fn forum(&mut self, board: &str, title: &str, body: &str) -> Result<()> {
        self.request(json!({"cmd": "forum", "board": board, "title": title, "body": body}))
            .await?;
        Ok(())
    }

    /// Read stored channel messages.
    pub async fn read(&mut self, channel: &str, limit: usize) -> Result<Vec<MessageRow>> {
        let value = self
            .request(json!({"cmd": "read", "channel": channel, "limit": limit}))
            .await?;
        Ok(serde_json::from_value(value["messages"].clone())?)
    }

    /// Read stored forum posts.
    pub async fn read_forum(&mut self, board: &str, limit: usize) -> Result<Vec<PostRow>> {
        let value = self
            .request(json!({"cmd": "read_forum", "board": board, "limit": limit}))
            .await?;
        Ok(serde_json::from_value(value["posts"].clone())?)
    }

    /// Send an end-to-end encrypted direct message.
    pub async fn send(&mut self, to: &str, text: &str) -> Result<()> {
        self.request(json!({"cmd": "send", "to": to, "text": text}))
            .await?;
        Ok(())
    }

    /// Queue an anonymous DC-Net message for the next round.
    pub async fn anon_post(&mut self, channel: &str, text: &str) -> Result<()> {
        self.request(json!({"cmd": "anon", "channel": channel, "text": text}))
            .await?;
        Ok(())
    }

    /// List known peers.
    pub async fn peers(&mut self) -> Result<Vec<PeerRow>> {
        let value = self.request(json!({"cmd": "peers"})).await?;
        Ok(serde_json::from_value(value["peers"].clone())?)
    }

    /// Publish a local file; returns the file id.
    pub async fn file_put(&mut self, path: &str, to: Option<&str>) -> Result<String> {
        let value = self
            .request(json!({"cmd": "file_put", "path": path, "to": to}))
            .await?;
        Ok(value["file_id"].as_str().unwrap_or_default().to_string())
    }

    /// Retrieve a file by id into `out`.
    pub async fn file_get(&mut self, file_id: &str, out: &str) -> Result<()> {
        self.request(json!({"cmd": "file_get", "file_id": file_id, "out": out}))
            .await?;
        Ok(())
    }

    /// List stored manifests.
    pub async fn files(&mut self) -> Result<Vec<FileRow>> {
        let value = self.request(json!({"cmd": "files"})).await?;
        Ok(serde_json::from_value(value["files"].clone())?)
    }

    /// Switch to event streaming mode.
    pub async fn subscribe_events(&mut self) -> Result<()> {
        self.request(json!({"cmd": "events"})).await?;
        self.streaming = true;
        Ok(())
    }

    /// Read the next streamed event.
    pub async fn next_event(&mut self) -> Result<Event> {
        if !self.streaming {
            bail!("not in event streaming mode");
        }
        let mut line = String::new();
        let read = self.read.read_line(&mut line).await?;
        if read == 0 {
            bail!("control socket closed");
        }
        Ok(serde_json::from_str(&line)?)
    }
}
