//! Local control socket.
//!
//! Newline-delimited JSON over a Unix socket (mode 0600). Used by the TUI
//! client and by scripts; the `events` command switches the connection to a
//! live event stream.

use crate::state::{NodeEvent, NodeState};
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Status,
    Post {
        channel: String,
        text: String,
    },
    Forum {
        board: String,
        title: String,
        body: String,
    },
    Read {
        channel: String,
        limit: Option<usize>,
    },
    ReadForum {
        board: String,
        limit: Option<usize>,
    },
    Send {
        to: String,
        text: String,
    },
    Anon {
        channel: String,
        text: String,
    },
    Reinstate {
        uid: String,
    },
    FilePut {
        path: String,
        to: Option<String>,
    },
    FileGet {
        file_id: String,
        out: String,
    },
    Files,
    Peers,
    Events,
}

/// Serve the control socket until shutdown.
pub async fn serve(
    state: Arc<NodeState>,
    path: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("cannot bind control socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("control socket at {}", path.display());

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_client(stream, state).await {
                        tracing::debug!("control client ended: {error:#}");
                    }
                });
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

async fn handle_client(stream: UnixStream, state: Arc<NodeState>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut line = String::new();
        let read_bytes = reader.read_line(&mut line).await?;
        if read_bytes == 0 {
            break;
        }
        let request: Request = match serde_json::from_str(line.trim()) {
            Ok(request) => request,
            Err(error) => {
                write_line(
                    &mut write,
                    &json!({"ok": false, "error": format!("bad request: {error}")}),
                )
                .await?;
                continue;
            }
        };

        if matches!(request, Request::Events) {
            write_line(&mut write, &json!({"ok": true, "stream": "events"})).await?;
            let mut events = state.subscribe_events();
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if write_line(&mut write, &event).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::debug!(skipped, "control event stream lagged");
                    }
                    Err(_) => return Ok(()),
                }
            }
        }

        let response = dispatch(&state, request).await;
        write_line(&mut write, &response).await?;
    }
    Ok(())
}

async fn dispatch(state: &Arc<NodeState>, request: Request) -> Value {
    match request {
        Request::Status => {
            let mut channels = Vec::new();
            let mut boards = Vec::new();
            for (topic, is_board) in state.subscription_list() {
                if is_board {
                    boards.push(topic);
                } else {
                    channels.push(topic);
                }
            }
            json!({
                "ok": true,
                "uid": state.identity.descriptor().uid,
                "fingerprint": state.fingerprint(),
                "peers": state.pool.count(),
                "routes": state.route_count(),
                "channels": channels,
                "boards": boards,
            })
        }
        Request::Post { channel, text } => {
            match crate::social::publish_channel(state, &channel, &text) {
                Ok(_) => json!({"ok": true}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Forum { board, title, body } => {
            match crate::social::publish_forum(state, &board, &title, &body) {
                Ok(_) => json!({"ok": true}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Read { channel, limit } => {
            let limit = limit.unwrap_or(100).min(500);
            let store = match state.messages.lock() {
                Ok(store) => store,
                Err(_) => return json!({"ok": false, "error": "store poisoned"}),
            };
            match store.channel_messages(&channel, 0, limit) {
                Ok(messages) => json!({
                    "ok": true,
                    "messages": messages
                        .into_iter()
                        .map(|message| json!({
                            "from": message.from,
                            "timestamp": message.timestamp,
                            "text": message.text,
                        }))
                        .collect::<Vec<_>>(),
                }),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::ReadForum { board, limit } => {
            let limit = limit.unwrap_or(100).min(500);
            let store = match state.messages.lock() {
                Ok(store) => store,
                Err(_) => return json!({"ok": false, "error": "store poisoned"}),
            };
            match store.forum_posts(&board, 0, limit) {
                Ok(posts) => json!({
                    "ok": true,
                    "posts": posts
                        .into_iter()
                        .map(|post| json!({
                            "from": post.from,
                            "timestamp": post.timestamp,
                            "title": post.title,
                            "body": post.body,
                        }))
                        .collect::<Vec<_>>(),
                }),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Send { to, text } => {
            let target = match resolve_peer(state, &to) {
                Ok(target) => target,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match crate::relay::send_message(state, &target, &text) {
                Ok(()) => json!({"ok": true, "to": target}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Anon { channel, text } => match crate::anon::queue(state, &channel, &text) {
            Ok(()) => json!({"ok": true, "queued": true}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        },
        Request::Reinstate { uid } => {
            let mut reputation = match state.reputation.lock() {
                Ok(tracker) => tracker,
                Err(_) => return json!({"ok": false, "error": "reputation tracker poisoned"}),
            };
            let evicted = reputation.is_evicted(&uid);
            let strikes = reputation.strikes(&uid);
            reputation.reinstate(&uid);
            json!({"ok": true, "uid": uid, "was_evicted": evicted, "strikes": strikes})
        }
        Request::FilePut { path, to } => {
            match crate::files::publish_file(state, std::path::Path::new(&path), to.as_deref()) {
                Ok(file_id) => json!({"ok": true, "file_id": file_id}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::FileGet { file_id, out } => {
            match crate::files::fetch_file(state, &file_id, std::path::Path::new(&out)).await {
                Ok(()) => json!({"ok": true, "path": out}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Files => match crate::files::list_files(state, 500) {
            Ok(files) => json!({
                "ok": true,
                "files": files
                    .into_iter()
                    .map(|file| json!({
                        "file_id": hex::encode(file.file_id),
                        "owner": file.owner,
                        "name": file.name,
                        "size": file.size,
                        "received_at": file.received_at,
                    }))
                    .collect::<Vec<_>>(),
            }),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        },
        Request::Peers => {
            let store = match state.trust.lock() {
                Ok(store) => store,
                Err(_) => return json!({"ok": false, "error": "trust store poisoned"}),
            };
            match store.peers(1000) {
                Ok(peers) => json!({
                    "ok": true,
                    "peers": peers
                        .into_iter()
                        .map(|peer| json!({
                            "fingerprint": peer.fingerprint,
                            "uid": peer.uid,
                            "trust": peer.trust_score,
                        }))
                        .collect::<Vec<_>>(),
                }),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        Request::Events => json!({"ok": false, "error": "events already streaming"}),
    }
}

/// Resolve a fingerprint or uid to a fingerprint.
fn resolve_peer(state: &Arc<NodeState>, target: &str) -> Result<String> {
    let store = state
        .trust
        .lock()
        .map_err(|_| anyhow!("trust store poisoned"))?;
    if store.get_peer(target)?.is_some() {
        return Ok(target.to_string());
    }
    for peer in store.peers(1000)? {
        if peer.uid == target {
            return Ok(peer.fingerprint);
        }
    }
    Err(anyhow!("unknown peer {target:?}"))
}

async fn write_line<W, T>(write: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize + ?Sized,
{
    let mut line = serde_json::to_string(value).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    line.push('\n');
    write.write_all(line.as_bytes()).await?;
    write.flush().await
}

/// Convenience for tests and callers that do not need `NodeEvent` internals.
pub type Event = NodeEvent;
