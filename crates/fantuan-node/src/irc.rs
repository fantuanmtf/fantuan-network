//! Minimal IRC bridge.
//!
//! A tiny IRC server that maps `JOIN`/`PRIVMSG` onto channel subscriptions
//! and publishing, and broadcasts stored channel events back to IRC clients.
//! Only the commands needed for chat are implemented.

use crate::state::{NodeEvent, NodeState};
use anyhow::{Context, Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

struct Client {
    nick: String,
    channels: HashSet<String>,
    tx: mpsc::UnboundedSender<String>,
}

type Clients = Arc<Mutex<HashMap<u64, Client>>>;

/// Bind `addr` and serve the IRC bridge until shutdown.
pub async fn serve(
    state: Arc<NodeState>,
    addr: &str,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind IRC bridge on {addr}"))?;
    tracing::info!("IRC bridge listening on {}", listener.local_addr()?);
    serve_on(listener, state, shutdown).await
}

/// Serve an already-bound listener (tests and callers that pick a port).
pub async fn serve_on(
    listener: TcpListener,
    state: Arc<NodeState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));

    let mut events = state.subscribe_events();
    let events_clients = clients.clone();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(NodeEvent::Channel {
                    channel,
                    from,
                    text,
                    ..
                }) => {
                    let line = format!(
                        ":{}!fantuan@localhost PRIVMSG {} :{}\r\n",
                        short(&from),
                        channel,
                        text
                    );
                    let clients = events_clients.lock().await;
                    for client in clients.values() {
                        if client.channels.contains(&channel) {
                            let _ = client.tx.send(line.clone());
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tracing::debug!(%peer, "IRC client connected");
                let state = state.clone();
                let clients = clients.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_client(stream, state, clients).await {
                        tracing::debug!("IRC client ended: {error:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_client(stream: TcpStream, state: Arc<NodeState>, clients: Clients) -> Result<()> {
    let id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    let (read, mut write) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    {
        let mut registry = clients.lock().await;
        registry.insert(
            id,
            Client {
                nick: format!("guest{id}"),
                channels: HashSet::new(),
                tx,
            },
        );
    }

    let mut reader = BufReader::new(read);
    let mut buffer = String::new();
    let mut nick = format!("guest{id}");
    let mut welcomed = false;

    loop {
        tokio::select! {
            Some(line) = rx.recv() => {
                write.write_all(line.as_bytes()).await?;
                write.flush().await?;
            }
            result = reader.read_line(&mut buffer) => {
                let read_bytes = result?;
                if read_bytes == 0 {
                    break;
                }
                let line = buffer.trim_end().to_string();
                buffer.clear();
                let quit = handle_line(
                    &state,
                    &clients,
                    id,
                    &mut nick,
                    &mut welcomed,
                    &line,
                )
                .await?;
                if quit {
                    break;
                }
            }
        }
    }

    clients.lock().await.remove(&id);
    Ok(())
}

async fn handle_line(
    state: &Arc<NodeState>,
    clients: &Clients,
    id: u64,
    nick: &mut String,
    welcomed: &mut bool,
    line: &str,
) -> Result<bool> {
    let mut parts = line.splitn(2, ' ');
    let command = parts.next().unwrap_or_default().to_uppercase();
    let rest = parts.next().unwrap_or_default().trim();

    match command.as_str() {
        "CAP" => {
            let _ = send_to(clients, id, ":localhost CAP * LS :\r\n").await;
        }
        "NICK" => {
            let new_nick = rest.trim_start_matches(':').trim();
            if new_nick.is_empty() {
                let _ = send_to(clients, id, ":localhost 431 * :No nickname given\r\n").await;
                return Ok(false);
            }
            *nick = new_nick.to_string();
            let mut registry = clients.lock().await;
            if let Some(client) = registry.get_mut(&id) {
                client.nick = nick.clone();
            }
        }
        "USER" => {
            if !*welcomed {
                *welcomed = true;
                let welcome = format!(":localhost 001 {nick} :Welcome to Fantuan Network\r\n");
                let _ = send_to(clients, id, &welcome).await;
            }
        }
        "JOIN" => {
            let channel = rest.trim_start_matches(':').trim();
            if !fantuan_msg::valid_topic(channel) {
                let _ = send_to(clients, id, ":localhost 403 * :Invalid channel name\r\n").await;
                return Ok(false);
            }
            state.subscribe_channel(channel);
            let mut registry = clients.lock().await;
            if let Some(client) = registry.get_mut(&id) {
                client.channels.insert(channel.to_string());
            }
            drop(registry);
            let join_line = format!(":{nick}!fantuan@localhost JOIN {channel}\r\n");
            let _ = send_to(clients, id, &join_line).await;
            let topic = format!(":localhost 332 {nick} {channel} :Fantuan channel\r\n");
            let _ = send_to(clients, id, &topic).await;
        }
        "PART" => {
            let channel = rest.trim_start_matches(':').trim();
            let mut registry = clients.lock().await;
            if let Some(client) = registry.get_mut(&id) {
                client.channels.remove(channel);
            }
            drop(registry);
            let part_line = format!(":{nick}!fantuan@localhost PART {channel}\r\n");
            let _ = send_to(clients, id, &part_line).await;
        }
        "PRIVMSG" => {
            let Some((target, text)) = rest.split_once(' ') else {
                let _ = send_to(clients, id, ":localhost 412 * :No text to send\r\n").await;
                return Ok(false);
            };
            let target = target.trim();
            let text = text.trim_start_matches(':');
            if !target.starts_with('#') {
                let notice = format!(
                    ":localhost NOTICE {nick} :direct messages require the control socket\r\n"
                );
                let _ = send_to(clients, id, &notice).await;
                return Ok(false);
            }
            state.subscribe_channel(target);
            if let Err(error) = crate::social::publish_channel(state, target, text) {
                let notice = format!(":localhost NOTICE {nick} :publish failed: {error}\r\n");
                let _ = send_to(clients, id, &notice).await;
            }
        }
        "PING" => {
            let pong = format!("PONG :{}\r\n", rest.trim_start_matches(':'));
            let _ = send_to(clients, id, &pong).await;
        }
        "QUIT" => return Ok(true),
        _ => {}
    }
    Ok(false)
}

async fn send_to(clients: &Clients, id: u64, line: &str) -> Result<()> {
    let registry = clients.lock().await;
    let client = registry
        .get(&id)
        .ok_or_else(|| anyhow!("unknown IRC client {id}"))?;
    client
        .tx
        .send(line.to_string())
        .map_err(|_| anyhow!("client gone"))?;
    Ok(())
}

fn short(fingerprint: &str) -> &str {
    fingerprint.get(..8).unwrap_or(fingerprint)
}
