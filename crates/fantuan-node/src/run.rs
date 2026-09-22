//! Node runtime: inbound accept loop, outbound peer loops, `ping` and the
//! operator event stream.

use crate::connection;
use crate::identity_cmd;
use crate::peer;
use crate::state::{NodeEvent, NodeState};
use crate::store::MessageStore;
use anyhow::{Context, Result, anyhow, bail};
use fantuan_core::{config::NodeConfig, time};
use fantuan_identity::TrustStore;
use fantuan_msg::{Message, Object};
use fantuan_transport::sam::{SamConfig, SamSession};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

static OUTBOUND_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Run the node until Ctrl-C.
pub async fn run(config: NodeConfig, extra_peers: Vec<String>) -> Result<()> {
    let identity = Arc::new(identity_cmd::load_identity(&config)?);
    let private_key = identity_cmd::i2p_private_key(&config)?;
    let port = SamConfig::from_addr(&config.sam_addr)?.port;

    let nickname = format!(
        "fantuan-{}-{}",
        std::process::id(),
        &identity.fingerprint_hex()[..8]
    );
    let inbound_config = SamConfig {
        port,
        nickname,
        publish: true,
    };
    let inbound = SamSession::open(&inbound_config, Some(&private_key))
        .await
        .context("cannot open SAM session (is i2pd running with SAM enabled?)")?;
    let destination = inbound.destination().to_string();

    let trust = TrustStore::open(&config.trust_db_path())?;
    let messages = MessageStore::open(&config.messages_db_path())?;
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let state = NodeState::new(identity.clone(), config.clone(), trust, messages, events_tx);

    println!("fantuan-node running");
    println!("  uid:         {}", identity.descriptor().uid);
    println!("  fingerprint: {}", identity.fingerprint_hex());
    println!("  destination: {destination}");

    tokio::spawn(async move {
        while let Some(event) = events_rx.recv().await {
            match event {
                NodeEvent::Message { from, text } => println!("[{}] {}", short(&from), text),
                NodeEvent::Relay { from } => {
                    println!("[relay] envelope delivered from {}", short(&from));
                }
                NodeEvent::Channel {
                    channel,
                    from,
                    text,
                    ..
                } => println!("[{channel}] {}: {text}", short(&from)),
                NodeEvent::Forum {
                    board, from, title, ..
                } => println!("[bbs:{board}] {}: {title}", short(&from)),
            }
        }
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("shutdown requested");
            let _ = shutdown.send(true);
        }
    });

    if let Some(socket) = config.control_socket_path() {
        let control_state = state.clone();
        let control_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(error) = crate::control::serve(control_state, socket, control_shutdown).await
            {
                tracing::warn!("control socket ended: {error:#}");
            }
        });
    }

    if let Some(addr) = config.irc_addr.clone() {
        let irc_state = state.clone();
        let irc_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(error) = crate::irc::serve(irc_state, &addr, irc_shutdown).await {
                tracing::warn!("IRC bridge ended: {error:#}");
            }
        });
    }

    let accept_state = state.clone();
    let accept_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        accept_loop(inbound, accept_state, accept_shutdown).await;
    });

    let mut peers = config.peers.clone();
    peers.extend(extra_peers);
    peers.sort();
    peers.dedup();
    for destination in peers {
        let out_state = state.clone();
        let out_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            outbound_loop(destination, out_state, out_shutdown).await;
        });
    }

    let mut shutdown_rx = shutdown_rx;
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    println!("fantuan-node stopped");
    Ok(())
}

/// Connect to a peer, handshake, optionally send a message, then ping.
pub async fn ping(config: &NodeConfig, destination: &str, message: Option<&str>) -> Result<()> {
    let identity = identity_cmd::load_identity(config)?;
    let mut session = open_transient(config, "ping").await?;
    let mut stream = session
        .connect(destination)
        .await
        .context("I2P connect failed")?;
    let mut peer = peer::handshake_client(
        &mut stream,
        &identity,
        Duration::from_secs(config.handshake_timeout_secs),
    )
    .await?;
    println!(
        "connected to {} ({})",
        peer.descriptor.uid,
        peer.fingerprint()
    );

    if let Some(text) = message {
        let signed = Message::create(&identity, text.as_bytes())?;
        let bytes = Object::Message(signed).to_canonical_bytes()?;
        peer.session.send(&mut stream, &bytes).await?;
    }

    let timestamp = time::now_unix();
    let ping = Object::Ping {
        nonce: 1,
        timestamp,
    }
    .to_canonical_bytes()?;
    let start = Instant::now();
    peer.session.send(&mut stream, &ping).await?;

    let reply = tokio::time::timeout(Duration::from_secs(30), peer.session.recv(&mut stream))
        .await
        .context("pong timeout")??;
    match Object::from_canonical_bytes(&reply)? {
        Object::Pong { .. } => {
            println!("pong in {:.1} ms", start.elapsed().as_secs_f64() * 1000.0);
            Ok(())
        }
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// Open a transient (non-published) SAM session.
pub async fn open_transient(config: &NodeConfig, label: &str) -> Result<SamSession> {
    let port = SamConfig::from_addr(&config.sam_addr)?.port;
    let outbound_config = SamConfig {
        port,
        nickname: format!(
            "fantuan-{label}-{}-{}",
            std::process::id(),
            OUTBOUND_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        publish: false,
    };
    SamSession::open(&outbound_config, None)
        .await
        .context("cannot open SAM session")
}

async fn accept_loop(
    mut session: SamSession,
    state: Arc<NodeState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = session.accept() => {
                match accepted {
                    Ok(stream) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_inbound(stream, state).await {
                                tracing::warn!("inbound session ended: {error:#}");
                            }
                        });
                    }
                    Err(error) => {
                        tracing::warn!("accept failed: {error}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
}

async fn handle_inbound(mut stream: yosemite::Stream, state: Arc<NodeState>) -> Result<()> {
    let peer = peer::handshake_server(
        &mut stream,
        &state.identity,
        Duration::from_secs(state.config.handshake_timeout_secs),
    )
    .await?;
    pin_peer(&state, &peer)?;
    tracing::info!(peer = peer.descriptor.uid, "inbound session established");
    connection::run(state, stream, peer).await
}

async fn outbound_loop(
    destination: String,
    state: Arc<NodeState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match connect_once(&destination, &state).await {
            Ok(()) => {
                tracing::info!(%destination, "outbound session closed");
                backoff = Duration::from_secs(1);
            }
            Err(error) => {
                tracing::warn!(%destination, "outbound session failed: {error:#}");
            }
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

async fn connect_once(destination: &str, state: &Arc<NodeState>) -> Result<()> {
    let mut session = open_transient(&state.config, "out").await?;
    let mut stream = session.connect(destination).await?;
    let peer = peer::handshake_client(
        &mut stream,
        &state.identity,
        Duration::from_secs(state.config.handshake_timeout_secs),
    )
    .await?;
    pin_peer(state, &peer)?;
    tracing::info!(peer = peer.descriptor.uid, "outbound session established");
    connection::run(state.clone(), stream, peer).await
}

fn pin_peer(state: &Arc<NodeState>, peer: &peer::BoundPeer) -> Result<()> {
    let store = state
        .trust
        .lock()
        .map_err(|_| anyhow!("trust store poisoned"))?;
    store.upsert_peer(
        peer.fingerprint(),
        peer.uid(),
        &peer.public_key_hex(),
        time::now_unix(),
    )?;
    Ok(())
}

fn short(fingerprint: &str) -> &str {
    fingerprint.get(..8).unwrap_or(fingerprint)
}
