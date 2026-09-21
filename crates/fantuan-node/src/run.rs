//! Node runtime: inbound accept loop, outbound peer loops and `ping`.

use crate::identity_cmd;
use crate::peer;
use anyhow::{Context, Result, anyhow, bail};
use fantuan_core::{config::NodeConfig, time};
use fantuan_identity::{Identity, TrustStore};
use fantuan_msg::{Message, Object};
use fantuan_transport::sam::{SamConfig, SamSession};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

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

    let trust = Arc::new(Mutex::new(TrustStore::open(&config.trust_db_path())?));

    println!("fantuan-node running");
    println!("  uid:         {}", identity.descriptor().uid);
    println!("  fingerprint: {}", identity.fingerprint_hex());
    println!("  destination: {destination}");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("shutdown requested");
            let _ = shutdown.send(true);
        }
    });

    let accept_identity = identity.clone();
    let accept_trust = trust.clone();
    let accept_config = config.clone();
    let accept_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        accept_loop(
            inbound,
            accept_identity,
            accept_trust,
            accept_config,
            accept_shutdown,
        )
        .await;
    });

    let mut peers = config.peers.clone();
    peers.extend(extra_peers);
    peers.sort();
    peers.dedup();
    for destination in peers {
        let out_identity = identity.clone();
        let out_trust = trust.clone();
        let out_config = config.clone();
        let out_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            outbound_loop(
                destination,
                out_identity,
                out_trust,
                out_config,
                out_shutdown,
            )
            .await;
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
    let port = SamConfig::from_addr(&config.sam_addr)?.port;
    let outbound_config = SamConfig {
        port,
        nickname: format!(
            "fantuan-out-{}-{}",
            std::process::id(),
            OUTBOUND_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        publish: false,
    };

    let mut session = SamSession::open(&outbound_config, None)
        .await
        .context("cannot open SAM session")?;
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

async fn accept_loop(
    mut session: SamSession,
    identity: Arc<Identity>,
    trust: Arc<Mutex<TrustStore>>,
    config: NodeConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = session.accept() => {
                match accepted {
                    Ok(stream) => {
                        let identity = identity.clone();
                        let trust = trust.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_inbound(stream, &identity, &trust, &config).await {
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

async fn handle_inbound(
    mut stream: yosemite::Stream,
    identity: &Identity,
    trust: &Mutex<TrustStore>,
    config: &NodeConfig,
) -> Result<()> {
    let mut peer = peer::handshake_server(
        &mut stream,
        identity,
        Duration::from_secs(config.handshake_timeout_secs),
    )
    .await?;
    pin_peer(trust, &peer)?;
    tracing::info!(peer = peer.descriptor.uid, "inbound session established");
    peer::serve(
        &mut stream,
        &mut peer,
        Duration::from_secs(config.idle_timeout_secs),
    )
    .await
}

async fn outbound_loop(
    destination: String,
    identity: Arc<Identity>,
    trust: Arc<Mutex<TrustStore>>,
    config: NodeConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match connect_once(&destination, &identity, &trust, &config).await {
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

async fn connect_once(
    destination: &str,
    identity: &Identity,
    trust: &Mutex<TrustStore>,
    config: &NodeConfig,
) -> Result<()> {
    let port = SamConfig::from_addr(&config.sam_addr)?.port;
    let outbound_config = SamConfig {
        port,
        nickname: format!(
            "fantuan-out-{}-{}",
            std::process::id(),
            OUTBOUND_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        publish: false,
    };
    let mut session = SamSession::open(&outbound_config, None).await?;
    let mut stream = session.connect(destination).await?;
    let mut peer = peer::handshake_client(
        &mut stream,
        identity,
        Duration::from_secs(config.handshake_timeout_secs),
    )
    .await?;
    pin_peer(trust, &peer)?;
    tracing::info!(peer = peer.descriptor.uid, "outbound session established");
    peer::serve(
        &mut stream,
        &mut peer,
        Duration::from_secs(config.idle_timeout_secs),
    )
    .await
}

fn pin_peer(trust: &Mutex<TrustStore>, peer: &peer::BoundPeer) -> Result<()> {
    let store = trust.lock().map_err(|_| anyhow!("trust store poisoned"))?;
    store.upsert_peer(
        peer.fingerprint(),
        peer.uid(),
        &peer.public_key_hex(),
        time::now_unix(),
    )?;
    Ok(())
}
