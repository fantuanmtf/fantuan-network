//! One-shot `send` command.
//!
//! Opens a transient session to a bootstrap peer, exchanges gossip to learn
//! the destination's certificate, then hands the peer an end-to-end
//! encrypted relay envelope addressed to the destination.

use crate::identity_cmd;
use crate::peer;
use anyhow::{Context, Result, bail};
use fantuan_core::config::NodeConfig;
use fantuan_identity::{Descriptor, TrustStore};
use fantuan_msg::{Gossip, MAX_ANNOUNCEMENTS, Object, Relay};
use fantuan_transport::sam::{SamConfig, SamSession};
use std::collections::HashMap;
use std::time::Duration;

/// Exchange a limited gossip handshake and return the relay to send.
pub async fn send(config: &NodeConfig, via: &str, to: &str, text: &str) -> Result<()> {
    if config.peers.is_empty() && via.is_empty() {
        bail!("no next hop: pass --via <destination> or set peers in the config");
    }
    let identity = identity_cmd::load_identity(config)?;
    let port = SamConfig::from_addr(&config.sam_addr)?.port;
    let outbound_config = SamConfig {
        port,
        nickname: format!(
            "fantuan-send-{}-{}",
            std::process::id(),
            fantuan_transport::next_connection_id()
        ),
        publish: false,
    };
    let mut session = SamSession::open(&outbound_config, None)
        .await
        .context("cannot open SAM session")?;
    let mut stream = session.connect(via).await.context("I2P connect failed")?;
    let mut peer = peer::handshake_client(
        &mut stream,
        &identity,
        Duration::from_secs(config.handshake_timeout_secs),
    )
    .await?;
    println!("next hop: {} ({})", peer.descriptor.uid, peer.fingerprint());

    // Offer our descriptors, then learn the destination certificate from the
    // peer's descriptor or its gossip.
    let mut candidates: HashMap<String, Vec<u8>> = HashMap::new();
    candidates.insert(
        peer.descriptor.fingerprint.clone(),
        peer.descriptor.openpgp_cert.clone(),
    );
    if let Some(cert) =
        load_descriptor_cert(config, &peer.descriptor.uid, &peer.descriptor.fingerprint)
    {
        candidates.insert(peer.descriptor.fingerprint.clone(), cert);
    }

    let our_gossip = local_gossip(config, &identity.fingerprint_hex())?;
    if !our_gossip.is_empty() {
        let bytes = Object::Gossip(our_gossip).to_canonical_bytes()?;
        peer.session.send(&mut stream, &bytes).await?;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut learned_target: Option<(Vec<u8>, String)> = None;
    while learned_target.is_none() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let bytes = match tokio::time::timeout(remaining, peer.session.recv(&mut stream)).await {
            Ok(Ok(bytes)) => bytes,
            _ => break,
        };
        if let Ok(Object::Gossip(gossip)) = Object::from_canonical_bytes(&bytes) {
            for announcement in &gossip.announcements {
                if let Ok(descriptor) = Descriptor::from_canonical(&announcement.descriptor) {
                    if descriptor.verify(&announcement.signature).is_ok() {
                        learned_target = match_resolve(&descriptor, to).or(learned_target);
                        candidates.insert(
                            descriptor.fingerprint.clone(),
                            descriptor.openpgp_cert.clone(),
                        );
                    }
                }
            }
        }
    }

    let target = learned_target.or_else(|| {
        candidates
            .iter()
            .find(|(fingerprint, _)| fingerprint.as_str() == to)
            .map(|(fingerprint, cert)| (cert.clone(), fingerprint.clone()))
            .or_else(|| local_target(config, to))
    });
    let Some((cert_bytes, target_fingerprint)) = target else {
        bail!("cannot resolve destination {to:?}; import its descriptor or exchange gossip first");
    };

    let cert = fantuan_identity::keys::cert_from_bytes(&cert_bytes)?;
    let inner = Object::Message(fantuan_msg::Message::create(&identity, text.as_bytes())?)
        .to_canonical_bytes()?;
    let payload = fantuan_identity::encrypt_for(&cert, &inner)?;
    let nonce = fantuan_core::time::now_unix();
    let relay = Relay::create(&identity, &target_fingerprint, nonce, payload)?;
    peer.session
        .send(&mut stream, &Object::Relay(relay).to_canonical_bytes()?)
        .await?;
    println!(
        "relay sent to {target_fingerprint} via {}",
        peer.fingerprint()
    );
    Ok(())
}

fn match_resolve(descriptor: &Descriptor, to: &str) -> Option<(Vec<u8>, String)> {
    if descriptor.fingerprint == to || descriptor.uid == to {
        Some((
            descriptor.openpgp_cert.clone(),
            descriptor.fingerprint.clone(),
        ))
    } else {
        None
    }
}

fn load_descriptor_cert(config: &NodeConfig, uid: &str, fingerprint: &str) -> Option<Vec<u8>> {
    let store = TrustStore::open(&config.trust_db_path()).ok()?;
    let stored = store.get_peer(fingerprint).ok()??;
    if stored.uid == uid {
        hex::decode(&stored.public_key_hex).ok()
    } else {
        None
    }
}

fn local_target(config: &NodeConfig, to: &str) -> Option<(Vec<u8>, String)> {
    let store = TrustStore::open(&config.trust_db_path()).ok()?;
    let peers = store.peers(10_000).ok()?;
    for peer in peers {
        if peer.fingerprint == to || peer.uid == to {
            let cert = hex::decode(&peer.public_key_hex).ok()?;
            return Some((cert, peer.fingerprint));
        }
    }
    None
}

fn local_gossip(config: &NodeConfig, own: &str) -> Result<Gossip> {
    let store = TrustStore::open(&config.trust_db_path())?;
    let mut gossip = Gossip::new();
    for (fingerprint, descriptor, signature) in store.descriptors(MAX_ANNOUNCEMENTS)? {
        if fingerprint != own {
            gossip.push_announcement(descriptor, signature);
        }
    }
    Ok(gossip)
}
