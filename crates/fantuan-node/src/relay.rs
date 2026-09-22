//! Relay handling: verify, deliver locally or forward one hop.
//!
//! Envelopes are OpenPGP-encrypted to the destination, so relays never see
//! plaintext. Admission (nonces, freshness, rate limits, TOFU) is enforced
//! per verified origin fingerprint.

use crate::peer::BoundPeer;
use crate::state::{NodeEvent, NodeState};
use anyhow::{Context, Result, anyhow, bail};
use fantuan_core::time;
use fantuan_identity::{decrypt, encrypt_for, keys::cert_from_bytes};
use fantuan_msg::{Message, Object, Relay};
use std::sync::Arc;

/// Freshness window for relay envelopes (re-exported for admission).
pub use fantuan_msg::RELAY_MAX_AGE_SECS as MAX_AGE_SECS;

/// Handle one incoming relay envelope.
pub fn handle(state: &Arc<NodeState>, peer: &BoundPeer, relay: Relay) -> Result<()> {
    let origin_cert_bytes = if relay.origin == peer.fingerprint() {
        peer.descriptor.openpgp_cert.clone()
    } else {
        cert_bytes_for(state, &relay.origin)?
    };

    {
        let mut admissions = state
            .admissions
            .lock()
            .map_err(|_| anyhow!("admission control poisoned"))?;
        admissions.pin(&relay.origin, &origin_cert_bytes)?;
        admissions.check(
            &relay.origin,
            relay.nonce,
            relay.timestamp,
            time::now_unix(),
        )?;
    }
    relay.verify_cert_bytes(&origin_cert_bytes)?;

    if relay.to == state.fingerprint() {
        let plaintext = decrypt(&state.identity, &relay.payload)?;
        let object = Object::from_canonical_bytes(&plaintext)?;
        match object {
            Object::Message(message) => {
                let cert = cert_from_bytes(&origin_cert_bytes)?;
                message.verify(&cert)?;
                let text = String::from_utf8_lossy(&message.payload).to_string();
                state.emit(NodeEvent::Message {
                    from: relay.origin.clone(),
                    text,
                });
            }
            Object::FileManifest(manifest) => {
                crate::files::handle_manifest(state, manifest, &relay.origin, &origin_cert_bytes)?;
            }
            other => {
                tracing::debug!("relayed object delivered: {other:?}");
                state.emit(NodeEvent::Relay {
                    from: relay.origin.clone(),
                });
            }
        }
        return Ok(());
    }

    let Some(next_hop) = state.next_hop(&relay.to) else {
        bail!("no route to relay destination {}", relay.to);
    };
    let forwarded = Object::Relay(relay.forwarded()?).to_canonical_bytes()?;
    state.pool.try_send(&next_hop, forwarded)?;
    tracing::debug!(next_hop, to = relay.to, "relay forwarded");
    Ok(())
}

/// Encrypt and send a text message to `to` over the relay layer.
pub fn send_message(state: &Arc<NodeState>, to: &str, text: &str) -> Result<()> {
    let message = Message::create(&state.identity, text.as_bytes())?;
    send_object(state, to, Object::Message(message))
}

/// Encrypt and send an arbitrary object to `to` over the relay layer.
pub fn send_object(state: &Arc<NodeState>, to: &str, inner: Object) -> Result<()> {
    let cert_bytes = cert_bytes_for(state, to)?;
    let cert = cert_from_bytes(&cert_bytes)?;
    let inner = inner.to_canonical_bytes()?;
    let payload = encrypt_for(&cert, &inner)?;

    let nonce = state.next_relay_nonce();
    let relay = Relay::create(&state.identity, to, nonce, payload)?;
    let next_hop = state
        .next_hop(to)
        .ok_or_else(|| anyhow!("no route to {to}"))?;
    state
        .pool
        .try_send(&next_hop, Object::Relay(relay).to_canonical_bytes()?)?;
    tracing::info!(next_hop, to, "relay sent");
    Ok(())
}

/// Look up a peer certificate by fingerprint.
pub fn cert_bytes_for(state: &Arc<NodeState>, fingerprint: &str) -> Result<Vec<u8>> {
    let store = state
        .trust
        .lock()
        .map_err(|_| anyhow!("trust store poisoned"))?;
    let peer = store
        .get_peer(fingerprint)?
        .ok_or_else(|| anyhow!("unknown peer {fingerprint}"))?;
    hex::decode(&peer.public_key_hex).context("stored peer key is not valid hex")
}
