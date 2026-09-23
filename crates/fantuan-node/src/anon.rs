//! Anonymous DC-Net integration.
//!
//! The scheduler queues messages, picks directly connected participants and
//! drives mesh rounds; round objects are exchanged through the normal
//! connection pool. Dropouts are penalized and eventually evicted.

use crate::state::{NodeEvent, NodeState};
use anyhow::{Result, anyhow, bail};
use fantuan_anon::{DriverContext, RoundDriver};
use fantuan_identity::{Descriptor, TrustGraph, TrustLevel};
use fantuan_msg::{DCNET_MAX_PARTICIPANTS, DCNET_PAYLOAD_LEN, Object};
use std::collections::HashMap;
use std::sync::Arc;

/// Fingerprint → X25519 static public key.
type NoiseKeys = HashMap<String, [u8; 32]>;
/// Fingerprint → certificate bytes.
type CertMap = HashMap<String, Vec<u8>>;

/// Connected participants: ourselves plus directly connected, non-evicted
/// peers, capped at the protocol maximum.
pub fn participants(state: &Arc<NodeState>) -> Vec<String> {
    let own = state.fingerprint();
    let evicted = state
        .reputation
        .lock()
        .map(|tracker| tracker.evicted())
        .unwrap_or_default();
    let mut list = vec![own];
    for peer in state
        .pool
        .peers()
        .into_iter()
        .filter(|peer| !evicted.contains(peer))
    {
        list.push(peer);
    }

    // Optional Sybil guard: require a minimum trust level.
    let min_trust = state.config.min_round_trust;
    if min_trust > 0
        && let Ok(store) = state.trust.lock()
    {
        let own = state.fingerprint();
        let mut graph = TrustGraph::new(&store, &own);
        let required = TrustLevel::from_i32(min_trust as i32);
        list.retain(|peer| {
            *peer == own
                || graph
                    .trust_of(peer)
                    .map(|level| level >= required)
                    .unwrap_or(false)
        });
    }

    list.sort();
    // Keep the local node in the list even after truncation.
    if list.len() > DCNET_MAX_PARTICIPANTS {
        let own = state.fingerprint();
        list.truncate(DCNET_MAX_PARTICIPANTS);
        if !list.contains(&own)
            && let Some(slot) = list.last_mut()
        {
            *slot = own;
        }
    }
    list
}

/// Build `(fingerprint -> noise public key)` and `(fingerprint -> cert)`.
fn context_maps(state: &Arc<NodeState>) -> Result<(NoiseKeys, CertMap)> {
    let store = state
        .trust
        .lock()
        .map_err(|_| anyhow!("trust store poisoned"))?;
    let mut noise = HashMap::new();
    let mut certs = HashMap::new();
    for peer in store.peers(1000)? {
        if let Some((descriptor_bytes, _signature)) = store.descriptor_of(&peer.fingerprint)?
            && let Ok(descriptor) = Descriptor::from_canonical(&descriptor_bytes)
        {
            noise.insert(peer.fingerprint.clone(), descriptor.noise_x25519_pub);
        }
        if let Ok(cert) = hex::decode(&peer.public_key_hex) {
            certs.insert(peer.fingerprint, cert);
        }
    }
    Ok((noise, certs))
}

/// Queue an anonymous message for the next round.
pub fn queue(state: &Arc<NodeState>, channel: &str, text: &str) -> Result<()> {
    if text.len() + 36 > DCNET_PAYLOAD_LEN {
        bail!(
            "anonymous message too long (max {} bytes)",
            DCNET_PAYLOAD_LEN - 36
        );
    }
    let mut driver = state
        .rounds
        .lock()
        .map_err(|_| anyhow!("round driver poisoned"))?;
    driver.queue_message(channel, text);
    Ok(())
}

/// Scheduler tick: expire rounds, apply reputation, start queued rounds.
pub fn tick(state: &Arc<NodeState>) -> Result<()> {
    let (noise, certs) = context_maps(state)?;
    let my_uid = state.fingerprint();
    let secret = state.identity.noise_secret();
    let context = DriverContext {
        identity: &state.identity,
        my_uid: &my_uid,
        noise_secret: &secret,
        peer_noise: &noise,
        peer_certs: &certs,
    };

    let mut outgoing: Vec<(String, Object)> = Vec::new();
    {
        let mut driver = state
            .rounds
            .lock()
            .map_err(|_| anyhow!("round driver poisoned"))?;
        let failures = driver.tick(&context);
        if !failures.is_empty() {
            let mut reputation = state
                .reputation
                .lock()
                .map_err(|_| anyhow!("reputation tracker poisoned"))?;
            for failure in failures {
                tracing::info!(
                    round_id = failure.round_id,
                    missing = ?failure.missing,
                    "round expired with missing shares"
                );
                for missing in failure.missing {
                    if reputation.penalize(&missing) {
                        state.emit(NodeEvent::PeerEvicted {
                            fingerprint: missing,
                        });
                    }
                }
            }
        }

        let participants = participants(state);
        if participants.len() >= 2 && driver.queued_len() > 0 {
            outgoing = driver.initiate_next(&participants, &context)?;
        }
    }

    send_outgoing(state, outgoing);
    Ok(())
}

/// Handle an inbound round object.
pub fn handle_round(state: &Arc<NodeState>, object: &Object) -> Result<()> {
    let (noise, certs) = context_maps(state)?;
    let my_uid = state.fingerprint();
    let secret = state.identity.noise_secret();
    let context = DriverContext {
        identity: &state.identity,
        my_uid: &my_uid,
        noise_secret: &secret,
        peer_noise: &noise,
        peer_certs: &certs,
    };

    let mut outgoing: Vec<(String, Object)> = Vec::new();
    let mut extracted = Vec::new();
    let mut completed = Vec::new();
    {
        let mut driver: std::sync::MutexGuard<'_, RoundDriver> = state
            .rounds
            .lock()
            .map_err(|_| anyhow!("round driver poisoned"))?;
        let action = driver.handle(object, &context);
        outgoing.extend(action.outgoing);
        extracted.extend(action.extracted);
        completed.extend(action.completed);
        outgoing.extend(driver.drain_pending_outgoing());
    }

    // A completed round proves every participant sent its share, so strikes
    // are consecutive rather than cumulative.
    if !completed.is_empty() {
        let mut reputation = state
            .reputation
            .lock()
            .map_err(|_| anyhow!("reputation tracker poisoned"))?;
        for completion in &completed {
            for participant in &completion.participants {
                reputation.reward(participant);
            }
            tracing::debug!(round_id = completion.round_id, "round completed");
        }
    }

    send_outgoing(state, outgoing);
    for item in extracted {
        tracing::info!(
            channel = item.channel,
            round_id = item.round_id,
            "anonymous message extracted"
        );
        state.emit(NodeEvent::Anonymous {
            channel: item.channel,
            text: item.text,
            round_id: item.round_id,
        });
    }
    Ok(())
}

fn send_outgoing(state: &Arc<NodeState>, outgoing: Vec<(String, Object)>) {
    for (target, object) in outgoing {
        match object.to_canonical_bytes() {
            Ok(bytes) => {
                if let Err(error) = state.pool.try_send(&target, bytes) {
                    tracing::debug!(%target, "round send failed: {error}");
                }
            }
            Err(error) => tracing::warn!("cannot encode round object: {error}"),
        }
    }
}
