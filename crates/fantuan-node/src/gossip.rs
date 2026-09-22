//! Gossip exchange: peer descriptors and trust vouches.
//!
//! On every new session we offer our known peer list; incoming lists are
//! verified before anything is stored: descriptors must carry their own valid
//! signature, and vouches must verify against the signer's stored
//! certificate.

use crate::state::NodeState;
use anyhow::{Result, anyhow};
use fantuan_core::time;
use fantuan_identity::{Descriptor, TrustGraph, TrustVouch};
use fantuan_msg::{Gossip, MAX_ANNOUNCEMENTS, MAX_VOUCHES, Object};
use serde_bytes::ByteBuf;
use std::sync::Arc;

/// Assemble the gossip list we send to a peer.
pub fn build(state: &Arc<NodeState>) -> Gossip {
    let own = state.fingerprint();
    let mut gossip = Gossip::new();

    // Our own descriptor (with its self-signature) is the primary way peers
    // learn about us.
    if let Ok(descriptor) = state.identity.descriptor().canonical_bytes() {
        gossip.push_announcement(descriptor, state.identity.descriptor_signature().to_vec());
    }

    let Ok(store) = state.trust.lock() else {
        return gossip;
    };

    if let Ok(descriptors) = store.descriptors(MAX_ANNOUNCEMENTS + 1) {
        for (fingerprint, descriptor, signature) in descriptors {
            if fingerprint == own || gossip.announcements.len() >= MAX_ANNOUNCEMENTS {
                continue;
            }
            gossip.push_announcement(descriptor, signature);
        }
    }

    if let Ok(relationships) = store.relationships() {
        for relationship in relationships {
            if relationship.signature.is_empty() || gossip.vouches.len() >= MAX_VOUCHES {
                continue;
            }
            gossip.push_vouch(TrustVouch {
                signer: relationship.signer,
                subject: relationship.subject,
                level: relationship.level,
                timestamp: relationship.updated_at,
                signature: ByteBuf::from(relationship.signature),
            });
        }
    }
    gossip
}

/// Broadcast our current gossip list to all peers except `exclude`.
pub fn broadcast(state: &Arc<NodeState>, exclude: &str) {
    let gossip = build(state);
    if gossip.is_empty() {
        return;
    }
    let Ok(bytes) = Object::Gossip(gossip).to_canonical_bytes() else {
        return;
    };
    for peer in state.pool.peers() {
        if peer != exclude {
            let _ = state.pool.try_send(&peer, bytes.clone());
        }
    }
}

/// Verify and store a received gossip list.
///
/// Returns the number of accepted announcements.
pub fn handle(state: &Arc<NodeState>, via: &str, gossip: &Gossip) -> Result<usize> {
    gossip.validate_limits()?;
    let own = state.fingerprint();
    let mut accepted = 0usize;
    let mut learned: Vec<(String, String)> = Vec::new();

    {
        let store = state
            .trust
            .lock()
            .map_err(|_| anyhow!("trust store poisoned"))?;

        for announcement in &gossip.announcements {
            let descriptor = match Descriptor::from_canonical(&announcement.descriptor) {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    tracing::warn!("gossip: bad descriptor: {error}");
                    continue;
                }
            };
            if descriptor.fingerprint == own {
                continue;
            }
            if let Err(error) = descriptor.verify(&announcement.signature) {
                tracing::warn!(
                    "gossip: descriptor signature rejected for {}: {error}",
                    descriptor.fingerprint
                );
                continue;
            }
            // Optional Sybil guard: third-party descriptors must be vouched
            // for by the peer forwarding them.
            if state.config.require_vouch_for_gossip
                && descriptor.fingerprint != via
                && store.relationship(via, &descriptor.fingerprint)?.is_none()
            {
                tracing::debug!(
                    %via,
                    subject = %descriptor.fingerprint,
                    "gossip: no vouch for third-party descriptor; rejected"
                );
                continue;
            }
            // Only genuinely new descriptors count as "accepted"; otherwise
            // two peers would echo gossip at each other forever.
            let already_known = store.descriptor_of(&descriptor.fingerprint)?.is_some();
            store.upsert_peer(
                &descriptor.fingerprint,
                &descriptor.uid,
                &hex::encode(&descriptor.openpgp_cert),
                time::now_unix(),
            )?;
            store.store_descriptor(
                &descriptor.fingerprint,
                &announcement.descriptor,
                &announcement.signature,
            )?;
            if !already_known {
                learned.push((descriptor.fingerprint.clone(), via.to_string()));
                accepted += 1;
            }
        }

        for vouch in &gossip.vouches {
            let Some(peer) = store.get_peer(&vouch.signer)? else {
                tracing::debug!("gossip: vouch from unknown signer {}", vouch.signer);
                continue;
            };
            let Ok(cert_bytes) = hex::decode(&peer.public_key_hex) else {
                continue;
            };
            if let Err(error) = vouch.verify_cert_bytes(&cert_bytes) {
                tracing::warn!("gossip: vouch rejected from {}: {error}", vouch.signer);
                continue;
            }
            store.set_relationship(
                &vouch.signer,
                &vouch.subject,
                vouch.level,
                vouch.timestamp,
                &vouch.signature,
            )?;
        }

        // Recompute trust scores so local policy sees fresh levels.
        let mut graph = TrustGraph::new(&store, &own);
        let updated = graph.refresh_scores().unwrap_or(0);
        if updated > 0 {
            tracing::debug!("gossip: refreshed {updated} trust scores");
        }
    }

    for (fingerprint, hop) in learned {
        state.record_route(&fingerprint, &hop);
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MessageStore;
    use fantuan_core::config::NodeConfig;
    use fantuan_identity::{Identity, TrustStore};
    use tokio::sync::mpsc;

    fn state(require_vouch: bool) -> Arc<NodeState> {
        let identity = Arc::new(Identity::generate("bob", "dest-bob").expect("identity"));
        let trust = TrustStore::in_memory().expect("trust");
        let messages = MessageStore::in_memory().expect("messages");
        let chunks = fantuan_storage::ChunkCache::in_memory(1 << 20).expect("chunks");
        let (events, _rx) = mpsc::unbounded_channel();
        let config = NodeConfig {
            require_vouch_for_gossip: require_vouch,
            ..NodeConfig::default()
        };
        NodeState::new(identity, config, trust, messages, chunks, events)
    }

    fn announcement(identity: &Identity) -> Gossip {
        let mut gossip = Gossip::new();
        gossip.push_announcement(
            identity.descriptor().canonical_bytes().expect("descriptor"),
            identity.descriptor_signature().to_vec(),
        );
        gossip
    }

    #[test]
    fn third_party_descriptor_requires_a_vouch_when_configured() {
        let state = state(true);
        let carol = Identity::generate("carol", "dest-carol").expect("identity");
        let gossip = announcement(&carol);

        // Unknown forwarder without a vouch: rejected.
        assert_eq!(handle(&state, "FP-VIA", &gossip).expect("handle"), 0);

        // With a vouch from the forwarder, the descriptor is accepted.
        {
            let store = state.trust.lock().expect("trust");
            store
                .set_relationship("FP-VIA", &carol.fingerprint_hex(), 1, 1, b"sig")
                .expect("vouch");
        }
        assert_eq!(handle(&state, "FP-VIA", &gossip).expect("handle"), 1);
    }

    #[test]
    fn direct_descriptor_needs_no_vouch() {
        let state = state(true);
        let carol = Identity::generate("carol", "dest-carol").expect("identity");
        let gossip = announcement(&carol);
        assert_eq!(
            handle(&state, &carol.fingerprint_hex(), &gossip).expect("handle"),
            1
        );
    }

    #[test]
    fn vouch_requirement_is_off_by_default() {
        let state = state(false);
        let carol = Identity::generate("carol", "dest-carol").expect("identity");
        let gossip = announcement(&carol);
        assert_eq!(handle(&state, "FP-VIA", &gossip).expect("handle"), 1);
    }
}
