//! Replication policy.
//!
//! Chunks are stored on the `replication` nodes whose ids are XOR-closest to
//! the chunk hash. These helpers are pure functions so the policy can be
//! unit tested and reused by the simulator.

use crate::dht::{Contact, NodeId, cmp_distance};

/// Sort contacts by XOR distance to `key`.
pub fn sorted_by_distance(key: &[u8; 32], candidates: &[Contact]) -> Vec<Contact> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| cmp_distance(key, &a.id, &b.id));
    sorted
}

/// Choose up to `count` providers for `key`.
pub fn providers_for(key: &[u8; 32], candidates: &[Contact], count: usize) -> Vec<Contact> {
    let mut sorted = sorted_by_distance(key, candidates);
    sorted.truncate(count);
    sorted
}

/// Decide whether the local node is among the `replication` closest for `key`.
pub fn should_store(local: &NodeId, key: &[u8; 32], peers: &[Contact], replication: usize) -> bool {
    if replication == 0 {
        return false;
    }
    let mut ids: Vec<NodeId> = peers.iter().map(|contact| contact.id).collect();
    ids.push(*local);
    ids.sort_by(|a, b| cmp_distance(key, a, b));
    ids.iter().take(replication).any(|id| id == local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(byte: u8) -> Contact {
        Contact {
            id: [byte; 32],
            fingerprint: format!("FP{byte}"),
        }
    }

    #[test]
    fn providers_are_the_closest() {
        let candidates = vec![contact(0xf0), contact(0x10), contact(0x80)];
        let key = [0x10u8; 32];
        let providers = providers_for(&key, &candidates, 1);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, [0x10u8; 32]);

        let providers = providers_for(&key, &candidates, 2);
        assert_eq!(providers.len(), 2);
        assert!(providers.iter().any(|p| p.id == [0x80u8; 32]));
    }

    #[test]
    fn should_store_checks_the_closest_set() {
        let key = [0x00u8; 32];
        let peers = vec![contact(0x80), contact(0x40)];
        // Local id 0x10 is closer to the key than both peers.
        assert!(should_store(&[0x10u8; 32], &key, &peers, 1));
        assert!(should_store(&[0x10u8; 32], &key, &peers, 3));
        // Local id 0xff is farther than two closer peers.
        assert!(!should_store(&[0xffu8; 32], &key, &peers, 2));
        assert!(should_store(&[0xffu8; 32], &key, &peers, 3));
        // Zero replication stores nothing.
        assert!(!should_store(&[0x10u8; 32], &key, &peers, 0));
    }

    #[test]
    fn empty_peers_always_store_locally() {
        assert!(should_store(&[7u8; 32], &[0u8; 32], &[], 2));
    }
}
