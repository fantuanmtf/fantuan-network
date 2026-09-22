//! Simplified Kademlia routing table.
//!
//! Node ids are 32-byte BLAKE3 digests of fingerprints, so XOR distance is
//! available in the same space as chunk hashes. Contacts are kept in 256
//! k-buckets indexed by the leading-zero count of the XOR distance; a full
//! bucket keeps its existing members (least-recently-seen eviction is out of
//! scope for the current stage).

/// A node identifier.
pub type NodeId = [u8; 32];

/// Derive a node id from a fingerprint.
pub fn node_id(fingerprint: &str) -> NodeId {
    *blake3::hash(fingerprint.as_bytes()).as_bytes()
}

/// XOR distance between two ids.
pub fn distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = a[index] ^ b[index];
    }
    out
}

/// Bucket index: leading zero bits of the XOR distance (0 for the first
/// differing bit in the top byte, up to 255).
pub fn bucket_index(local: &NodeId, remote: &NodeId) -> usize {
    let distance = distance(local, remote);
    for (index, byte) in distance.iter().enumerate() {
        if *byte != 0 {
            return index * 8 + byte.leading_zeros() as usize;
        }
    }
    255
}

/// Compare two ids by distance to a target.
pub fn cmp_distance(target: &NodeId, a: &NodeId, b: &NodeId) -> std::cmp::Ordering {
    distance(target, a).cmp(&distance(target, b))
}

/// A known peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// Node id.
    pub id: NodeId,
    /// Peer fingerprint.
    pub fingerprint: String,
}

/// Kademlia routing table.
pub struct RoutingTable {
    local: NodeId,
    k: usize,
    buckets: Vec<Vec<Contact>>,
}

impl RoutingTable {
    /// Create a table for `local` with bucket size `k`.
    pub fn new(local: NodeId, k: usize) -> Self {
        Self {
            local,
            k,
            buckets: vec![Vec::new(); 256],
        }
    }

    /// Insert or refresh a contact. Returns false when it was dropped.
    pub fn insert(&mut self, contact: Contact) -> bool {
        if contact.id == self.local {
            return false;
        }
        let bucket = bucket_index(&self.local, &contact.id);
        let entries = &mut self.buckets[bucket];
        if let Some(position) = entries.iter().position(|entry| entry.id == contact.id) {
            entries.remove(position);
            entries.push(contact);
            return true;
        }
        if entries.len() < self.k {
            entries.push(contact);
            return true;
        }
        false
    }

    /// The `count` closest contacts to `target` (excluding the local node).
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<Contact> {
        let mut contacts: Vec<Contact> = self.buckets.iter().flatten().cloned().collect();
        contacts.sort_by(|a, b| cmp_distance(target, &a.id, &b.id));
        contacts.truncate(count);
        contacts
    }

    /// All known contacts.
    pub fn contacts(&self) -> Vec<Contact> {
        self.buckets.iter().flatten().cloned().collect()
    }

    /// Number of contacts.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id_byte: u8) -> Contact {
        Contact {
            id: [id_byte; 32],
            fingerprint: format!("FP{id_byte}"),
        }
    }

    #[test]
    fn distance_and_bucket() {
        let local = [0u8; 32];
        assert_eq!(distance(&local, &local), [0u8; 32]);
        // First byte differs at the highest bit -> bucket 0.
        let mut remote = [0u8; 32];
        remote[0] = 0x80;
        assert_eq!(bucket_index(&local, &remote), 0);
        // First byte equal, second differs at the highest bit -> bucket 8.
        let mut remote = [0u8; 32];
        remote[1] = 0x80;
        assert_eq!(bucket_index(&local, &remote), 8);
    }

    #[test]
    fn insert_refresh_and_capacity() {
        let mut table = RoutingTable::new([0u8; 32], 2);
        // 0x04, 0x05 and 0x06 all land in the same bucket.
        assert!(table.insert(contact(4)));
        assert!(table.insert(contact(5)));
        assert!(!table.insert(contact(6)), "bucket is full");
        assert_eq!(table.len(), 2);
        // Refreshing keeps it at capacity.
        assert!(table.insert(contact(4)));
        assert_eq!(table.len(), 2);
        // The local node is never inserted.
        assert!(!table.insert(Contact {
            id: [0u8; 32],
            fingerprint: "self".to_string()
        }));
    }

    #[test]
    fn closest_orders_by_xor_distance() {
        let mut table = RoutingTable::new([0u8; 32], 8);
        // Spread contacts across buckets.
        let mut ids = [[0x80u8; 32], [0x40u8; 32], [0x10u8; 32]];
        for (index, id) in ids.iter_mut().enumerate() {
            table.insert(Contact {
                id: *id,
                fingerprint: format!("FP{index}"),
            });
        }
        let target = [0x10u8; 32];
        let closest = table.closest(&target, 2);
        assert_eq!(closest.len(), 2);
        assert_eq!(closest[0].id, target, "exact match comes first");
    }
}
