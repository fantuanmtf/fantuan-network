//! Round identity and round context (DC-Net v2).
//!
//! Frozen specification (`docs/PROTOCOL.md` section 11):
//!
//! ```text
//! RoundIdentity = (initiator, epoch, instance)
//! RoundContext  = (version, channel, declared_set, deadline_secs, payload_len)
//!
//! CH        = u32(len, big endian) ‖ UTF-8 bytes
//! SET       = u32(count, big endian) ‖ count × 32B, ascending by raw bytes
//! CTX_BYTES = u8(version) ‖ CH ‖ SET ‖ u64(deadline_secs, BE) ‖ u32(payload_len, BE)
//! CTXH      = BLAKE3("fantuan-round-context-v1" ‖ CTX_BYTES)
//! identity  = initiator(32B) ‖ u64(epoch, BE) ‖ instance(16B)
//! ```
//!
//! Identities are [`fantuan_identity`] protocol identities (`proto_id`), not
//! OpenPGP fingerprints. Every integer is big endian; length prefixes appear
//! only on `CH`. The context hash covers every field that changes a round's
//! meaning, so share, ACK and key-derivation domains can bind `CTXH` instead
//! of repeating the fields, and objects can never be transplanted between two
//! contexts that share a `RoundIdentity`.

use crate::dcnet::{DCNET_MAX_DEADLINE_SECS, DCNET_MAX_PARTICIPANTS, DCNET_MIN_PAYLOAD_LEN};
use crate::error::{MsgError, Result};
use crate::post::valid_topic;
use fantuan_identity::PROTO_ID_LEN;

/// Round context format version bound into the context and every preimage.
pub const ROUND_CONTEXT_VERSION: u8 = 2;
/// Domain separator for the context hash.
pub const CONTEXT_HASH_DOMAIN: &[u8] = b"fantuan-round-context-v1";
/// Width of a context hash, in bytes.
pub const CONTEXT_HASH_LEN: usize = 32;
/// Width of a round instance value, in bytes.
pub const INSTANCE_LEN: usize = 16;
/// Smallest declared set a round may have.
pub const DCNET_MIN_PARTICIPANTS: usize = 2;

/// The identity of one round instance: `(initiator, epoch, instance)`.
///
/// `epoch` orders rounds within one initiator's namespace and is never reused;
/// `instance` is a fresh random value that keeps key material and signatures
/// unique even if an epoch is somehow repeated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoundIdentity {
    /// Protocol identity of the initiator.
    pub initiator: [u8; PROTO_ID_LEN],
    /// Initiator-scoped round counter.
    pub epoch: u64,
    /// Random per-attempt instance value.
    pub instance: [u8; INSTANCE_LEN],
}

impl RoundIdentity {
    /// Create a round identity.
    pub fn new(initiator: [u8; PROTO_ID_LEN], epoch: u64, instance: [u8; INSTANCE_LEN]) -> Self {
        Self {
            initiator,
            epoch,
            instance,
        }
    }

    /// Generate a fresh 128-bit instance value from the OS CSPRNG.
    ///
    /// Never derived from a clock, a counter or persisted state: a rolled-back
    /// node must still produce instance values it has never used before.
    pub fn fresh_instance() -> Result<[u8; INSTANCE_LEN]> {
        let mut instance = [0u8; INSTANCE_LEN];
        getrandom::fill(&mut instance)
            .map_err(|error| MsgError::Encoding(format!("entropy failure: {error}")))?;
        Ok(instance)
    }

    /// The frozen byte layout used by every signature and KDF preimage:
    /// `initiator(32B) ‖ u64(epoch, BE) ‖ instance(16B)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROTO_ID_LEN + 8 + INSTANCE_LEN);
        out.extend_from_slice(&self.initiator);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.instance);
        out
    }
}

/// Everything that defines the semantics of one round, except its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundContext {
    version: u8,
    channel: String,
    declared_set: Vec<[u8; PROTO_ID_LEN]>,
    deadline_secs: u64,
    payload_len: u32,
}

impl RoundContext {
    /// Build a context for a round we are starting or joining.
    ///
    /// The declared set is canonicalised (sorted ascending); duplicate entries
    /// are rejected rather than merged, because a set that lists a participant
    /// twice is malformed and must not silently become a valid round.
    pub fn new(
        channel: &str,
        mut declared_set: Vec<[u8; PROTO_ID_LEN]>,
        deadline_secs: u64,
        payload_len: u32,
    ) -> Result<Self> {
        Self::check_ranges(channel, declared_set.len(), deadline_secs, payload_len)?;
        declared_set.sort_unstable();
        if declared_set.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MsgError::Encoding(
                "declared set contains a duplicate participant".to_string(),
            ));
        }
        Ok(Self::assemble(
            channel,
            declared_set,
            deadline_secs,
            payload_len,
        ))
    }

    /// Build a context from decoded fields, requiring the canonical form.
    ///
    /// Unlike [`RoundContext::new`] this never reorders: a declared set that
    /// arrives unsorted or with duplicates is rejected, so two decoders can
    /// never disagree about the bytes a context hashes.
    pub fn from_canonical_parts(
        channel: &str,
        declared_set: Vec<[u8; PROTO_ID_LEN]>,
        deadline_secs: u64,
        payload_len: u32,
    ) -> Result<Self> {
        Self::check_ranges(channel, declared_set.len(), deadline_secs, payload_len)?;
        if declared_set.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(MsgError::Encoding(
                "declared set is not strictly ascending".to_string(),
            ));
        }
        Ok(Self::assemble(
            channel,
            declared_set,
            deadline_secs,
            payload_len,
        ))
    }

    fn check_ranges(
        channel: &str,
        participants: usize,
        deadline_secs: u64,
        payload_len: u32,
    ) -> Result<()> {
        if !valid_topic(channel) {
            return Err(MsgError::Encoding("invalid round channel".to_string()));
        }
        if !(DCNET_MIN_PARTICIPANTS..=DCNET_MAX_PARTICIPANTS).contains(&participants) {
            return Err(MsgError::TooLarge(format!(
                "round has {participants} participants (expected {DCNET_MIN_PARTICIPANTS}..={DCNET_MAX_PARTICIPANTS})"
            )));
        }
        if !(1..=DCNET_MAX_DEADLINE_SECS).contains(&deadline_secs) {
            return Err(MsgError::TooLarge(
                "round deadline out of range".to_string(),
            ));
        }
        let payload_len = payload_len as usize;
        if !(DCNET_MIN_PAYLOAD_LEN..=crate::dcnet::DCNET_MAX_PAYLOAD_LEN).contains(&payload_len) {
            return Err(MsgError::TooLarge(
                "round payload length out of range".to_string(),
            ));
        }
        Ok(())
    }

    fn assemble(
        channel: &str,
        declared_set: Vec<[u8; PROTO_ID_LEN]>,
        deadline_secs: u64,
        payload_len: u32,
    ) -> Self {
        Self {
            version: ROUND_CONTEXT_VERSION,
            channel: channel.to_string(),
            declared_set,
            deadline_secs,
            payload_len,
        }
    }

    /// Context format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Channel label.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Declared participants, ascending by raw bytes.
    pub fn declared_set(&self) -> &[[u8; PROTO_ID_LEN]] {
        &self.declared_set
    }

    /// Round deadline in seconds.
    pub fn deadline_secs(&self) -> u64 {
        self.deadline_secs
    }

    /// Share length every participant must use.
    pub fn payload_len(&self) -> u32 {
        self.payload_len
    }

    /// The frozen context byte layout.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 4 + self.channel.len() + 4 + self.declared_set.len() * PROTO_ID_LEN + 12,
        );
        out.push(self.version);
        out.extend_from_slice(&(self.channel.len() as u32).to_be_bytes());
        out.extend_from_slice(self.channel.as_bytes());
        out.extend_from_slice(&(self.declared_set.len() as u32).to_be_bytes());
        for participant in &self.declared_set {
            out.extend_from_slice(participant);
        }
        out.extend_from_slice(&self.deadline_secs.to_be_bytes());
        out.extend_from_slice(&self.payload_len.to_be_bytes());
        out
    }

    /// `CTXH = BLAKE3("fantuan-round-context-v1" ‖ CTX_BYTES)`.
    pub fn hash(&self) -> [u8; CONTEXT_HASH_LEN] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTEXT_HASH_DOMAIN);
        hasher.update(&self.canonical_bytes());
        let mut hash = [0u8; CONTEXT_HASH_LEN];
        hash.copy_from_slice(&hasher.finalize().as_bytes()[..CONTEXT_HASH_LEN]);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(byte: u8) -> [u8; PROTO_ID_LEN] {
        [byte; PROTO_ID_LEN]
    }

    fn sample() -> RoundContext {
        RoundContext::new("#anon", vec![pid(3), pid(1), pid(2)], 15, 1024).expect("context")
    }

    /// T-CONTEXT-HASH-DERIVE: the byte layout and the hash must match an
    /// independent reimplementation built from the specification text.
    #[test]
    fn context_hash_matches_an_independent_reimplementation() {
        let context = sample();

        let mut expected = Vec::new();
        expected.push(2u8);
        expected.extend_from_slice(&(context.channel().len() as u32).to_be_bytes());
        expected.extend_from_slice(context.channel().as_bytes());
        expected.extend_from_slice(&(context.declared_set().len() as u32).to_be_bytes());
        for participant in context.declared_set() {
            expected.extend_from_slice(participant);
        }
        expected.extend_from_slice(&context.deadline_secs().to_be_bytes());
        expected.extend_from_slice(&context.payload_len().to_be_bytes());
        assert_eq!(context.canonical_bytes(), expected);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fantuan-round-context-v1");
        hasher.update(&expected);
        assert_eq!(
            context.hash().as_slice(),
            &hasher.finalize().as_bytes()[..32]
        );
        assert_eq!(context.hash().len(), CONTEXT_HASH_LEN);

        // Field layout spot checks: version first, channel length second.
        assert_eq!(context.canonical_bytes()[0], ROUND_CONTEXT_VERSION);
        assert_eq!(
            &context.canonical_bytes()[1..5],
            &(context.channel().len() as u32).to_be_bytes()
        );
    }

    /// T-CONTEXT-DUP: identical contexts hash identically, order-independent
    /// inputs canonicalise to the same bytes, duplicates are rejected, and the
    /// decoder refuses non-canonical sets.
    #[test]
    fn context_duplicates_and_canonicalisation() {
        // Same context, twice: the classification of a repeated start relies
        // on identical bytes producing an identical hash.
        assert_eq!(sample().hash(), sample().hash());
        assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());

        // Input order does not matter for local construction.
        let ordered = RoundContext::new("#anon", vec![pid(1), pid(2), pid(3)], 15, 1024).unwrap();
        assert_eq!(ordered.canonical_bytes(), sample().canonical_bytes());

        // A participant listed twice is malformed, not silently merged.
        assert!(RoundContext::new("#anon", vec![pid(1), pid(1), pid(2)], 15, 1024).is_err());

        // Decoded fields must already be canonical.
        assert!(
            RoundContext::from_canonical_parts("#anon", vec![pid(3), pid(1), pid(2)], 15, 1024)
                .is_err(),
            "an unsorted declared set must be rejected on decode"
        );
        assert!(
            RoundContext::from_canonical_parts("#anon", vec![pid(1), pid(1)], 15, 1024).is_err(),
            "a duplicate declared set must be rejected on decode"
        );
        assert_eq!(
            RoundContext::from_canonical_parts("#anon", vec![pid(1), pid(2), pid(3)], 15, 1024)
                .expect("canonical set decodes")
                .hash(),
            sample().hash()
        );

        // Duplicate/equivocation classification compares contexts by hash, so
        // any difference in any field must change it.
        let base = sample().hash();
        let variants = [
            RoundContext::new("#other", vec![pid(1), pid(2), pid(3)], 15, 1024).unwrap(),
            RoundContext::new("#anon", vec![pid(1), pid(2), pid(4)], 15, 1024).unwrap(),
            RoundContext::new("#anon", vec![pid(1), pid(2), pid(3), pid(4)], 15, 1024).unwrap(),
            RoundContext::new("#anon", vec![pid(1), pid(2), pid(3)], 14, 1024).unwrap(),
            RoundContext::new("#anon", vec![pid(1), pid(2), pid(3)], 15, 2048).unwrap(),
        ];
        for variant in variants {
            assert_ne!(variant.hash(), base, "a changed field must change CTXH");
            assert_ne!(variant.canonical_bytes(), sample().canonical_bytes());
        }
    }

    /// L5 ranges: every documented bound is enforced, at the boundary.
    #[test]
    fn context_ranges_are_enforced() {
        assert!(RoundContext::new("#anon", vec![pid(1)], 15, 1024).is_err());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 15, 1024).is_ok());
        let sixteen: Vec<_> = (1..=16u8).map(pid).collect();
        assert!(RoundContext::new("#anon", sixteen.clone(), 15, 1024).is_ok());
        let seventeen: Vec<_> = (1..=17u8).map(pid).collect();
        assert!(RoundContext::new("#anon", seventeen, 15, 1024).is_err());

        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 0, 1024).is_err());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 30, 1024).is_ok());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 31, 1024).is_err());

        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 15, 35).is_err());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 15, 36).is_ok());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 15, 4096).is_ok());
        assert!(RoundContext::new("#anon", vec![pid(1), pid(2)], 15, 4097).is_err());

        assert!(RoundContext::new("", vec![pid(1), pid(2)], 15, 1024).is_err());
        assert!(RoundContext::new("#bad channel", vec![pid(1), pid(2)], 15, 1024).is_err());
    }

    /// The identity layout is frozen: it is repeated in every preimage.
    #[test]
    fn round_identity_bytes_are_frozen() {
        let identity = RoundIdentity::new(pid(7), 0x0102030405060708, [9u8; INSTANCE_LEN]);
        let bytes = identity.canonical_bytes();
        assert_eq!(bytes.len(), PROTO_ID_LEN + 8 + INSTANCE_LEN);
        assert_eq!(&bytes[..PROTO_ID_LEN], &pid(7));
        assert_eq!(
            &bytes[PROTO_ID_LEN..PROTO_ID_LEN + 8],
            &0x0102030405060708u64.to_be_bytes(),
            "epoch is big endian"
        );
        assert_eq!(&bytes[PROTO_ID_LEN + 8..], &[9u8; INSTANCE_LEN]);

        // Fresh instances come from the OS CSPRNG, not from a counter.
        let first = RoundIdentity::fresh_instance().expect("instance");
        let second = RoundIdentity::fresh_instance().expect("instance");
        assert_ne!(first, second);
    }
}
