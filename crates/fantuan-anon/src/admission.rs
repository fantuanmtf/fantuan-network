//! Round admission: the state-machine boundary around a round identity.
//!
//! Frozen specification (`docs/PROTOCOL.md` section 11, review findings
//! R1/R2/R5). The execution order is fixed:
//!
//! 1. stateless validation (format, version, ranges) — done by the caller /
//!    by [`fantuan_msg::RoundContext`] construction;
//! 2. start signature verification over `RoundIdentity ‖ CTX_BYTES` — the
//!    caller's job; only an [`AuthenticatedRound`] reaches this module;
//! 3. one atomic state section per namespace, entered by [`RoundAdmission`];
//! 4. classification, then commit.
//!
//! ```text
//! epoch < watermark                                      -> stale
//! epoch == watermark ∧ same instance ∧ same context hash  -> replay
//! epoch == watermark ∧ anything else                      -> equivocation
//! epoch > EPOCH_MAX_USABLE                               -> overflow
//! watermark < epoch <= EPOCH_MAX_USABLE                   -> candidate:
//!     accepted only when authenticated ∧ context valid ∧ membership valid
//! ```
//!
//! Classification depends only on the epoch and the initiator's stored state,
//! never on who is asking; membership gates only the *accept*. Nothing but an
//! accept writes state: no rejection may move the watermark, replace the
//! accepted instance or context, or produce a share, an extraction or a
//! reputation event. Unauthenticated input never reaches this module at all,
//! so it cannot even be classified.
//!
//! Durability: the state is committed through [`NamespaceStore`] *before* the
//! in-memory copy changes (write-before-act), so a crash can only leave the
//! namespace further ahead than the in-memory state, never behind — and,
//! because a retry always mints a new epoch, being ahead costs nothing.

use crate::error::Result;
use fantuan_identity::PROTO_ID_LEN;
use fantuan_msg::{CONTEXT_HASH_LEN, INSTANCE_LEN, RoundContext, RoundIdentity};
use std::collections::HashMap;

/// Highest epoch a round may use; above it the namespace is exhausted and
/// admission fails closed rather than wrapping.
pub const EPOCH_MAX_USABLE: u64 = u64::MAX - (1 << 16);

/// What was last accepted in one initiator's namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceState {
    /// Highest accepted epoch.
    watermark: u64,
    /// Instance of the accepted round at that epoch.
    instance: [u8; INSTANCE_LEN],
    /// Context hash of the accepted round at that epoch.
    context_hash: [u8; CONTEXT_HASH_LEN],
}

impl NamespaceState {
    /// Rebuild state from persisted parts (used when loading a log).
    pub fn from_parts(
        watermark: u64,
        instance: [u8; INSTANCE_LEN],
        context_hash: [u8; CONTEXT_HASH_LEN],
    ) -> Self {
        Self {
            watermark,
            instance,
            context_hash,
        }
    }

    /// Highest accepted epoch.
    pub fn watermark(&self) -> u64 {
        self.watermark
    }

    /// Instance of the accepted round.
    pub fn instance(&self) -> &[u8; INSTANCE_LEN] {
        &self.instance
    }

    /// Context hash of the accepted round.
    pub fn context_hash(&self) -> &[u8; CONTEXT_HASH_LEN] {
        &self.context_hash
    }
}

/// Where namespace watermarks are made durable.
///
/// `commit` must make the state durable (append + fsync) before it returns;
/// the admission machine updates its in-memory copy only after that. Losing a
/// committed record is a storage failure, not a protocol event.
pub trait NamespaceStore {
    /// Make `state` durable for `initiator`.
    fn commit(&mut self, initiator: &[u8; PROTO_ID_LEN], state: &NamespaceState) -> Result<()>;
}

/// A store that forgets everything on restart.
///
/// Only for tests and for hosts that have not enabled the durable log yet: it
/// provides no replay protection across restarts.
#[derive(Debug, Default)]
pub struct VolatileStore;

impl NamespaceStore for VolatileStore {
    fn commit(&mut self, _initiator: &[u8; PROTO_ID_LEN], _state: &NamespaceState) -> Result<()> {
        Ok(())
    }
}

/// A round whose start signature has already been verified.
///
/// Constructing this value asserts that step 2 of the frozen order happened.
/// The only legitimate producer is the v2 start verifier
/// (`DcRoundStart` verification, wired in the preimage step); tests construct
/// it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRound {
    identity: RoundIdentity,
    context: RoundContext,
    context_hash: [u8; CONTEXT_HASH_LEN],
}

impl AuthenticatedRound {
    /// Build from an authenticated start.
    ///
    /// The context hash is computed here rather than taken from the wire, so
    /// every node derives it from the same bytes.
    pub fn verified(identity: RoundIdentity, context: RoundContext) -> Self {
        let context_hash = context.hash();
        Self {
            identity,
            context,
            context_hash,
        }
    }

    /// Round identity.
    pub fn identity(&self) -> &RoundIdentity {
        &self.identity
    }

    /// Round context.
    pub fn context(&self) -> &RoundContext {
        &self.context
    }

    /// Context hash, recomputed from the context.
    pub fn context_hash(&self) -> &[u8; CONTEXT_HASH_LEN] {
        &self.context_hash
    }
}

/// Outcome of admitting one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Admitted: the only outcome that changes state.
    Accepted,
    /// In range for the namespace, but this node is not in the declared set.
    /// Classified as neither stale nor equivocation: it says nothing about the
    /// initiator's namespace, and it never moves the watermark.
    NotAMember,
    /// Below the accepted watermark.
    Stale,
    /// Same epoch, same instance and same context as the accepted round.
    Replay,
    /// Same epoch, but a different instance or a different context.
    Equivocation,
    /// Beyond [`EPOCH_MAX_USABLE`].
    Overflow,
    /// The durable commit failed, so nothing was accepted and nothing changed.
    ///
    /// The round is refused rather than admitted without durability: the
    /// watermark is the replay defence, so admitting without it would silently
    /// drop the guarantee.
    StoreFailed,
}

/// Namespace watermarks plus the store that makes them durable.
pub struct RoundAdmission<S: NamespaceStore> {
    namespaces: HashMap<[u8; PROTO_ID_LEN], NamespaceState>,
    store: S,
}

impl<S: NamespaceStore> RoundAdmission<S> {
    /// Create an admission machine with no known namespaces.
    pub fn new(store: S) -> Self {
        Self {
            namespaces: HashMap::new(),
            store,
        }
    }

    /// Restore a namespace from persisted state.
    pub fn restore(&mut self, initiator: [u8; PROTO_ID_LEN], state: NamespaceState) {
        self.namespaces.insert(initiator, state);
    }

    /// Read the accepted state of one namespace.
    pub fn state(&self, initiator: &[u8; PROTO_ID_LEN]) -> Option<&NamespaceState> {
        self.namespaces.get(initiator)
    }

    /// Number of namespaces with accepted state.
    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    /// Classify and, when everything holds, accept one round.
    ///
    /// `local` is our own protocol identity: the accept branch requires that
    /// the round's declared set contains us.
    pub fn admit(&mut self, local: &[u8; PROTO_ID_LEN], round: &AuthenticatedRound) -> Admission {
        let initiator = &round.identity.initiator;
        let epoch = round.identity.epoch;

        // Classification is decided from the epoch and the stored state only.
        if epoch > EPOCH_MAX_USABLE {
            return Admission::Overflow;
        }
        if let Some(current) = self.namespaces.get(initiator) {
            if epoch < current.watermark {
                return Admission::Stale;
            }
            if epoch == current.watermark {
                let same_instance = round.identity.instance == current.instance;
                let same_context = *round.context_hash() == current.context_hash;
                return if same_instance && same_context {
                    Admission::Replay
                } else {
                    Admission::Equivocation
                };
            }
        }

        // Candidate: the accept conjunction. Membership gates the accept only.
        if !round.context.declared_set().contains(local) {
            return Admission::NotAMember;
        }

        let next = NamespaceState {
            watermark: epoch,
            instance: round.identity.instance,
            context_hash: *round.context_hash(),
        };
        // Write-before-act: the durable commit must succeed before the
        // in-memory copy changes.
        if let Err(error) = self.store.commit(initiator, &next) {
            tracing::warn!("round admission could not persist namespace state: {error}");
            return Admission::StoreFailed;
        }
        self.namespaces.insert(*initiator, next);
        Admission::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AnonError;

    fn pid(byte: u8) -> [u8; PROTO_ID_LEN] {
        [byte; PROTO_ID_LEN]
    }

    /// Deterministic instance values: `[seed; 16]` keeps failures readable.
    fn instance(seed: u8) -> [u8; INSTANCE_LEN] {
        [seed; INSTANCE_LEN]
    }

    fn round(
        initiator: u8,
        epoch: u64,
        instance_seed: u8,
        members: &[u8],
        channel: &str,
    ) -> AuthenticatedRound {
        let context = RoundContext::new(
            channel,
            members.iter().copied().map(pid).collect(),
            15,
            1024,
        )
        .expect("context");
        AuthenticatedRound::verified(
            RoundIdentity::new(pid(initiator), epoch, instance(instance_seed)),
            context,
        )
    }

    /// A store that records every commit and can be told to fail.
    #[derive(Default)]
    struct RecordingStore {
        commits: Vec<([u8; PROTO_ID_LEN], NamespaceState)>,
        fail_on: Option<usize>,
    }

    impl NamespaceStore for RecordingStore {
        fn commit(&mut self, initiator: &[u8; PROTO_ID_LEN], state: &NamespaceState) -> Result<()> {
            if Some(self.commits.len()) == self.fail_on {
                return Err(AnonError::Round("disk full".to_string()));
            }
            self.commits.push((*initiator, *state));
            Ok(())
        }
    }

    const LOCAL: [u8; PROTO_ID_LEN] = [0xAA; PROTO_ID_LEN];

    /// T-EPOCH-MONOTONE: acceptance is monotone per namespace with no jump
    /// bound, and every non-accept case is classified.
    #[test]
    fn epoch_monotone_admission() {
        let mut admission = RoundAdmission::new(VolatileStore);

        // A far epoch is accepted: no jump bound exists, and a receiver that
        // never saw the earlier epochs must not be locked out (regression for
        // the removed MAX_EPOCH_JUMP rule).
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 101, 1, &[0xAA, 0xBB], "#anon")),
            Admission::Accepted
        );
        assert_eq!(admission.state(&pid(1)).expect("state").watermark(), 101);
        // The next epoch is fine.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 102, 2, &[0xAA, 0xBB], "#anon")),
            Admission::Accepted
        );

        // Same epoch, same instance and context: replay.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 102, 2, &[0xAA, 0xBB], "#anon")),
            Admission::Replay
        );
        // A round that a later epoch has superseded is stale, not a replay:
        // the epoch decides the class before instance or context are compared.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 101, 1, &[0xAA, 0xBB], "#anon")),
            Admission::Stale
        );
        // Same epoch, different instance: equivocation.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 102, 3, &[0xAA, 0xBB], "#anon")),
            Admission::Equivocation
        );
        // Same epoch, different context only: also equivocation.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 102, 2, &[0xAA, 0xBB], "#other")),
            Admission::Equivocation
        );
        // Below the watermark: stale, even with a different instance and
        // context. There is no unclassified case.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 5, 9, &[0xAA, 0xBB], "#other")),
            Admission::Stale
        );

        // The watermark never moved during any of those rejections.
        assert_eq!(admission.state(&pid(1)).expect("state").watermark(), 102);
        assert_eq!(
            admission.state(&pid(1)).expect("state").instance(),
            &instance(2)
        );
    }

    /// T-EPOCH-OVERFLOW: the namespace is exhausted above EPOCH_MAX_USABLE and
    /// refuses without wrapping or changing state.
    #[test]
    fn epoch_overflow_is_refused_without_state_change() {
        let mut admission = RoundAdmission::new(VolatileStore);
        assert_eq!(
            admission.admit(
                &LOCAL,
                &round(1, EPOCH_MAX_USABLE, 1, &[0xAA, 0xBB], "#anon")
            ),
            Admission::Accepted
        );
        assert_eq!(
            admission.admit(
                &LOCAL,
                &round(1, EPOCH_MAX_USABLE + 1, 2, &[0xAA, 0xBB], "#anon")
            ),
            Admission::Overflow
        );
        assert_eq!(
            admission.admit(&LOCAL, &round(1, u64::MAX, 3, &[0xAA, 0xBB], "#anon")),
            Admission::Overflow
        );
        assert_eq!(
            admission.state(&pid(1)).expect("state").watermark(),
            EPOCH_MAX_USABLE,
            "an overflow attempt must not move the watermark"
        );
    }

    /// T-EPOCH-ATOMIC-1: two instances for one epoch admit exactly one, and
    /// the winner is whichever arrived first — deterministically.
    #[test]
    fn concurrent_instances_admit_exactly_one() {
        for (first_seed, second_seed) in [(1u8, 2u8), (2, 1)] {
            let mut admission = RoundAdmission::new(VolatileStore);
            let first = round(1, 7, first_seed, &[0xAA, 0xBB], "#anon");
            let second = round(1, 7, second_seed, &[0xAA, 0xBB], "#anon");
            assert_eq!(admission.admit(&LOCAL, &first), Admission::Accepted);
            assert_eq!(
                admission.admit(&LOCAL, &second),
                Admission::Equivocation,
                "the second instance of an accepted epoch is an equivocation"
            );
            assert_eq!(
                admission.state(&pid(1)).expect("state").instance(),
                &instance(first_seed),
                "the first arrival owns the epoch"
            );
            // And the accepted one is still classified as a replay afterwards.
            assert_eq!(admission.admit(&LOCAL, &first), Admission::Replay);
        }
    }

    /// T-ROUND-CONTEXT-CONFLICT: one identity, two contexts — at most one is
    /// ever accepted, and the conflict is classified, not silently dropped.
    #[test]
    fn context_conflict_is_equivocation_and_never_a_second_accept() {
        let mut admission = RoundAdmission::new(VolatileStore);
        let context_a = round(1, 9, 4, &[0xAA, 0xBB], "#anon");
        let context_b = round(1, 9, 4, &[0xAA, 0xCC], "#anon"); // different declared set
        assert_ne!(context_a.context_hash(), context_b.context_hash());

        assert_eq!(admission.admit(&LOCAL, &context_a), Admission::Accepted);
        assert_eq!(admission.admit(&LOCAL, &context_b), Admission::Equivocation);
        assert_eq!(
            admission.state(&pid(1)).expect("state").context_hash(),
            context_a.context_hash(),
            "the accepted context is never replaced by a conflicting one"
        );
    }

    /// T-CONTEXT-ORDER-SPLIT: two nodes that see the conflicting contexts in
    /// opposite orders accept different ones. That divergence is specified and
    /// has no safety consequence: each node accepted exactly one context and
    /// refuses every later round under that epoch.
    #[test]
    fn order_split_across_nodes_has_no_second_acceptance() {
        let context_a = round(1, 9, 4, &[0xAA, 0xBB], "#anon");
        let context_b = round(1, 9, 4, &[0xAA, 0xCC], "#anon");

        let mut first_node = RoundAdmission::new(VolatileStore);
        assert_eq!(first_node.admit(&LOCAL, &context_a), Admission::Accepted);
        assert_eq!(
            first_node.admit(&LOCAL, &context_b),
            Admission::Equivocation
        );

        let mut second_node = RoundAdmission::new(VolatileStore);
        assert_eq!(second_node.admit(&LOCAL, &context_b), Admission::Accepted);
        assert_eq!(
            second_node.admit(&LOCAL, &context_a),
            Admission::Equivocation
        );

        assert_ne!(
            first_node.state(&pid(1)).expect("state").context_hash(),
            second_node.state(&pid(1)).expect("state").context_hash(),
            "the two views really do diverge"
        );
        // Neither node ever accepts a second context for that epoch.
        assert_eq!(
            first_node.admit(&LOCAL, &round(1, 9, 5, &[0xAA, 0xBB], "#anon")),
            Admission::Equivocation
        );
        assert_eq!(
            second_node.admit(&LOCAL, &round(1, 9, 5, &[0xAA, 0xBB], "#anon")),
            Admission::Equivocation
        );
    }

    /// A non-member round in range is refused *without* touching the
    /// namespace: an initiator cannot advance our watermark by inviting
    /// somebody else, so a later membership-valid round for the same epoch is
    /// still acceptable.
    #[test]
    fn non_member_rounds_do_not_move_the_watermark() {
        let mut admission = RoundAdmission::new(VolatileStore);
        let strangers = round(1, 11, 1, &[0xBB, 0xCC], "#anon");
        assert_eq!(admission.admit(&LOCAL, &strangers), Admission::NotAMember);
        assert!(admission.state(&pid(1)).is_none());
        assert_eq!(admission.namespace_count(), 0);

        // The same epoch, now naming us, is accepted.
        assert_eq!(
            admission.admit(&LOCAL, &round(1, 11, 2, &[0xAA, 0xBB], "#anon")),
            Admission::Accepted
        );
    }

    /// T-EPOCH-ATOMIC-4: only an accept writes state, and the durable commit
    /// happens before the in-memory change (write-before-act).
    #[test]
    fn only_accepts_change_state_and_commits_precede_the_write() {
        let mut admission = RoundAdmission::new(RecordingStore::default());
        let accepted = round(1, 3, 1, &[0xAA, 0xBB], "#anon");
        assert_eq!(admission.admit(&LOCAL, &accepted), Admission::Accepted);
        assert_eq!(admission.store.commits.len(), 1, "one commit per accept");

        for rejected in [
            accepted.clone(),                              // replay
            round(1, 3, 2, &[0xAA, 0xBB], "#anon"),        // equivocation
            round(1, 2, 3, &[0xAA, 0xBB], "#anon"),        // stale
            round(1, u64::MAX, 4, &[0xAA, 0xBB], "#anon"), // overflow
            round(1, 4, 5, &[0xBB, 0xCC], "#anon"),        // not a member
        ] {
            assert_ne!(admission.admit(&LOCAL, &rejected), Admission::Accepted);
        }
        assert_eq!(
            admission.store.commits.len(),
            1,
            "rejections must not commit anything"
        );

        // A failing commit refuses the round and leaves memory untouched.
        let mut failing = RoundAdmission::new(RecordingStore {
            commits: Vec::new(),
            fail_on: Some(0),
        });
        assert_eq!(failing.admit(&LOCAL, &accepted), Admission::StoreFailed);
        assert!(failing.state(&pid(1)).is_none(), "nothing was accepted");
        assert!(failing.store.commits.is_empty());
    }

    /// T-EPOCH-ATOMIC-3: over a long deterministic sequence, the invariants
    /// hold — the watermark never decreases, only accepts change state, and an
    /// accepted round is always a replay when repeated.
    #[test]
    fn admission_property_sequence_holds_invariants() {
        let mut admission = RoundAdmission::new(VolatileStore);
        // Deterministic LCG: no external RNG dependency, reproducible runs.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };

        let mut watermarks: HashMap<[u8; PROTO_ID_LEN], u64> = HashMap::new();
        let mut accepted: Vec<(u8, u64, u8, &'static str, u8)> = Vec::new();
        for _ in 0..512 {
            let initiator = 1 + (next() % 4) as u8;
            let epoch = (next() % 40) as u64;
            let instance_seed = (next() % 6) as u8;
            let member = if next() % 8 == 0 { 0xBB } else { 0xAA };
            let channel = if next() % 5 == 0 { "#other" } else { "#anon" };
            let candidate = round(initiator, epoch, instance_seed, &[member, 0xCC], channel);

            let before = admission.state(&pid(initiator)).copied();
            let outcome = admission.admit(&LOCAL, &candidate);
            let after = admission.state(&pid(initiator)).copied();

            match outcome {
                Admission::Accepted => {
                    assert_ne!(before, after, "an accept must change state");
                    assert_eq!(after.expect("state").watermark(), epoch);
                    accepted.push((initiator, epoch, instance_seed, channel, member));
                    let entry = watermarks.entry(pid(initiator)).or_insert(0);
                    assert!(
                        epoch >= *entry,
                        "the watermark must never decrease ({epoch} < {entry})"
                    );
                    *entry = epoch;
                }
                other => {
                    assert_eq!(before, after, "{other:?} must not change state");
                    assert!(!matches!(other, Admission::Accepted));
                }
            }
        }

        // Classification is by epoch first: replaying the round that still sets
        // the watermark is a replay, while an accepted round that a later epoch
        // has superseded is stale. Neither is ever accepted again.
        for (initiator, epoch, instance_seed, channel, member) in accepted {
            let repeat = round(initiator, epoch, instance_seed, &[member, 0xCC], channel);
            let is_current = admission
                .state(&pid(initiator))
                .map(|state| state.watermark() == epoch)
                .unwrap_or(false);
            let outcome = admission.admit(&LOCAL, &repeat);
            if is_current {
                assert_eq!(outcome, Admission::Replay);
            } else {
                assert_eq!(outcome, Admission::Stale);
            }
        }
    }

    /// T-INSTANCE-RNG (step-3 portion): instance values never come from
    /// admission state. The full "identical state file" check arrives with the
    /// durable log.
    #[test]
    fn instance_values_are_independent_of_admission_state() {
        let mut admission = RoundAdmission::new(VolatileStore);
        let mut seen: Vec<[u8; INSTANCE_LEN]> = Vec::new();
        for _ in 0..8 {
            let fresh = RoundIdentity::fresh_instance().expect("instance");
            assert!(!seen.contains(&fresh), "instances must not repeat");
            seen.push(fresh);
            // Admitting rounds in between must not influence the next value.
            let epoch = admission
                .state(&pid(1))
                .map(|state| state.watermark() + 1)
                .unwrap_or(1);
            assert_eq!(
                admission.admit(&LOCAL, &round(1, epoch, 1, &[0xAA, 0xBB], "#anon")),
                Admission::Accepted
            );
        }
        for (index, value) in seen.iter().enumerate() {
            assert!(
                !value.iter().all(|byte| *byte == value[0]),
                "instance {index} looks derived, not random: {value:?}"
            );
        }
    }
}
