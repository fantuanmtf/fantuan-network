//! Mesh DC-Net round driver.
//!
//! Protocol (mesh, no trusted collector):
//!   1. The initiator broadcasts a `DcRoundStart` to all participants.
//!   2. Every other participant computes a neutral share (pairwise keys only)
//!      and broadcasts a `DcRoundShare` to everyone.
//!   3. Once every other share has arrived, the initiator broadcasts its own
//!      share (which carries the message) last.
//!   4. Every node XORs all shares and extracts the message locally.
//!
//! Sender anonymity: every participant transmits a share every round and all
//! shares are pseudorandom without the pairwise keys. If two nodes initiate
//! the same round id simultaneously, the lexicographically smaller initiator
//! wins; the loser aborts before sending a message-carrying share.

use crate::error::{AnonError, Result};
use crate::round::{RoundCollector, RoundTracker};
use crate::share::{compute_xor_share, sign_share, verify_share};
use fantuan_identity::Identity;
use fantuan_msg::{DCNET_PAYLOAD_LEN, DcRoundShare, DcRoundStart, Object, unpad_message};
use std::collections::{HashMap, HashSet, VecDeque};

/// Round deadline in seconds.
pub const ROUND_DEADLINE_SECS: u64 = 15;
/// Retries before a queued message is dropped.
pub const MAX_CONFLICT_RETRIES: u32 = 3;
/// Maximum concurrently collecting rounds (DoS bound).
pub const MAX_COLLECTORS: usize = 16;

/// Immutable context for driver calls.
pub struct DriverContext<'a> {
    /// Our identity (used to sign shares).
    pub identity: &'a Identity,
    /// Our fingerprint.
    pub my_uid: &'a str,
    /// Our X25519 static secret.
    pub noise_secret: &'a [u8; 32],
    /// Participant fingerprint → X25519 static public key.
    pub peer_noise: &'a HashMap<String, [u8; 32]>,
    /// Participant fingerprint → certificate bytes (share verification).
    pub peer_certs: &'a HashMap<String, Vec<u8>>,
}

/// Current wall-clock time in milliseconds, the source of round ids.
fn now_ms() -> u64 {
    fantuan_core::time::now_unix_millis() as u64
}

/// A message extracted from a completed round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// Channel label.
    pub channel: String,
    /// Extracted text.
    pub text: String,
    /// Round id.
    pub round_id: u64,
}

/// A round that expired with missing participants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundFailure {
    /// Channel label.
    pub channel: String,
    /// Round id.
    pub round_id: u64,
    /// Participants that did not contribute.
    pub missing: Vec<String>,
    /// Initiator fingerprint.
    pub initiator: String,
}

/// A round that completed with every share present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundCompletion {
    /// Round id.
    pub round_id: u64,
    /// Participants that contributed, excluding the local node.
    pub participants: Vec<String>,
}

/// Result of handling one incoming object.
#[derive(Debug, Default)]
pub struct RoundAction {
    /// Messages extracted from this step.
    pub extracted: Vec<Extracted>,
    /// Objects to send, as `(target, object)`.
    pub outgoing: Vec<(String, Object)>,
    /// Rounds that completed with every share: proof a peer participated, so
    /// the caller can clear its strikes.
    pub completed: Vec<RoundCompletion>,
}

/// Per-node round state machine.
pub struct RoundDriver {
    tracker: RoundTracker,
    collectors: HashMap<u64, RoundCollector>,
    emitted: HashSet<u64>,
    queue: VecDeque<(String, String)>,
    pending_message: Option<String>,
    pending_channel: Option<String>,
    pending_round_id: Option<u64>,
    retries: u32,
    my_share: Option<(Vec<u8>, Vec<u8>)>,
    my_share_broadcast: bool,
    pending_outgoing: Vec<(String, Object)>,
    retry_after_peer: Option<u64>,
    deadline_secs: u64,
}

impl Default for RoundDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundDriver {
    /// Create an idle driver.
    pub fn new() -> Self {
        Self {
            tracker: RoundTracker::new(),
            collectors: HashMap::new(),
            emitted: HashSet::new(),
            queue: VecDeque::new(),
            pending_message: None,
            pending_channel: None,
            pending_round_id: None,
            retries: 0,
            my_share: None,
            my_share_broadcast: false,
            pending_outgoing: Vec::new(),
            retry_after_peer: None,
            deadline_secs: ROUND_DEADLINE_SECS,
        }
    }

    /// Override the round deadline used for rounds we initiate.
    ///
    /// Shorter deadlines suit tests and deployments that prefer a fast
    /// failure; the value is clamped to the protocol range.
    pub fn set_deadline_secs(&mut self, secs: u64) {
        self.deadline_secs = secs.clamp(1, fantuan_msg::DCNET_MAX_DEADLINE_SECS);
    }

    /// Queue a channel message for the next round.
    pub fn queue_message(&mut self, channel: &str, text: &str) {
        self.queue
            .push_back((channel.to_string(), text.to_string()));
    }

    /// Number of queued messages.
    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    /// Highest round id this driver has accepted or issued.
    ///
    /// Read-only introspection: how far the local tracker has been moved, and
    /// by what.
    pub fn current_round_id(&self) -> u64 {
        self.tracker.current()
    }

    /// Number of rounds still collecting.
    pub fn active_rounds(&self) -> usize {
        self.collectors.len()
    }

    /// Initiate a round for the next queued message, if any.
    pub fn initiate_next(
        &mut self,
        participants: &[String],
        ctx: &DriverContext,
    ) -> Result<Vec<(String, Object)>> {
        let Some((channel, text)) = self.queue.pop_front() else {
            return Ok(Vec::new());
        };
        match self.initiate(&channel, &text, participants, ctx) {
            Ok(outgoing) => Ok(outgoing),
            Err(error) => {
                tracing::warn!("cannot start anonymous round on {channel}: {error}");
                Ok(Vec::new())
            }
        }
    }

    /// Start a round carrying `text`; the message share is sent last.
    pub fn initiate(
        &mut self,
        channel: &str,
        text: &str,
        participants: &[String],
        ctx: &DriverContext,
    ) -> Result<Vec<(String, Object)>> {
        if text.len() + 36 > DCNET_PAYLOAD_LEN {
            return Err(AnonError::Round(format!(
                "message too long (max {} bytes)",
                DCNET_PAYLOAD_LEN - 36
            )));
        }
        if participants.len() < 2 || !participants.iter().any(|uid| uid == ctx.my_uid) {
            return Err(AnonError::Round("not a participant".to_string()));
        }
        if participants.len() > fantuan_msg::DCNET_MAX_PARTICIPANTS {
            return Err(AnonError::Round("too many participants".to_string()));
        }

        let round_id = self.tracker.next_round(now_ms());
        let share = compute_xor_share(
            ctx.noise_secret,
            ctx.my_uid,
            participants,
            ctx.peer_noise,
            Some(text.as_bytes()),
            DCNET_PAYLOAD_LEN,
            round_id,
        )?;
        let signature = sign_share(ctx.identity, channel, round_id, &share)?;

        let collector = RoundCollector::new(
            channel,
            round_id,
            ctx.my_uid,
            participants,
            self.deadline_secs,
            DCNET_PAYLOAD_LEN,
        )?;
        self.collectors.insert(round_id, collector);

        self.pending_message = Some(text.to_string());
        self.pending_channel = Some(channel.to_string());
        self.pending_round_id = Some(round_id);
        self.my_share = Some((share, signature));
        self.my_share_broadcast = false;
        self.retries = 0;

        let start = DcRoundStart::new(
            channel,
            round_id,
            ctx.my_uid,
            participants,
            self.deadline_secs,
            DCNET_PAYLOAD_LEN,
        )?;
        let mut outgoing = Vec::new();
        for uid in participants {
            if uid != ctx.my_uid {
                outgoing.push((uid.clone(), Object::DcRoundStart(start.clone())));
            }
        }
        tracing::debug!(round_id, participants = participants.len(), "round started");
        Ok(outgoing)
    }

    /// Handle one incoming object.
    pub fn handle(&mut self, object: &Object, ctx: &DriverContext) -> RoundAction {
        let mut action = match object {
            Object::DcRoundStart(start) => self.on_start(start, ctx),
            Object::DcRoundShare(share) => self.on_share(share, ctx),
            _ => RoundAction::default(),
        };
        action.outgoing.append(&mut self.pending_outgoing);
        action
    }

    /// Expire collectors, retry our pending round, and report failures.
    ///
    /// The scheduler calls this once per interval with the current context so
    /// expired rounds can be retried and dropouts reported.
    pub fn tick(&mut self, ctx: &DriverContext) -> Vec<RoundFailure> {
        let expired: Vec<u64> = self
            .collectors
            .iter()
            .filter(|(_, collector)| collector.is_expired())
            .map(|(round_id, _)| *round_id)
            .collect();

        let mut failures = Vec::new();
        for round_id in expired {
            let Some(collector) = self.collectors.remove(&round_id) else {
                continue;
            };
            let missing: Vec<String> = collector
                .missing_participants()
                .into_iter()
                .filter(|uid| uid != ctx.my_uid)
                .collect();
            // A round of ours that nobody joined is not evidence against any
            // individual participant: it usually means our start was already
            // stale by the time it went out (see `RoundTracker::mark_seen`),
            // and blaming the whole set would let one race evict honest peers.
            //
            // A round we participate in always holds at least our own share,
            // so an empty collector can only be one of our own abandoned
            // rounds. Partial participation is still attributed: one peer
            // answering while others stay silent is a dropout, not a race.
            let abandoned = collector.initiator == ctx.my_uid && collector.received_count() == 0;
            if !missing.is_empty() && !abandoned {
                failures.push(RoundFailure {
                    channel: collector.channel.clone(),
                    round_id,
                    missing,
                    initiator: collector.initiator.clone(),
                });
            } else if abandoned {
                tracing::debug!(
                    round_id,
                    "round of ours expired with no shares; not attributing a dropout"
                );
            }
            let participants: Vec<String> = collector.participants.iter().cloned().collect();
            let channel = collector.channel.clone();

            if self.pending_round_id == Some(round_id) {
                self.abort_pending_round();
                self.retry_pending_with(&channel, &participants, ctx);
            }
            if self.retry_after_peer == Some(round_id) {
                self.retry_after_peer = None;
                if self.pending_message.is_some() {
                    self.retry_pending_with(&channel, &participants, ctx);
                }
            }
        }
        failures
    }

    /// Outgoing objects produced internally (retries).
    pub fn drain_pending_outgoing(&mut self) -> Vec<(String, Object)> {
        std::mem::take(&mut self.pending_outgoing)
    }

    fn on_start(&mut self, start: &DcRoundStart, ctx: &DriverContext) -> RoundAction {
        if start.validate().is_err() {
            return RoundAction::default();
        }
        if self.collectors.len() >= MAX_COLLECTORS {
            tracing::warn!(round_id = start.round_id, "collector limit reached");
            return RoundAction::default();
        }
        if !self.tracker.mark_seen(start.round_id, now_ms()) {
            let conflict =
                self.pending_round_id == Some(start.round_id) && start.initiator != ctx.my_uid;
            if conflict && start.initiator.as_str() < ctx.my_uid {
                // We lose the tie-break; our start carried no message share.
                self.abort_pending_round();
                self.retry_after_peer = Some(start.round_id);
            } else {
                return RoundAction::default();
            }
        }
        if !start.participants.iter().any(|uid| uid == ctx.my_uid) {
            return RoundAction::default();
        }

        let Ok(share) = compute_xor_share(
            ctx.noise_secret,
            ctx.my_uid,
            &start.participants,
            ctx.peer_noise,
            None,
            start.payload_len as usize,
            start.round_id,
        ) else {
            tracing::warn!(round_id = start.round_id, "missing keys; not participating");
            return RoundAction::default();
        };
        let Ok(signature) = sign_share(ctx.identity, &start.channel, start.round_id, &share) else {
            return RoundAction::default();
        };

        let Ok(mut collector) = RoundCollector::new(
            &start.channel,
            start.round_id,
            &start.initiator,
            &start.participants,
            start.deadline_secs,
            start.payload_len as usize,
        ) else {
            return RoundAction::default();
        };
        let _ = collector.submit_share(ctx.my_uid, &share);
        self.collectors.insert(start.round_id, collector);

        let share_object = Object::DcRoundShare(DcRoundShare::new(
            &start.channel,
            start.round_id,
            ctx.my_uid,
            share,
            signature,
        ));
        let mut action = RoundAction::default();
        for uid in &start.participants {
            if uid != ctx.my_uid {
                action.outgoing.push((uid.clone(), share_object.clone()));
            }
        }
        action
    }

    fn on_share(&mut self, share: &DcRoundShare, ctx: &DriverContext) -> RoundAction {
        if share.validate().is_err() {
            return RoundAction::default();
        }
        // Shares must be signed by a known certificate.
        let Some(cert_bytes) = ctx.peer_certs.get(&share.peer_uid) else {
            tracing::warn!(peer = share.peer_uid, "unknown signer; share rejected");
            return RoundAction::default();
        };
        if !verify_share(
            cert_bytes,
            &share.channel,
            share.round_id,
            &share.xored_payload,
            &share.signature,
        ) {
            tracing::warn!(peer = share.peer_uid, "bad share signature");
            return RoundAction::default();
        }

        let is_my_round = self.pending_round_id == Some(share.round_id);
        let Some(collector) = self.collectors.get_mut(&share.round_id) else {
            return RoundAction::default();
        };
        if collector
            .submit_share(&share.peer_uid, &share.xored_payload)
            .is_err()
        {
            return RoundAction::default();
        }
        let all_others_arrived = collector.missing_participants() == vec![ctx.my_uid.to_string()];

        let mut action = RoundAction::default();
        if is_my_round
            && !self.my_share_broadcast
            && all_others_arrived
            && let Some((my_share, my_signature)) = self.my_share.clone()
        {
            let share_object = Object::DcRoundShare(DcRoundShare::new(
                &share.channel,
                share.round_id,
                ctx.my_uid,
                my_share.clone(),
                my_signature,
            ));
            collector.submit_share(ctx.my_uid, &my_share).ok();
            self.my_share_broadcast = true;
            for uid in &collector.participants.clone() {
                if uid != ctx.my_uid {
                    action.outgoing.push((uid.clone(), share_object.clone()));
                }
            }
        }

        if collector.is_complete() {
            let extracted_ok = if let Some(payload) = collector.extract() {
                match unpad_message(&payload).and_then(|bytes| String::from_utf8(bytes).ok()) {
                    Some(text) if self.emitted.insert(share.round_id) => {
                        action.extracted.push(Extracted {
                            channel: share.channel.clone(),
                            text,
                            round_id: share.round_id,
                        });
                        true
                    }
                    _ => false,
                }
            } else {
                false
            };
            let participants: Vec<String> = collector.participants.iter().cloned().collect();
            let channel = collector.channel.clone();
            action.completed.push(RoundCompletion {
                round_id: share.round_id,
                participants: participants
                    .iter()
                    .filter(|uid| uid.as_str() != ctx.my_uid)
                    .cloned()
                    .collect(),
            });
            self.collectors.remove(&share.round_id);
            if is_my_round {
                self.pending_round_id = None;
                self.pending_channel = None;
                self.my_share = None;
                self.my_share_broadcast = false;
                if extracted_ok {
                    self.pending_message = None;
                } else {
                    self.retry_pending_with(&channel, &participants, ctx);
                }
            }
            if self.retry_after_peer == Some(share.round_id) {
                self.retry_after_peer = None;
                if self.pending_message.is_some() {
                    self.retry_pending_with(&channel, &participants, ctx);
                }
            }
        }
        action
    }

    fn abort_pending_round(&mut self) {
        if let Some(round_id) = self.pending_round_id.take() {
            self.collectors.remove(&round_id);
        }
        self.my_share = None;
        self.my_share_broadcast = false;
    }

    fn retry_pending_with(&mut self, channel: &str, participants: &[String], ctx: &DriverContext) {
        if self.retries >= MAX_CONFLICT_RETRIES {
            tracing::warn!("dropping anonymous message after {MAX_CONFLICT_RETRIES} retries");
            self.pending_message = None;
            self.pending_channel = None;
            return;
        }
        self.retries += 1;
        let Some(text) = self.pending_message.clone() else {
            return;
        };
        if let Ok(outgoing) = self.initiate(channel, &text, participants, ctx) {
            self.pending_outgoing.extend(outgoing);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::RoundCollector;
    use fantuan_identity::Identity;
    use std::time::Duration;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct TestNode {
        identity: Identity,
        uid: String,
        secret: [u8; 32],
        public: [u8; 32],
    }

    fn node(uid: &str) -> TestNode {
        let identity = Identity::generate(uid, &format!("dest-{uid}")).expect("identity");
        let secret = StaticSecret::random();
        let public = *PublicKey::from(&secret).as_bytes();
        TestNode {
            uid: uid.to_string(),
            identity,
            secret: secret.to_bytes(),
            public,
        }
    }

    fn context<'a>(
        node: &'a TestNode,
        noise: &'a HashMap<String, [u8; 32]>,
        certs: &'a HashMap<String, Vec<u8>>,
    ) -> DriverContext<'a> {
        DriverContext {
            identity: &node.identity,
            my_uid: &node.uid,
            noise_secret: &node.secret,
            peer_noise: noise,
            peer_certs: certs,
        }
    }

    fn maps(nodes: &[&TestNode]) -> (HashMap<String, [u8; 32]>, HashMap<String, Vec<u8>>) {
        let mut noise = HashMap::new();
        let mut certs = HashMap::new();
        for node in nodes {
            noise.insert(node.uid.clone(), node.public);
            certs.insert(
                node.uid.clone(),
                node.identity.public_cert_bytes().expect("cert"),
            );
        }
        (noise, certs)
    }

    struct Pump<'a> {
        drivers: Vec<&'a mut RoundDriver>,
        contexts: Vec<&'a DriverContext<'a>>,
        queue: Vec<(String, Object)>,
        delivered: Vec<Extracted>,
    }

    impl<'a> Pump<'a> {
        fn run(&mut self, max_steps: usize) {
            for _ in 0..max_steps {
                if self.queue.is_empty() {
                    break;
                }
                let (uid, object) = self.queue.remove(0);
                let index = self
                    .contexts
                    .iter()
                    .position(|context| context.my_uid == uid)
                    .expect("known uid");
                let action = self.drivers[index].handle(&object, self.contexts[index]);
                self.delivered.extend(action.extracted);
                self.queue.extend(action.outgoing);
                let pending = self.drivers[index].drain_pending_outgoing();
                self.queue.extend(pending);
            }
        }
    }

    #[test]
    fn three_party_round_delivers_anonymous_message() {
        let alice = node("alice");
        let bob = node("bob");
        let carol = node("carol");
        let (noise, certs) = maps(&[&alice, &bob, &carol]);
        let ctx_a = context(&alice, &noise, &certs);
        let ctx_b = context(&bob, &noise, &certs);
        let ctx_c = context(&carol, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];

        let mut driver_a = RoundDriver::new();
        let mut driver_b = RoundDriver::new();
        let mut driver_c = RoundDriver::new();
        let outgoing = driver_a
            .initiate("#anon", "hello anonymous world", &participants, &ctx_a)
            .expect("initiate");

        let mut pump = Pump {
            drivers: vec![&mut driver_a, &mut driver_b, &mut driver_c],
            contexts: vec![&ctx_a, &ctx_b, &ctx_c],
            queue: outgoing,
            delivered: Vec::new(),
        };
        pump.run(128);

        let texts: Vec<&str> = pump
            .delivered
            .iter()
            .map(|item| item.text.as_str())
            .collect();
        let matches = texts
            .iter()
            .filter(|text| **text == "hello anonymous world")
            .count();
        assert_eq!(matches, 3, "all three nodes extract the message: {texts:?}");
    }

    #[test]
    fn concurrent_initiations_both_deliver() {
        let alice = node("alice");
        let bob = node("bob");
        let (noise, certs) = maps(&[&alice, &bob]);
        let ctx_a = context(&alice, &noise, &certs);
        let ctx_b = context(&bob, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone()];

        let mut driver_a = RoundDriver::new();
        let mut driver_b = RoundDriver::new();
        let mut outgoing = driver_a
            .initiate("#anon", "from alice", &participants, &ctx_a)
            .expect("a");
        outgoing.extend(
            driver_b
                .initiate("#anon", "from bob", &participants, &ctx_b)
                .expect("b"),
        );

        let mut pump = Pump {
            drivers: vec![&mut driver_a, &mut driver_b],
            contexts: vec![&ctx_a, &ctx_b],
            queue: outgoing,
            delivered: Vec::new(),
        };
        pump.run(128);

        let texts: Vec<&str> = pump
            .delivered
            .iter()
            .map(|item| item.text.as_str())
            .collect();
        assert!(texts.contains(&"from alice"), "alice delivered: {texts:?}");
        assert!(texts.contains(&"from bob"), "bob delivered: {texts:?}");
    }

    #[test]
    fn missing_participant_is_reported_on_expiry() {
        let participants = vec!["A".to_string(), "B".to_string()];
        let mut collector =
            RoundCollector::new("#anon", 1, "A", &participants, 1, 256).expect("collector");
        collector.submit_share("A", &[0u8; 256]).expect("own");
        assert_eq!(collector.missing_participants(), vec!["B".to_string()]);
        assert!(!collector.is_complete());
    }

    #[test]
    fn a_round_nobody_joined_is_not_attributed() {
        let alice = node("alice");
        let bob = node("bob");
        let carol = node("carol");
        let (noise, certs) = maps(&[&alice, &bob, &carol]);
        let ctx_a = context(&alice, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];

        let mut driver = RoundDriver::new();
        driver.set_deadline_secs(1);
        let outgoing = driver
            .initiate("#anon", "nobody answers", &participants, &ctx_a)
            .expect("initiate");
        assert!(!outgoing.is_empty(), "the start went out");

        std::thread::sleep(Duration::from_millis(1_200));
        let failures = driver.tick(&ctx_a);
        assert!(
            failures.is_empty(),
            "an unanswered round is not evidence against anyone: {failures:?}"
        );
    }

    #[test]
    fn a_partial_response_is_attributed() {
        let alice = node("alice");
        let bob = node("bob");
        let carol = node("carol");
        let (noise, certs) = maps(&[&alice, &bob, &carol]);
        let ctx_a = context(&alice, &noise, &certs);
        let ctx_b = context(&bob, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone(), carol.uid.clone()];

        let mut driver_a = RoundDriver::new();
        driver_a.set_deadline_secs(1);
        let mut driver_b = RoundDriver::new();
        let outgoing = driver_a
            .initiate("#anon", "bob answers", &participants, &ctx_a)
            .expect("initiate");

        // Deliver the start to bob only: carol has no driver here, which is
        // exactly what "silent" means for this round.
        let (_, start) = outgoing
            .into_iter()
            .find(|(uid, _)| uid == &bob.uid)
            .expect("bob receives the start");
        let bob_action = driver_b.handle(&start, &ctx_b);
        for (uid, object) in &bob_action.outgoing {
            if uid == &alice.uid {
                driver_a.handle(object, &ctx_a);
            }
        }

        std::thread::sleep(Duration::from_millis(1_200));
        let failures = driver_a.tick(&ctx_a);
        assert_eq!(failures.len(), 1, "one round expired: {failures:?}");
        assert_eq!(
            failures[0].missing,
            vec![carol.uid.clone()],
            "the silent participant is the one attributed"
        );
    }

    #[test]
    fn a_replayed_round_is_accepted_and_extracted_again() {
        // Finding R6 (docs/ROUND_SYNC_REVIEW.md): round-id replay protection
        // is in-memory, and pairwise pads depend only on `(pair, round_id)`,
        // so captured wire objects replay into a restarted peer unchanged.
        let alice = node("alice");
        let bob = node("bob");
        let (noise, certs) = maps(&[&alice, &bob]);
        let ctx_a = context(&alice, &noise, &certs);
        let ctx_b = context(&bob, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone()];

        let mut driver_a = RoundDriver::new();
        let mut driver_b = RoundDriver::new();
        let mut pending = driver_a
            .initiate("#anon", "replayed message", &participants, &ctx_a)
            .expect("initiate");
        // Extractions are collected per node: initiator and participant each
        // complete their own collector.
        let mut alice_extracted: Vec<String> = Vec::new();
        let mut bob_extracted: Vec<String> = Vec::new();
        let mut captured: Vec<Object> = Vec::new();
        for _ in 0..32 {
            if pending.is_empty() {
                break;
            }
            let (uid, object) = pending.remove(0);
            if uid == bob.uid {
                captured.push(object.clone());
            }
            let recipient_is_alice = uid == alice.uid;
            let driver = if recipient_is_alice {
                &mut driver_a
            } else {
                &mut driver_b
            };
            let ctx = if recipient_is_alice { &ctx_a } else { &ctx_b };
            let action = driver.handle(&object, ctx);
            let texts: Vec<String> = action.extracted.into_iter().map(|item| item.text).collect();
            if recipient_is_alice {
                alice_extracted.extend(texts);
            } else {
                bob_extracted.extend(texts);
            }
            pending.extend(action.outgoing);
            pending.extend(driver.drain_pending_outgoing());
        }
        assert_eq!(alice_extracted, vec!["replayed message".to_string()]);
        assert_eq!(bob_extracted, vec!["replayed message".to_string()]);
        assert!(!captured.is_empty(), "the round produced objects for bob");

        // A restarted bob: fresh driver, same identity and keys, empty
        // tracker. The captured objects are replayed verbatim.
        let mut restarted_a = RoundDriver::new();
        let mut restarted_b = RoundDriver::new();
        let mut replayed: Vec<String> = Vec::new();
        let mut replay: Vec<(String, Object)> = captured
            .into_iter()
            .map(|object| (bob.uid.clone(), object))
            .collect();
        for _ in 0..32 {
            if replay.is_empty() {
                break;
            }
            let (uid, object) = replay.remove(0);
            let recipient_is_alice = uid == alice.uid;
            let driver = if recipient_is_alice {
                &mut restarted_a
            } else {
                &mut restarted_b
            };
            let ctx = if recipient_is_alice { &ctx_a } else { &ctx_b };
            let action = driver.handle(&object, ctx);
            replayed.extend(action.extracted.into_iter().map(|item| item.text));
            replay.extend(action.outgoing);
            replay.extend(driver.drain_pending_outgoing());
        }
        assert_eq!(
            replayed,
            vec!["replayed message".to_string()],
            "the replayed round extracts the same message again"
        );
    }

    #[test]
    fn collector_limit_bounds_round_flood() {
        let alice = node("alice");
        let bob = node("bob");
        let (noise, certs) = maps(&[&alice, &bob]);
        let ctx = context(&alice, &noise, &certs);
        let participants = vec![alice.uid.clone(), bob.uid.clone()];

        let mut driver = RoundDriver::new();
        for round in 1..=(MAX_COLLECTORS as u64 + 2) {
            let start =
                DcRoundStart::new("#anon", round, &bob.uid, &participants, 15, 256).expect("start");
            driver.handle(&Object::DcRoundStart(start), &ctx);
        }
        assert_eq!(driver.active_rounds(), MAX_COLLECTORS);
    }
}
