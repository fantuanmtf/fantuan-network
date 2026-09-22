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

/// Immutable context for driver calls.
pub struct RoundContext<'a> {
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

/// Result of handling one incoming object.
#[derive(Debug, Default)]
pub struct RoundAction {
    /// Messages extracted from this step.
    pub extracted: Vec<Extracted>,
    /// Objects to send, as `(target, object)`.
    pub outgoing: Vec<(String, Object)>,
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
        }
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

    /// Number of rounds still collecting.
    pub fn active_rounds(&self) -> usize {
        self.collectors.len()
    }

    /// Initiate a round for the next queued message, if any.
    pub fn initiate_next(
        &mut self,
        participants: &[String],
        ctx: &RoundContext,
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
        ctx: &RoundContext,
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

        let round_id = self.tracker.next_round();
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
            ROUND_DEADLINE_SECS,
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
            ROUND_DEADLINE_SECS,
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
    pub fn handle(&mut self, object: &Object, ctx: &RoundContext) -> RoundAction {
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
    pub fn tick(&mut self, ctx: &RoundContext) -> Vec<RoundFailure> {
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
            if !missing.is_empty() {
                failures.push(RoundFailure {
                    channel: collector.channel.clone(),
                    round_id,
                    missing,
                    initiator: collector.initiator.clone(),
                });
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

    fn on_start(&mut self, start: &DcRoundStart, ctx: &RoundContext) -> RoundAction {
        if start.validate().is_err() {
            return RoundAction::default();
        }
        if !self.tracker.mark_seen(start.round_id) {
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

    fn on_share(&mut self, share: &DcRoundShare, ctx: &RoundContext) -> RoundAction {
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

    fn retry_pending_with(&mut self, channel: &str, participants: &[String], ctx: &RoundContext) {
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
    ) -> RoundContext<'a> {
        RoundContext {
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
        contexts: Vec<&'a RoundContext<'a>>,
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
}
