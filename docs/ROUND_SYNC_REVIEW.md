# Round Identification Under Byzantine Clocks — Security Review

Status: internal review, 2026-09-23, of the clock-derived round ids introduced
in Phase 7 (commit `627836f`). Scope: `fantuan-anon` (round tracker, driver,
share derivation), `fantuan-msg` DC-Net objects, and the node paths that feed
them. Not a third-party audit.

Verdict: **the current design is not justified by the protocol's stated threat
model.** It moved the problem it was meant to fix — logical-clock divergence —
into a physical-clock dependency, and uses an unauthenticated, attacker-chosen
number as a replay/identification decision against a locally poisoned
high-water mark. The cryptographic core (pads, share signatures, message
checksum) is unaffected. The failure is in the scheduling layer being
load-bearing for security.

## 0. Corrections to the framing

Two premises need adjusting before the analysis, or the conclusions will be
about the wrong mechanism.

1. **Round membership is not decided by the 30-second window.** Membership is
   exact equality on `round_id`: `RoundCollector` is keyed by the id, and a
   share is submitted only into a collector with the same id
   (`crates/fantuan-anon/src/driver.rs`). The 30-second constant
   (`MAX_FUTURE_SKEW_MS`) is only an *acceptance bound* on future-dated ids:
   `mark_seen` rejects `round_id > receiver_now + 30s`.
2. **The critical path is not the window: it is the high-water mark.**
   `mark_seen` also rejects any `round_id <= self.current_round_id`, and
   `current_round_id` is raised to whatever id a peer announces. Both the
   security-relevant staleness test and the "is this a fresh round" test are
   therefore decisions driven by *values chosen by remote parties*, compared
   against *state those same parties can move*.

Together those two facts mean the 30-second value is much less interesting
than the requirement it is being asked to satisfy: physical time is used to
make a *cross-node* ordering decision, which is exactly the class of problem a
clock cannot solve in the presence of Byzantine faults.

## 1. Clock assumptions in the current design

| Assumption | Where it is required | Stated anywhere? |
|-----------|---------------------|------------------|
| Honest clocks differ by \|skew\| ≤ 30 s − delay | participation (see §2.3 for the real bound) | No |
| Honest clock is not behind the newest round id by more than ~one round interval | initiation | No |
| Initiated ids are unique per (participant pair set) — a cryptographic requirement of the pad derivation | confidentiality/instance separation | No (implicit) |
| Clock never steps backwards | monotonicity of the id floor | No |
| No peer sends a future-dated id | the poisoning attack (§3 A1) | Cannot be assumed |

Terminology, kept distinct because the mitigations differ:

- **Clock skew** — static offset between two clocks. NTP/PTP-disciplined
  hosts: ~ms (LAN), ~10 ms (internet); unreachable NTP: seconds; no NTP at
  all: unbounded.
- **Clock drift** — rate difference, 20–100 ppm on typical hardware, i.e.
  1.7–8.6 s per day of unsynchronised operation. This is why "skew" without a
  sync source is not a bounded quantity.
- **Network delay** — one-way latency. I2P is a high-latency transport; the
  repository's own I2P test needed retry logic to absorb tunnel warm-up, which
  is evidence of multi-second tail latency and no measurement anywhere in CI.
- **Message reordering** — impossible within one Noise session (ordered
  stream, sequence numbers); possible *across* sessions, which matters here
  because a round start and the shares it triggers travel on different
  sessions (§3 A6).
- **Byzantine clock manipulation** — a peer may set its wall clock to any
  value. Nothing in the protocol prevents this, and nothing authenticates the
  resulting id.

**Honest clocks are not required to be synchronised to a trusted source
anywhere in the code or docs.** No NTP dependency is declared, no
`clock_synced` preflight exists, and clock problems surface only as
`tracing::debug!` lines.

## 2. Round identification

### 2.1 Is physical time the round identifier?

Yes, in the two ways that matter:

- **Identification.** `round_id = quantise(initiator_clock) + 1`, floored by
  the highest id seen. All participants must hold the *same* value to exchange
  shares.
- **Cryptographic domain separation.** The id is an HKDF input to every
  pairwise pad (`derive_pair_share`: `PAIR_DOMAIN ‖ round_id ‖ low ‖ high`)
  and part of the share signature domain (`share_message(channel, round_id,
  share)`). So the id's *uniqueness per pair* is a cryptographic requirement,
  not a bookkeeping detail — it separates pad instances and signature
  instances.

Note what the pad derivation does **not** bind: the participant set. Pads
depend only on `(pair, round_id)`. Two rounds that reuse an id therefore reuse
every pad of every pair they share. Content confidentiality is not the issue
(DC-Net content is public to participants by design, and a round carries one
message); the issue is that the id stops being a unique *round instance*,
which is what the signature domain and the `emitted` dedup set rely on.

### 2.2 Can two honest nodes disagree about the current round?

Yes, and disagreement is now a normal operating condition rather than a bug:

- `current_round_id` is per-node state that moves only on observation, so a
  node that was not invited to a round, or that joined later, holds a lower
  value. Before Phase 7 this froze the node permanently (finding D3); now it
  only means "this node will accept an id that an up-to-date node rejects".
- Concretely: node C (current = X−1) accepts a start with id X; node A
  (current = X) rejects the same start. The initiator's round then completes
  for C and expires for A, and A is reported as a dropout (§3 A5).

### 2.3 What the effective tolerances actually are

Derived from the code, not from the constant:

- **Participation** requires `receiver_now − 30 s ≤ id ≤ receiver_now + 30 s`
  and `id > receiver.current`. An honest initiator's id ≈ real time, so a
  receiver whose clock is **more than 30 s behind** sees every honest start as
  "from the future" and rejects it; a receiver **more than 30 s ahead** accepts
  them normally. So participation tolerance is ±30 s, two-sided in practice.
- **Initiation** requires `id > max over receivers of current`, and
  `current` on a live peer is approximately the most recent round id, i.e.
  approximately real time. Since the initiator stamps `max(current,
  quantise(its_now)) + 1`, the binding constraint is the *high-water mark*,
  not the 30 s window: **an initiator must not be behind the network's most
  recent round**, which is at most one round interval (default 5 s) of slack —
  and less in a busy network where several initiators advance the id space.
  The advertised 30 s does not apply in this direction at all.
- **Self-poisoning:** a node more than 30 s ahead can still participate, but
  the first time it initiates, its own `current` jumps to its (fast) clock and
  it then rejects every honest start for the duration of its skew, silently.

## 3. Byzantine attack scenarios

| # | Attack | Attacker capability | Preconditions | Effect | Severity |
|---|--------|--------------------|---------------|--------|----------|
| A1 | **Tracker poisoning** | any connected peer, no trust level needed; one unsigned `DcRoundStart` per 30 s per victim | victim has a free collector slot (< 16) | victim silently rejects all honest starts for 30 s, renewable | **High** |
| A2 | **Eviction by proxy** | A1, then ordinary rounds by honest peers | honest peers invite the poisoned victim | honest peers accumulate strikes against the victim and evict it; anonymity set shrinks | **High** |
| A3 | **Anonymity-set collapse** | any peer that can initiate a round naming the victim (pre-existing, not clock-caused) | 2 participants suffice (`validate` allows 2) | in a 2-party round the sender is the non-attacker participant, deterministically | **High** |
| A4 | **Clock-skewed honest node** | none (misconfiguration) | \|skew\| > 30 s, or behind by more than one round interval | silent loss of initiation (and of participation if > 30 s behind) | **Medium** |
| A5 | **Strike mis-attribution** | any initiator choosing an id that some peers accept and others reject | participants' `current` values differ | honest participants that never saw a valid start are reported as dropouts | **Medium** |
| A6 | **Start/share reordering** | network, or a peer that delays | start and shares travel on different sessions | share arrives before the collector exists, is dropped, round expires | **Low** |
| A7 | **Replay after restart** | any peer replaying a captured start (+shares) | victim restarted since that round; id within ±30 s | round re-extracted and re-delivered; `emitted` dedup is in-memory | **Medium** (High once Phase 8 publishes extractions) |
| A8 | **Boundary submission** | any peer | none | id exactly `now + 30 s` is accepted (bound is strict `>`), giving the maximum poisoning window | **Medium** |
| A9 | **Round jamming** (pre-existing, clock-independent) | a participant in the round | none | a share that is not `pad ⊕ message` fails the checksum; nobody extracts; retries reuse the same participant list and the message is dropped after 3 attempts. **No shares are missing, so no strikes are ever attributed** | **Medium** |

### A1 — Tracker poisoning, in detail

- **Attacker capability:** a single authenticated session (any vouch level, no
  round trust required).
- **Preconditions:** the victim has fewer than `MAX_COLLECTORS` (16) live
  collectors.
- **Sequence:** craft a valid `DcRoundStart` — the object is unsigned, so any
  channel, any participant list and any initiator work — with
  `round_id = victim_now + 29 s`; send it. Repeat every ~30 s.
- **Affected state:** the victim's `RoundTracker::current_round_id`.
- **Why it works:** `mark_seen` runs *before* the participant-membership check
  and before share computation, so the id is absorbed even if the victim is
  not a participant, cannot derive the pads, or ignores the round.
- **Impact:** for the next 30 s every honest start (id ≈ now) is `≤ current`
  and therefore stale to the victim; it never joins those rounds. Peers then
  see it as a dropout: A2. Availability failure for the victim, and an
  anonymity-set reduction for everyone whose rounds the victim would have
  joined. No cryptographic property is broken — which is precisely the point:
  the decision was taken on an unauthenticated number.
- **Cost:** one frame per 30 s per victim, under every existing rate limit.

### A2 — Eviction by proxy

The strike design (consecutive strikes, `reward` on completed rounds) turns A1
into network-wide eviction: while poisoned, the victim cannot complete rounds,
so `reward` never clears its strikes, and three honest-initiated rounds suffice
for each honest peer to evict it. The attacker is not a participant in those
rounds and is never penalised. Phase 7's `abandoned` rule does not apply (it
only suppresses attribution when *no* shares arrived, and here the other
participants answered).

### A3 — Anonymity-set collapse (pre-existing; not introduced by Phase 7)

The initiator chooses the participant list, and a receiving node joins any
well-formed round that names it — there is no recipient-side consent policy and
no minimum size above 2. In a two-participant round the extraction is the
message, and the attacker knows whether it was the sender, so the sender is
identified with certainty. This is the *active* form of the selective
participation exposure `docs/ATTACKS.md` §2 already warns about passively.
A1 makes it remotely forcible: poison everyone else, remain the only reliably
available participant, and rounds shrink toward the attacker plus one victim.

### A9 — Jamming is unpunished

`missing_participants` drives strikes; a participant that *does* submit a
corrupt share produces a complete-but-undecryptable collector (checksum
failure), so it is never attributed, and the retry re-uses the same participant
list. One malicious participant can therefore block a channel's anonymous
messaging indefinitely at no cost.

## 4. What the bound must cover, and what 30 s is actually for

Following the decomposition that established BFT systems use (CometBFT's
proposer-based timestamps parameterise exactly these two quantities):

```
acceptance_window  ≥  PRECISION  +  MSGDELAY  +  quantisation
```

- `PRECISION` — maximum honest clock skew. NTP-disciplined: ≤ 1 s is a safe
  engineering figure, ≤ 10 ms typical. Unsynced: unbounded.
- `MSGDELAY` — one-way delay including queueing. Unmeasured in this
  repository; I2P tunnel warm-up in the project's own integration test implies
  multi-second tails; assuming ≤ 10 s is defensible but unverified.
- quantisation — 100 ms, included by construction.

So the *honest* side needs roughly 11 s under stated assumptions, and 30 s
gives ~2.7× margin. That would be a fine number if it were only the honest
side. It is not: the same constant is simultaneously the attacker's budget,
because the acceptance path advances a high-water mark that disables honest
rounds (`A1`). **The requirement with the opposite gradient has been folded
into the same constant**: honest tolerance wants Δ large, DoS resistance wants
Δ small. No value of Δ satisfies both, which is why the fix must remove the
shared quantity rather than tune it.

The 30 s is also not applied where the design claims tolerance: initiation is
bounded by the round high-water mark (~one round interval, ~5 s), as derived in
§2.3. So the design is simultaneously *more* permissive than intended (attacker
budget) and *less* permissive than documented (honest initiation).

## 5. Where wall-clock time is used, by role

| Role | Mechanism | Verdict |
|------|-----------|---------|
| **Replay protection (rounds)** | `mark_seen` staleness vs a peer-movable high-water mark | Unsound: attacker-influenced, volatile across restart (A7), no durable state |
| **Round identification** | quantised initiator clock | Unsound as a *cross-node* agreement primitive — this is a consensus problem, not a clock problem |
| **Cryptographic domain separation** | `round_id` as HKDF/signature input | Requirement is uniqueness per pair; currently guaranteed only by clock heuristics and volatile state |
| **Liveness / participation** | clock-window acceptance | Fails silently outside ±30 s, and outside ~one round interval in the initiation direction |
| **Round expiry** | `RoundCollector::deadline` on `Instant` | **Correct.** Monotonic, immune to clock steps (tokio documents `Instant` as monotonically nondecreasing) |
| **Relay anti-replay** | per-origin nonce, persisted reservation + clock floor | **Sound under Byzantine clocks.** Per-origin monotone counters never need cross-node comparability; a Byzantine peer can only affect its own stream |
| **Relay freshness** | ±60 s timestamp window | Heuristic only; the nonce is the real protection. Its gap is receiver-side: `last_nonce` is in-memory, so a restarted receiver accepts replays inside the window |
| **Scheduling** | `round_interval_secs`, `cover_interval_secs` | Harmless |
| **Message/forum timestamps** | object timestamps, history `since` | Ordering/UX only; not a security boundary, but forgeable and worth stating as such |

The pattern is consistent: physical time is fine where the value is *local*
(expiry, scheduling) or where the requirement is *monotone within one origin*
(relay nonces). It fails exactly where a *shared, agreed* value is needed.

## 6. Comparison with established designs

- **CometBFT / Tendermint BFT Time** computes block time as the *weighted
  median* of validator Precommit timestamps, so the canonical time is one
  contributed by a correct validator; a Byzantine minority cannot move it. The
  agreed value comes from consensus, not from any node's clock.
- **CometBFT PBTS** (the current scheme) parameterises the assumption
  explicitly: `PRECISION` (how far honest clocks may differ) and `MSGDELAY`
  (bounded proposal delay); validators accept a proposal timestamp only within
  that combined window. Its light-client verifier takes an explicit
  `maxClockDrift` for "how far in the future a header may be". Two lessons:
  the drift bound is (a) derived from named assumptions and (b) *configurable
  and documented*, not a bare constant. Validators are required to run synced
  clocks — an operational requirement this project does not state.
- **Monotone counters / per-origin namespaces** — the pattern already used in
  this codebase for relay nonces (`fantuan-node::nonce`). It gives replay
  protection and instance uniqueness with no clock at all; the only thing it
  cannot give is a *global* order, which is why it is the right fit for
  anything that must not be comparable across nodes.
- **Hybrid logical clocks** (physical component + logical counter) fix
  monotonicity *within* a node across clock steps and give comparability for
  causality, but they do **not** bound a Byzantine peer's value and do not
  produce agreement — they are not a substitute for the namespace change.
- **TrueTime-style bounded-uncertainty clocks** (explicit uncertainty interval,
  wait out the interval before acting) require an authenticated time
  infrastructure this project does not have; without it the "uncertainty" is
  unbounded in the presence of a Byzantine peer.
- **Epochs from an agreed beacon** (threshold-signed epoch values, as mixnets
  use for epoch scheduling) are the correct long-term answer if a *shared*
  notion of the current epoch is ever needed (for example for a full mixnet).
  They replace the clock with a cheap consensus object.

## 7. Recommended architecture

The goal is that no cryptographic or identification decision depends on a
remote party's physical clock.

1. **Per-initiator epoch namespace.** Round identity becomes
   `(initiator_fingerprint, epoch)`, where `epoch` is a *per-initiator*
   monotone counter persisted with the same reservation scheme as
   `RelayNonce`. Staleness becomes a per-initiator high-water mark in a
   bounded table with TTL. A Byzantine initiator can then only advance **its
   own** namespace — A1 and A2 disappear, because there is nothing shared to
   poison. The lagging-node problem (D3) also disappears: each node's counter
   is its own.
2. **Random instance value for uniqueness.** Carry a 128-bit random instance
   in the round object and use `H(initiator, epoch, instance)` as the pad and
   signature domain. Uniqueness then survives clock steps *and* state loss
   (VM snapshot restore, wiped data dir), which no counter alone does.
3. **ACK-gated strike attribution.** Count a participant as expected only once
   it has acknowledged the start (a signed ack, or its first share). Strikes
   then mean "acknowledged, then silent", which is sound; participants who
   never saw a valid start can no longer be blamed — fixing A5 and making the
   `abandoned` heuristic unnecessary.
4. **Recipient-side consent policy.** Refuse rounds below a configured
   minimum participant count and from initiators below `min_round_trust`, and
   never join a round naming unknown peers. This closes A3.
5. **Sign `DcRoundStart`** (already tracked as E5): makes A1/A5 attributable
   and rate-limitable per identity, and allows penalties for abuse.
6. **Persist per-initiator high-water marks** so a restart does not reopen a
   replay window (A7); dedup extracted messages in the store by
   `(initiator, epoch, instance)`.
7. **Keep physical time only where it is local.** Expiry stays on `Instant`
   (already correct). Relay freshness stays a heuristic backed by the durable
   nonce. Scheduling intervals are unaffected. If a drift check is kept
   anywhere, express it as `PRECISION + MSGDELAY` with named, documented
   assumptions, and never reuse one constant for two opposing purposes.
8. **Address jamming separately** (A9): at minimum, log complete-but-invalid
   rounds as an anomaly and randomise participant selection per round so a
   jammer is not present every time; the stronger fixes (trap protocols,
   commitment/reveal pair rounds) are research-scale work.

## 8. Assumption taxonomy for the current design

**Formally required (but unstated):**
- For participation: honest clock within ±30 s of every peer, minus delay.
- For initiation: honest clock not behind the network's newest round id
  (≈ one round interval, ~5 s).
- For id uniqueness: no id reuse per pair, which the design does not enforce
  across restarts and does not state as a requirement.

**Protocol guarantees (hold regardless of clock values):**
- Share authenticity (OpenPGP signatures over `(channel, round_id, share)`).
- Extraction integrity (BLAKE3 frame checksum → failure is detectable).
- Pad cancellation for a complete participant set.
- Relay confidentiality and admission monotonicity per origin.

**Engineering heuristics:**
- 30 s as an acceptance window; ±60 s as a relay freshness window.
- "I2P delays are well below 30 s" (unmeasured).
- "Operators run NTP" (never stated).

**Unproven / unjustified:**
- That the 30 s bound covers honest skew *and* is not an attacker budget.
- That a peer-supplied id can be trusted to order rounds (A1).
- That restart-safety of relay nonces extends to round state (it does not).
- That strikes only punish the guilty (A5).

## 9. Findings, owner phases

| Id | Finding | Severity | Owner |
|----|---------|----------|-------|
| R1 | Future-dated id poisons a peer's round tracker (A1) | High | Phase 8 (items 1, 2, 5) |
| R2 | Poisoning escalates to network-wide eviction by honest peers (A2) | High | Phase 8 (items 1, 2, 3) |
| R3 | Initiator-chosen 2-party rounds attribute the sender (A3) | High | Phase 8 (item 4) |
| R4 | Effective skew tolerance is ~one round interval for initiation, not 30 s (A4) | Medium | Phase 8 (items 1, 7) |
| R5 | Id divergence causes strikes against honest participants (A5) | Medium | Phase 8 (item 3) |
| R6 | Round-id replay window after restart (A7) | Medium | Phase 8 (item 6) |
| R7 | 30 s conflates honest tolerance with attacker budget | Medium | Phase 8 (item 7) |
| R8 | Jamming is undetectable and unpunished (A9) | Medium | Phase 8 (item 8) |
| R9 | `is_stale` is dead code; no staleness check on any share path | Low | Phase 8 hygiene |
| R10 | Relay freshness depends on an in-memory receiver-side nonce table | Low | later |

Nothing here is a break of the DC-Net cryptographic core; every finding is in
the identification, admission or reputation layer built around it. That is
also why the fixes are architectural (remove the shared clock quantity) rather
than parametric (tune the constant).

## 10. Second-pass verification (2026-09-23)

Every major finding was re-derived from the code and, where possible, turned
into an executable reproduction. Four corrections to the first pass came out
of it, plus three findings the first pass missed. Classification:

- **PROVEN** — demonstrated directly from code, no test possible or needed.
- **REPRODUCED** — an executable test demonstrates it. Tests that assert the
  *attack succeeds* are marked below; they must be **inverted** when the
  finding is fixed, never deleted.
- **INFERRED** — follows from the code but was not dynamically reproduced.
- **ARGUED** — a design judgement about the trade-off, not a claim about
  behaviour.

### 10.1 Item-by-item verification

| # | Claim under test | Verdict | Evidence |
|---|------------------|---------|----------|
| 1 | A1 watermark poisoning | **REPRODUCED** (attack succeeds) | `round_clock_attacks.rs::a_future_dated_start_poisons_the_round_tracker`. The same start that a control peer absorbs is silently rejected by the poisoned peer |
| 2 | A2 strike/eviction escalation | **REPRODUCED** (attack succeeds), rate corrected | `round_clock_attacks.rs::poisoning_escalates_to_eviction_by_honest_rounds`: three honest rounds evict the honest-but-poisoned node while the answering peer keeps its standing |
| 3 | A3 participant-selection / attribution | **CORRECTED — replaced by A0** | The first pass had the mechanism wrong (see 10.2); the conclusion is stronger |
| 4 | A7 restart/replay window | **REPRODUCED**, window corrected | `driver.rs::a_replayed_round_is_accepted_and_extracted_again`; `round.rs::a_fresh_tracker_accepts_any_past_id` shows the window is unbounded in the past |
| 5 | `MAX_FUTURE_SKEW_MS` semantics | **PROVEN** | `round.rs::the_future_bound_is_strict`: strictly `> now + 30_000` is rejected; exactly at the bound is accepted. The constant bounds only the *future*; staleness is bounded by the high-water mark |
| 6 | Ordering of authorization, membership, `mark_seen`, collector creation, mutation | **PROVEN** | `driver.rs` `on_start`: validate (325) → collector cap (329) → **`mark_seen` mutates state (333)** → participant membership (344) → share computation (348) → collector (364). There is no authorization step at all, and mutation precedes every check that could reject the object |
| 7 | Replay of the same `round_id`; reused material | **REPRODUCED** | Pairwise pads are `HKDF(ECDH(a,b), PAIR_DOMAIN ‖ round_id ‖ len(a)‖a ‖ len(b)‖b)` (`share.rs`), independent of the participant set and of time; share signatures are over `(channel, round_id, share)`. A replayed round re-derives identical pads, so the same message extracts again. No *new* confidentiality loss: DC-Net content is public to participants by design and a round carries one message |
| 8 | Claimed confidentiality impact | **NOT REAL** | Impact is limited to anti-replay, instance uniqueness, attribution and state-machine integrity. The first pass's "two-time pad" framing was checked and withdrawn |

### 10.2 Corrections to the first pass

1. **A3 was wrong, and the truth is worse (new finding A0).** The first pass
   claimed an attacker could run a two-party round and attribute the victim's
   message to it. It cannot: the *initiator is the sender*
   (`compute_xor_share(.., Some(text), ..)` has exactly one call site, in
   `initiate`; participants always pass `None`), so a round the attacker starts
   carries the attacker's own message. The real property failure is that the
   sender is the initiator **in every round**, and the initiator is named in
   the `DcRoundStart` that every participant receives. Every participant can
   therefore attribute the extracted text to the initiator with certainty, at
   any participant-set size and with no collusion. A0 is **PROVEN** (single
   call site) and pinned by
   `round_attacks.rs::only_the_initiator_contributes_message_material`, which
   recomputes the participant's share independently and shows it is exactly
   the neutral value.
   Consequence: `docs/ATTACKS.md` §2 and `docs/SECURITY.md` invariant 13 claim
   sender anonymity against any adversary that does not control all but one
   participant; **the implementation does not provide it**, and the simulator
   gates (`entropy = log2(N)`, top-1 = 1/N) measure a model in which any
   participant may send. The gate output is therefore not evidence about the
   implementation (this strengthens finding E1/E3 of `docs/ROADMAP.md` §4.3).
2. **A7's window is unbounded in the past, not ±30 s.** A restarted node's
   tracker starts at 0, and the only rejection criteria are `id <= current`
   and `id > now + 30 s`, so any historical round id is accepted. Replaying a
   round captured days ago works.
3. **A2's rate is bounded by a separate bug (new finding R11).** Rounds the
   scheduler retries are never sent: `retry_pending_with` queues objects into
   `RoundDriver::pending_outgoing`, which only `handle` drains, while
   `anon::tick` calls `tick` and `initiate_next` and never
   `drain_pending_outgoing`. In a quiet network a failed round is retried
   three times in bookkeeping only. **REPRODUCED** by
   `round_attacks.rs::retry_objects_are_stranded_until_inbound_traffic_arrives`
   and by the A2 test, which has to use three separate messages instead of one
   message with retries.
4. **The effective initiation tolerance is ~one round interval, confirmed.**
   `round.rs::an_initiator_behind_the_latest_round_cannot_start_one` and
   `a_receiver_more_than_thirty_seconds_behind_rejects_honest_starts` pin the
   two bounds: initiation is limited by the high-water mark (≈ 5 s at the
   default interval), participation by ±30 s minus delay.

### 10.3 Findings the first pass missed

| Id | Finding | Verdict | Evidence |
|----|---------|---------|----------|
| A0 | The initiator is the only message carrier and is named in the start, so participants attribute the message with certainty | **PROVEN** | single `Some(text)` call site; `only_the_initiator_contributes_message_material` |
| R11 | Retry objects are stranded in the driver's pending buffer; the scheduler never flushes them | **REPRODUCED** | `retry_objects_are_stranded_until_inbound_traffic_arrives` |
| R12 | Participant selection does not require a clique, so a non-clique connected set makes every round fail silently for the non-adjacent participants — and they then blame each other for the shares they could not receive | **REPRODUCED** | `dcnet_partial_mesh.rs::a_non_clique_participant_set_fails_silently_and_blames_peers` (no attacker involved) |

R12 surfaced by accident: the first version of the A1 test used a topology in
which bob and carol were both connected to alice but not to each other; the
round could not complete and the test failed for that reason rather than for
the poisoning.

### 10.4 Property classes (separated)

| Class | Status | Findings |
|-------|--------|----------|
| **Protocol safety (cryptographic)** | **HOLDS** | Share authenticity, pad cancellation, checksum detection, relay confidentiality, per-origin relay nonce monotonicity. Verified by the existing suites and by R8, which shows corruption *is* detected |
| **Anti-replay** | **FAILS** | A7 (round ids: unbounded past after restart), R10 (relay freshness depends on an in-memory receiver table). Relay *sending* is restart-safe (Phase 7); relay *receiving* is not |
| **Liveness** | **FAILS** in several ways | A1/A2 (poisoning excludes and then evicts an honest node), R4 (clock-skewed nodes cannot initiate; behind-by-31 s cannot participate), R11 (retries never sent), R12 (non-clique rounds fail for some participants), R8 (one jamming participant blocks a channel indefinitely) |
| **Membership and attribution** | **UNSOUND** | A0 (no sender anonymity among participants, contradicting the documented claim), R5/A2 (strikes land on honest nodes, up to eviction), R8 (corruptors are never penalised) |
| **Operational clock assumptions** | **UNSTATED AND UNTESTED IN DEPLOYMENT** | R7 (the 30 s constant serves two opposing purposes), R4 (effective tolerances differ from the documented ones), no NTP requirement anywhere |

### 10.5 What this changes for the fix

The verification does not change the recommended architecture (§7); it makes
its justification concrete and adds three items:

1. A0 means the anonymous layer's headline property must be fixed or
   re-documented. Either participants may carry messages (making the
   participant set the anonymity set the docs already claim), or the claim in
   `ATTACKS.md`/`SECURITY.md` and the simulator model must be corrected to
   "content and sender are hidden from non-participants only".
2. R11 must be fixed with the retry path it belongs to; until then, retry
   accounting (`MAX_CONFLICT_RETRIES`) is misleading in any operator-facing
   documentation.
3. R12 makes the participant-contract requirement of `PROTOCOL.md` §11
   (direct connectivity) a *correctness* requirement rather than a note:
   selection should either verify reachability or the collector should
   distinguish "share not received" from "peer not reachable".

All reproductions were run on 2026-09-23 against commit `627836f`; they pass,
meaning the attacks succeed. Each carries a header comment saying so, and each
must be inverted rather than deleted when the corresponding finding is fixed.

Suite state after this pass: 235 tests pass (0 failed, 2 ignored I2P), up from
223; `clippy -D warnings`, `cargo fmt --check` and the 1000-line limit are
clean, and the timing-sensitive reproductions (A1, A2, R12) were run three
times each without a flake. The only non-test production change in this pass is
the read-only accessor `RoundDriver::current_round_id()`; no protocol
behaviour was altered.
