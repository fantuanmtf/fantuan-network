# Fantuan Network — Internal Security Report (v0.1.0)

Status: internal review of Phases 1–7. This report is not a substitute for a
third-party audit.

## 1. Scope

Components reviewed: identity layer (OpenPGP/descriptors/bindings), transport
layer (I2P SAM + Noise), message layer (CBOR objects), trust graph and gossip,
relay layer, channel/forum/history handling, content-addressed file storage,
DC-Net anonymous rounds, traffic shaping, node control interfaces.

Out of scope: the i2pd router itself, the operating system, network
infrastructure, and the Python analyzer's statistical correctness. Note that
this last exclusion is not benign — the analyzer has no test suite, does not
run in CI, and holds every anonymity gate (6.7, 6.8).

## 2. Cryptography inventory

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Identity | Ed25519 + X25519 OpenPGP certificate (nettle backend) | primary certify key, signing and encryption subkeys |
| Descriptor/object signatures | OpenPGP detached (Ed25519) | domain separators, canonical CBOR |
| Session | Noise XX `25519_ChaChaPoly_BLAKE2s` | per-session ephemeral keys, replay-safe counters |
| Session binding | OpenPGP signature over `handshake_hash ‖ static ‖ BLAKE3(descriptor)` | binds identity to the exact session |
| Relay payload | OpenPGP encryption to the destination subkey | relays see ciphertext only |
| Chunks | ChaCha20-Poly1305, random nonce, `file_id ‖ index` AAD | content-addressed by BLAKE3 |
| DC-Net shares | X25519 ECDH + HKDF-SHA256 | pairwise blocks cancel in one round |
| Randomness | `getrandom` / OsRng | |

## 3. Attack results

| Attack | Result | Evidence |
|--------|--------|----------|
| GPA on DC-Net mesh | entropy = log2(N), top-1 = 1/N | `crates/fantuan-sim/src/attacks.rs`, analyzer gates |
| Timing correlation | **not measurable as implemented**: the metric correlates each candidate against the sum of all candidates, so r → 1 by construction and the reported 1.0000 carries no signal (6.7) | `dcnet-mesh` attack matrix |
| Intersection | stable membership ⇒ no shrinkage; selective ⇒ collapses to 1 | `attack-selective` scenario |
| N−1 collusion | attribution succeeds by construction of the share algebra (known DC-Net limit), but the test asserting it is an algebraic identity and would not catch a regression (6.8) | `fantuan-anon` `colluding_majority_can_attribute_the_sender` |
| N−k collusion | attribution fails | `colluding_minority_cannot_attribute_the_sender` |
| Share forgery / replay | rejected (signature + monotonic round ids) | `fantuan-anon` tests |
| Peer impersonation | rejected (binding + TOFU keys) | `fantuan-transport` session tests |
| Frame tamper / replay | rejected (Noise AEAD + sequence) | `fantuan-transport` tests |
| Unauthenticated relay/messages | dropped (only Ping/Pong allowed) | `fantuan-transport` tests |
| Sybil descriptors | rejected with `require_vouch_for_gossip` | `fantuan-node` gossip tests |
| Frame flood | over-budget frames dropped | `fantuan-traffic::limit` tests |
| Chunk flood / replay | deduplicated by content hash, bounded cache | `fantuan-storage` tests |

## 4. Hardening controls

- **Session boundary**: authenticated handshake (10 s timeout), unauthenticated
  sessions may only exchange Ping/Pong, TOFU key pinning, per-direction
  sequence numbers.
- **Parser discipline**: canonical CBOR with re-encode equality checks, strict
  size caps (object 64 KiB, payload 32 KiB, channels 8 KiB, forums 32 KiB),
  bounded vector lengths.
- **Resource bounds**: max 256 connections, writer queue 64 frames, inbound
  queue 1024, relay nonce/rate tables 4096 with eviction, chunk cache byte
  budget, collector cap 16, gossip announcements 64 / vouches 256.
- **Relay admission**: per-origin nonce, ±60 s freshness, 60/60 s rate limit,
  TOFU certificate pinning, hop limit 8, inbound hops validation.
- **Anonymity layer**: round ids are clock-derived and quantised (stale ids
  and ids beyond the skew bound refused), share signatures verified against
  known certificates, consecutive strikes with a reachable `reinstate`, and no
  attribution for a round of ours that nobody answered.
- **Local interfaces**: control socket mode 0600, IRC bridge bind address is
  operator-controlled (loopback recommended), delete requests only accepted
  from the original owner.
- **Dependencies**: `cargo audit --deny warnings` runs in CI.

## 5. Verification evidence

- 223 workspace tests pass (`cargo test --workspace --release`, 0 failed,
  2 ignored I2P integration tests); Phase 7 raised the count from 207 at
  `9a4b7b0`. A revision of this section that predates Phase 7 claimed "221+"
  when the real number was 207, which is exactly the kind of drift the review
  was meant to catch.
- `clippy -D warnings`, `cargo fmt --check` and a 1000-line per-file limit
  enforced in CI. The Python analyzer runs **outside** CI and has no tests of
  its own (see 6.8).
- Real-I2P integration tests (feature-gated): two-node signed message, three-
  node relay, plus SAM session tests.
- Offline simulation gates: entropy, mutual information, GPA top-1 and
  intersection gates PASS for `dcnet-mesh` / `dcnet-cover`.

## 6. Residual risks

1. **No full mixnet**: padding and cover traffic do not defeat a long-term
   global observer; volume and cadence remain. Timing shaping is specified
   but not wired at all (6.1).
2. **DC-Net content is not confidential**; only the sender is hidden.
3. **N−1 collusion** identifies the sender by construction.
4. **Trust bootstrap** relies on manual vouches; there is no revocation or
   expiry yet.
5. **File replication** is best-effort with no repair or incentives.
6. **i2pd trust**: anonymity at the network layer is inherited from the local
   router.
7. **Single maintainer**: bus factor and review capacity are limited.

### 6.1 Timing shaping is unwired

`EpochBatcher`/`jitter_millis` have no call sites. Phase 5 and Phase 6
documentation claimed otherwise; that claim has been removed from
`docs/PROTOCOL.md`, `docs/ATTACKS.md` and `docs/ROADMAP.md`.

### 6.2 Size shaping leaks at both ends

Payloads above 8187 bytes go out as raw frames, which covers file chunks
(≤ 64 KiB), manifests and history responses; the one-shot `ping`/`send`
session bypasses shaping entirely.

### 6.3 Restart is not survivable — resolved (Phase 7)

Relay nonces now come from a restart-safe allocator that persists a
reservation block before use and floors the counter at the wall clock; known
peers are redialled at startup, which rebuilds routes from gossip. Regression
test: `relay_resilience.rs::relay_survives_a_sender_restart`.

What remains: DHT state, admission pins and DC-Net round state are still
in-memory, so a restart re-learns them. Admission pins are rebuilt from the
first envelope received, which is the documented TOFU behaviour.

### 6.4 A rejected object closes the connection — resolved (Phase 7)

Rejections of third-party objects (relayed envelopes, flooded messages and
chunks, unservable chunk requests) now drop the object and keep the session;
only signature, size, encoding and binding failures on the peer's own
material stay fatal. Regression test:
`relay_resilience.rs::rejected_relays_keep_the_session_alive`.

### 6.5 Round ids desynchronise permanently — resolved (Phase 7)

Round ids are wall-clock based and quantised, so a node that observed no round
is not behind its peers and can still initiate. Regression test:
`dcnet_partial_mesh.rs::a_node_outside_the_rounds_can_still_initiate`.

New residual: participation now depends on a roughly correct clock. A node
off by more than the 30 s skew bound cannot join rounds at all, and a forward
clock jump invalidates in-flight rounds.

### 6.6 Reputation is a one-way ratchet — resolved (Phase 7)

Strikes are consecutive (`reward` is driven by completed rounds) and eviction
is reversible through the `reinstate` control command. A round of our own that
nobody joined is no longer attributed to the participants.

### 6.7 The timing-correlation metric is degenerate

Correlating a candidate against the sum of all candidates yields r ≈ 1 for
balanced traffic; the reported value is an artefact, not an attack result.
The metric is also the only entry in the attack matrix with no gate.

### 6.8 The N−1 collusion test is tautological, and the analyzer is untested

`recomputed == victim_share` holds for any share, message-carrying or not.
Separately, `analysis/` has no test suite and does not run in CI, even though
every anonymity gate lives there. Both are Phase 9 work.

### 6.9 Unsigned round starts and no forward secrecy in DC-Net

`DcRoundStart` carries no signature and its initiator is not checked against
the sending connection. Pairwise blocks derive from long-term static keys, so
they offer no forward secrecy.

### 6.10 Anonymous messages reach no application

An extracted message emits a local event only — no store, no flood, no
history, no IRC bridging — and its channel label is unauthenticated.

## 7. Recommendations

1. ~~Fix the correctness and wiring defects in 6.1–6.6~~ Phase 7 closed
   6.3–6.6. 6.1 (timing shaping) and 6.2 (size shaping) move to Phase 8.
2. Close the anonymous layer end to end (Phase 8) so anonymity is a usable
   property rather than a local display line.
3. Make the evidence trustworthy — analyzer tests in CI, a real timing metric,
   a real attribution test, longer campaigns — before commissioning the audit
   (Phase 9). A mixnet whose gates are tautological would not be evidence of
   anything.
4. Commission an external audit of the session/round/relay paths once Phase 9
   has landed.
5. Add vouch expiry/revocation and per-peer behavior scoring.
6. Consider forward-secret ratcheting for direct sessions, manifests and
   DC-Net pairwise blocks.
7. Remove the clock dependence introduced by 6.5's fix, or bound it: a round
   protocol that needs synchronized wall clocks should say so in the operator
   documentation.
