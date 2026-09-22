# Fantuan Network — Internal Security Report (v0.1.0)

Status: internal review of Phases 1–6. This report is not a substitute for a
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
- **Anonymity layer**: round ids advance by exactly one, share signatures
  verified against known certificates, dropouts penalized and evicted.
- **Local interfaces**: control socket mode 0600, IRC bridge bind address is
  operator-controlled (loopback recommended), delete requests only accepted
  from the original owner.
- **Dependencies**: `cargo audit --deny warnings` runs in CI.

## 5. Verification evidence

- 207 workspace tests pass (`cargo test --workspace --release`, 0 failed,
  2 ignored I2P integration tests), measured on 2026-09-23 at commit
  `9a4b7b0`. An earlier revision of this section claimed "221+", which was
  never true.
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

### 6.3 Restart is not survivable

Relay nonces restart at 1, and routing tables, DHT state, admission pins and
DC-Net round state are all in-memory. A restarted node is treated as a
replayer by its peers, has no route to answer relay attempts with, and has no
automatic re-dial for known peers.

### 6.4 A rejected object closes the connection

Admission and routing rejections are returned as errors from `handle_object`
and break the session loop, so a crafted relay — or a peer's ordinary
restart — tears down a link rather than dropping a frame.

### 6.5 Round ids desynchronise permanently

`RoundTracker::mark_seen` accepts only `current + 1`. Any missed round, or any
divergence in the observed participant set between nodes, desynchronises the
tracker for good; honest peers then accrue strikes against each other.

### 6.6 Reputation is a one-way ratchet

Strikes are cumulative (the module doc says consecutive), and
`reward`/`reinstate` are unreachable, so eviction lasts for the process
lifetime. `docs/PROTOCOL.md` has been corrected accordingly.

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

1. Fix the correctness and wiring defects in 6.1–6.6 before adding features
   (Phase 7) and before building the mixnet (Phase 11): a mixnet whose gates
   are tautological would not be evidence of anything.
2. Close the anonymous layer end to end (Phase 8) so anonymity is a usable
   property rather than a local display line.
3. Make the evidence trustworthy — analyzer tests in CI, a real timing metric,
   a real attribution test, longer campaigns — before commissioning the audit
   (Phase 9).
4. Commission an external audit of the session/round/relay paths once Phase 9
   has landed.
5. Add vouch expiry/revocation and per-peer behavior scoring.
6. Consider forward-secret ratcheting for direct sessions, manifests and
   DC-Net pairwise blocks.
