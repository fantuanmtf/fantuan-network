# Fantuan Network — Internal Security Report (v0.1.0)

Status: internal review of Phases 1–6. This report is not a substitute for a
third-party audit.

## 1. Scope

Components reviewed: identity layer (OpenPGP/descriptors/bindings), transport
layer (I2P SAM + Noise), message layer (CBOR objects), trust graph and gossip,
relay layer, channel/forum/history handling, content-addressed file storage,
DC-Net anonymous rounds, traffic shaping, node control interfaces.

Out of scope: the i2pd router itself, the operating system, network
infrastructure, and the Python analyzer's statistical correctness beyond its
unit-tested primitives.

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
| Timing correlation | all candidates correlate equally | `dcnet-mesh` attack matrix |
| Intersection | stable membership ⇒ no shrinkage; selective ⇒ collapses to 1 | `attack-selective` scenario |
| N−1 collusion | attribution succeeds (known DC-Net limit) | `fantuan-anon` `colluding_majority_can_attribute_the_sender` |
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

- 221+ workspace tests, `clippy -D warnings`, `cargo fmt --check` and a
  1000-line per-file limit enforced in CI.
- Real-I2P integration tests (feature-gated): two-node signed message, three-
  node relay, plus SAM session tests.
- Offline simulation gates: entropy, mutual information, GPA top-1 and
  intersection gates PASS for `dcnet-mesh` / `dcnet-cover`.

## 6. Residual risks

1. **No full mixnet**: mix-lite padding/cover does not defeat a long-term
   global observer; volume and cadence remain.
2. **DC-Net content is not confidential**; only the sender is hidden.
3. **N−1 collusion** identifies the sender by construction.
4. **Trust bootstrap** relies on manual vouches; there is no revocation or
   expiry yet.
5. **File replication** is best-effort with no repair or incentives.
6. **i2pd trust**: anonymity at the network layer is inherited from the local
   router.
7. **Single maintainer**: bus factor and review capacity are limited.

## 7. Recommendations

1. Commission an external audit of the session/round/relay paths.
2. Implement a full mixnet and longer simulation campaigns (many seeds,
   larger N) before claiming strong anonymity.
3. Add vouch expiry/revocation and per-peer behavior scoring.
4. Consider forward-secret ratcheting for direct sessions and manifests.
