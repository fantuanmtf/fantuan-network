# Fantuan Network — Roadmap

Status: Phase 6 complete (v0.1.0). A post-Phase-6 review on 2026-09-23 found
three claims that were not backed by code and four defects that break
real multi-node operation; both are recorded in section 4 and are what
Phases 7–9 exist to fix. Nothing is removed from the earlier phases: the
delivered artefacts are real, but some of their surrounding claims were not.

## 1. Strategy

Greenfield rewrite of the Chrono-shift codebase. The old repository is
archived and used only as a source of algorithms, protocol ideas and
adversarial tests; its code and its vulnerabilities are not inherited.

Rust is the primary language, but the project is not constrained to pure
Rust. Native dependencies and mixed-language components are allowed when
justified and are logged in `docs/DEPENDENCIES.md`.

## 2. Confirmed decisions

| Area | Decision |
|------|----------|
| Repository | `github.com/fantuanmtf/fantuan-network` (origin), GitLab mirror |
| Push policy | Commit locally at milestones; push to GitHub and GitLab together |
| Identity | Real OpenPGP via `sequoia-openpgp` (nettle backend) |
| Storage | SQLite (`rusqlite`, bundled) for user/trust data; `redb` in Phase 4 |
| Transport | I2P SAM v3 (`yosemite`) + Noise (`snow`) |
| Identity/Noise binding | Independent X25519 static key, OpenPGP-signed |
| Message encoding | CBOR (`ciborium`) |
| Client | TUI (`ratatui`); no web console, no proxy service |
| File size | Every source file ≤ 1000 lines, CI-enforced |
| Language policy | Docs, reports, comments, identifiers, commits: English |
| Verification | Offline discrete-event simulation + statistical analysis |
| Attack coverage | GPA, partial adversarial nodes, timing, intersection, n−1, linkage |

## 3. Phases

### Phase 0 — Foundation (done)
Workspace, crate skeletons, CI (fmt, clippy, test, file size, cargo-audit),
English documentation skeleton, I2P development helper, git remotes.

Exit: CI green; conventions enforced.

### Phase 1 — Foundation stack (done)
1. `fantuan-core`: errors, configuration, secure file I/O, time helpers.
2. `fantuan-identity`: OpenPGP key hierarchy, descriptor creation and
   verification, identity binding, trust graph storage (SQLite).
3. `fantuan-msg`: canonical CBOR object envelope, detached signatures,
   size caps.
4. `fantuan-transport`: SAM session wrapper, Noise XX sessions, connection
   pool; live SAM tests behind `--ignored`.
5. `fantuan-sim` + `analysis/`: discrete-event core (virtual clock, event
   queue, seeded RNG, metrics) and the Python report pipeline.
6. `fantuan-node`: CLI (`identity init|show|export|import`, `run`, `ping`,
   `config`).

Exit met: two nodes complete an authenticated Noise session over real I2P
and exchange a CBOR message (`crates/fantuan-node/tests/i2p_session.rs`);
spoofing, replay, tamper and oversize tests pass.

### Phase 2 — Peer-to-peer (done)
1. Signed trust vouches (`TrustVouch`) and fixed-point `TrustGraph` scoring.
2. Gossip exchange of self-signed descriptors and vouches with verified
   ingestion and bounded propagation.
3. Relay envelopes with end-to-end OpenPGP payload encryption, per-origin
   admission control (nonces, freshness, rate limit, TOFU, hop limit) and
   next-hop routing.
4. Connection loop multiplexing inbound objects with an outbound queue, so
   gossip and relays can be sent from any task.
5. CLI: `send --to --via --message`, `peers`, `trust set --target --level`.

Exit met: three nodes form a network, learn each other through gossip, and a
message is relayed from A to C through B — proven both with an in-memory
duplex test and over real I2P
(`crates/fantuan-node/tests/relay_loopback.rs`, `tests/i2p_session.rs`).

### Phase 3 — BBS/IRC and client (done)
1. Signed `ChannelMessage`, `ForumPost`, `HistoryRequest/Response` and
   `DeleteRequest` objects with canonical CBOR, size caps and per-object id.
2. SQLite message store with dedup, per-topic history queries and delete.
3. Store-and-forward: subscribed objects are stored, emitted and flooded;
   reconnecting peers request history since their newest stored timestamp.
4. Local control socket (newline JSON + event stream) and a TUI client
   (`fantuan`) that chats, posts and reads.
5. Minimal IRC bridge mapping `JOIN`/`PRIVMSG` onto channels.

Exit met: two clients chat, post and read through one node (control API and
IRC tests); messages and forum posts published while a node is offline are
delivered through history sync on reconnect
(`crates/fantuan-node/tests/control_api.rs`, `tests/irc_bridge.rs`,
`tests/offline_history.rs`).

### Phase 4 — Distributed storage (done)
1. `fantuan-storage`: chunking, ChaCha20-Poly1305 encryption, content
   addressing and assembly; signed manifests; redb chunk cache with a byte
   budget; simplified Kademlia routing table; closest-node replication
   policy.
2. `fantuan-msg`: `FileChunk`, `FileManifest` and `ChunkRequest` objects.
3. Node: verified chunk ingest with one-shot flooding, TTL-bound chunk
   requests with reverse-path routing to DHT-closest peers, manifest delivery
   through relay envelopes, and `file_put` / `file_get` / `files` control
   commands.

Exit met: A publishes a 100 KiB file addressed to C, chunks replicate to B
and C, Alice's and Carol's caches are cleared, and Carol retrieves the exact
bytes from B while stored data never contains plaintext
(`crates/fantuan-node/tests/file_transfer.rs`).

### Phase 5 — Anonymous layer and traffic shaping (done)
1. `fantuan-anon`: X25519/HKDF pairwise shares, checksummed message frames,
   monotonic round tracking, share-authenticated mesh round driver, dropout
   reputation with eviction.
2. `fantuan-traffic`: fixed padding buckets and cover frames, plus batching and
   jitter primitives. **Correction (post-Phase-6 review):** the batching and
   jitter primitives are re-exported but never called, so only padding and
   cover traffic are actually wired. See section 4, finding F1.
3. `fantuan-msg`: `DcRoundStart` / `DcRoundShare` wire objects.
4. Node: anonymous scheduler and round handling, participants = connected
   non-evicted peers, per-round signatures verified against certificates,
   shaped connections with automatic cover traffic, `anon` control command
   and `/anon` in the TUI.
5. Simulator: `dcnet-mesh` and `dcnet-cover` scenarios with entropy, mutual
   information and correlation gates in both Rust tests and the Python
   report.

Exit met: three fully connected nodes each extract an anonymous message
(`crates/fantuan-node/tests/dcnet_rounds.rs`); evicted peers are excluded;
the analyzer reports PASS on entropy/MI gates for `dcnet-mesh`
(`reports/anonymity-dcnet-mesh-<seed>.md`).

Note: a full mixnet (fixed-size cells, layered routing, per-hop delays) is
deferred to Phase 11; Phase 5 shipped padding plus cover traffic, and the
batching/jitter primitives it added were never wired (see F1 in section 4).

### Phase 6 — Attack hardening and documentation (done)
1. Attack matrix: GPA entropy/top-1, timing correlation, intersection and
   participation linkage in `fantuan-sim::attacks` plus the Python analyzer;
   N−1/N−k collusion with real share algebra in `fantuan-anon`.
2. Sybil hardening: `require_vouch_for_gossip` gates third-party descriptors,
   `min_round_trust` filters round participants, relay quotas stay keyed by
   verified identity.
3. DoS hardening: per-connection token bucket, collector cap, bounded queues
   and tables, chunk request dedup, freshness windows.
4. Documentation: `docs/ATTACKS.md`, `docs/SECURITY_REPORT.md`, updated
   protocol, security, architecture and testing guides.

Exit met: attack suite (Rust + Python), English security report, and complete
documentation. Evidence: `crates/fantuan-sim/src/attacks.rs`,
`crates/fantuan-anon/src/share.rs` collusion tests,
`reports/anonymity-dcnet-mesh-11.md` (all gates PASS),
`docs/SECURITY_REPORT.md`.

## 4. Post-Phase-6 review (2026-09-23, commit `9a4b7b0`)

Verified state at review time: 207 tests pass
(`cargo test --workspace --release`, 0 failed, 2 ignored I2P integration
tests); `cargo fmt --check` and the 1000-line limit pass; the tree is clean
and both remotes are configured. `clippy -D warnings` was not re-run during
the review.

### 4.1 Claims without code behind them

| # | Claim | Reality |
|---|-------|---------|
| F1 | Epoch batching and jitter shipped (PROTOCOL.md, ATTACKS.md, ROADMAP Phase 5) | `EpochBatcher`/`jitter_millis` have no call sites; only padding and cover are wired |
| F2 | "221+ workspace tests" (SECURITY_REPORT.md) | 207 tests pass; the commit message was right and the report was not |
| F3 | Evicted peers can be reinstated (PROTOCOL.md, ATTACKS.md) | `reward`/`reinstate` are unreachable and strikes are cumulative, so eviction is permanent |

### 4.2 Defects that break multi-node operation

| # | Defect | Effect |
|---|--------|--------|
| D1 | Relay nonces restart at 1 and routes are not persisted | A restarted node is treated as a replayer and answers relay attempts with "no route" |
| D2 | Any rejected object breaks the session loop | A crafted relay, or an ordinary restart, tears down the link instead of dropping a frame |
| D3 | Round tracker accepts only `current + 1` | One missed round or a divergent participant set desynchronises DC-Net permanently |
| D4 | Strikes are cumulative with no reinstate path | Three lifetime dropouts evict a peer forever |

### 4.3 Weaknesses in the security evidence

| # | Issue | Effect |
|---|-------|--------|
| E1 | The timing-correlation metric correlates candidates against their own sum | `r ≈ 1` by construction; the reported 1.0000 is an artefact and has no gate |
| E2 | The N−1 collusion test asserts an algebraic identity | A regression breaking real attribution would still pass |
| E3 | `analysis/` has no tests and does not run in CI | Every anonymity gate lives in untested, unexecuted code |
| E4 | Padding stops at 8187 bytes and one-shot sends bypass shaping | File chunks, manifests and history responses leak their size |
| E5 | `DcRoundStart` is unsigned and its initiator is unchecked | Any connected peer can inject a round and occupy a collector slot |
| E6 | DC-Net pairwise blocks come from long-term static keys | No forward secrecy: one static-key compromise reveals all past rounds |

### 4.4 Functional gap

An extracted anonymous message emits a local event only — it is not stored,
flooded, served in history or bridged to IRC, and its channel label is
unauthenticated. Anonymous sending is not usable as a feature yet
(PROTOCOL §13.8, tracked as Phase 8).

## 5. Phases 7–11

The order matters: correctness first, then the anonymous layer's closed loop,
then trustworthy evidence, then the mixnet. Building a mixnet on gates that
are true by construction would produce a system that is confident and wrong.

### Phase 7 — Reliability and invariants

1. Make relay admission and routing restart-safe (persisted nonce high-water
   mark or a restart-safe window; persisted or re-derived routes; automatic
   re-dial of known peers from stored descriptors).
2. Downgrade non-fatal rejections to dropped frames; reserve session teardown
   for signature, size, encoding and binding failures (D2, PROTOCOL §13.4).
3. Replace the strict round counter with a windowed tracker plus a recovery
   path for lagging nodes (D3, PROTOCOL §13.5).
4. Make strikes consecutive, wire `reward`/`reinstate` or delete the claim
   (D4/F3, PROTOCOL §13.9).
5. Handle SIGTERM and drain queues before exit; add a systemd unit.

Exit: three new integration tests — relay survives a node restart; a rejected
or expired relay leaves the connection alive; a four-node non-full-mesh
topology still converges a DC-Net round.

### Phase 8 — Anonymous layer closed loop

1. Route extracted messages into channel/forum storage and flood, gated by an
   explicit opt-in setting, and expose them to the TUI, control socket, IRC
   bridge and history sync (F4, PROTOCOL §13.8).
2. Sign `DcRoundStart` and verify its initiator against the sending
   connection (E5, PROTOCOL §13.6).
3. Select a random participant subset per round instead of the whole
   connected set, to blunt intersection and selective-participation exposure.
4. Wire epoch batching and jitter, or delete the primitives and the claim
   (F1, PROTOCOL §13.1).
5. Give large objects a fixed-cell path so padding no longer stops at 8187
   bytes, and shape the one-shot send path (E4, PROTOCOL §13.2).
6. Replace long-term-key pairwise blocks with per-round ephemeral DH
   (E6, PROTOCOL §13.7).

Exit: an anonymous post is visible in the TUI and through the IRC bridge and
is served by history sync on reconnect; every frame a shaped connection emits
falls on a bucket boundary, including file chunks; the analysis gates still
PASS with batching enabled.

### Phase 9 — Trustworthy evidence before any audit

1. Add a pytest suite for `analysis/` and run it plus the analyzer in CI
   (E3).
2. Replace the timing metric with one that correlates a candidate against an
   observation of the link rather than the candidate sum, and gate it (E1).
3. Replace the N−1 test with a real attribution test that compares an
   observed share against the neutral value (E2).
4. Give every gate a negative case proving it can fail.
5. Long-run campaigns: many seeds, larger N, published reports.

Exit: CI runs the Python analyzer; each gate fails on a deliberately broken
input; campaign reports land in `reports/`.

### Phase 10 — Operations and v0.2.0

1. Optional passphrase protection for node secret keys (open item O2).
2. `config validate` / `config write` CLI and a way to dump effective config.
3. Metrics or a health surface, structured logging.
4. Packaging, changelog, `v0.2.0` tag.

Exit: the node can be managed by systemd, stopped cleanly, and released with
artefacts.

### Phase 11 — Full mixnet

Fixed-size cells, layered routing and per-hop delays, replacing the
padding-plus-cover approximation. Only worth starting once Phase 9 has made
the measuring instruments trustworthy.

Exit: an audit-grade anonymity report for fixed-cell routing.

### Deferred, unscheduled

| Priority | Item |
|----------|------|
| Medium | Vouch expiry/revocation and per-peer behavior scoring |
| Medium | Forward-secret ratcheting for direct sessions and manifests |
| Low | Erasure-coded file replication with repair |

## 6. Verification gates

Fast simulation seeds run in `cargo test`. Long runs use
`scripts/run-anon-analysis.sh` and write English reports to `reports/`.
I2P integration tests are feature-gated and never part of default CI.

Gates are only worth what their instruments are worth. Until Phase 9 puts the
analyzer under test, a PASS means the pipeline ran, not that the property
holds (see findings E1–E3).

## 7. Risks

| Risk | Mitigation |
|------|------------|
| SAM crate maintenance | Wrapped behind `SamSession`; evaluated alternatives recorded in `DEPENDENCIES.md` |
| nettle/SQLite native builds | Documented system packages; CI installs them |
| Mixed-language drift | Python confined to `analysis/`; JSON contract with Rust |
| DHT/mix scope | Dedicated design docs and milestones: DHT in Phase 4, mixnet in Phase 11 |
| Regression loss from rewrite | Ported adversarial tests plus per-phase exit gates |
| Self-confirming evidence | Every gate gets a negative case in Phase 9; the timing metric proved the risk is real (E1) |
| Documentation drifting ahead of code | `docs/PROTOCOL.md` §13 tracks deviations; a review pass is a phase activity, not an afterthought |

## 8. Open items

- O1 Commit identity for the new repository — resolved (`fantuanmtf`, both
  remotes configured).
- O2 Optional passphrase protection for node secret keys (Phase 10).
- O3 DHT parameters and mix topology — folded into the Phase 11 mixnet design
  doc.
