# Fantuan Network — Roadmap

Status: Phase 5 complete.

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
2. `fantuan-traffic`: fixed padding buckets, cover frames, epoch batching and
   bounded jitter (mix-lite).
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
deferred to Phase 6 hardening; Phase 5 ships mix-lite batching plus cover
traffic.

### Phase 6 — Attack hardening and documentation
Full attack matrix (GPA, partial, timing, intersection, n−1, participation
linkage), Sybil and DoS hardening, complete English documentation.

Exit: attack suite, English security report, complete docs.

## 4. Verification gates

Fast simulation seeds run in `cargo test`. Long runs use
`scripts/run-anon-analysis.sh` and write English reports to `reports/`.
I2P integration tests are feature-gated and never part of default CI.

## 5. Risks

| Risk | Mitigation |
|------|------------|
| SAM crate maintenance | Wrapped behind `SamSession`; evaluated alternatives recorded in `DEPENDENCIES.md` |
| nettle/SQLite native builds | Documented system packages; CI installs them |
| Mixed-language drift | Python confined to `analysis/`; JSON contract with Rust |
| DHT/mix scope | Dedicated design docs and milestones in Phases 4–5 |
| Regression loss from rewrite | Ported adversarial tests plus per-phase exit gates |

## 6. Open items

- O1 Commit identity for the new repository.
- O2 Optional passphrase protection for node secret keys.
- O3 DHT parameters and mix topology (Phase 4/5 design docs).
