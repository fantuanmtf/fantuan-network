# Fantuan Network — Roadmap

Status: Phase 1 complete.

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

### Phase 2 — Peer-to-peer
Descriptor exchange discovery (bootstrap list plus trust-weighted gossip),
SQLite trust graph scoring, signed messaging, router and relay.

Exit: three-node network; trust chain queryable; relayed message delivered.

### Phase 3 — BBS/IRC and client
Channels, forum posts, offline messages, TUI, local IRC bridge.

Exit: two TUI clients chat, post and read; offline messages are delivered
after reconnect.

### Phase 4 — Distributed storage
Content-addressed chunks (BLAKE3, ChaCha20-Poly1305, owner signature),
cache (`redb`), Kademlia DHT, replication.

Exit: publish and retrieve a file across three nodes; nodes see only hashes
and ciphertext.

### Phase 5 — Anonymous layer
DC-Net (mesh baseline), scheduler, malicious detection and reputation
penalty, mix routing, padding, traffic batching and cover traffic.
Simulator scenarios cover each mechanism.

Exit: anonymous round delivery with three or more nodes; dropout eviction;
entropy, mutual information and Pearson gates pass.

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
