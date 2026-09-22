# Fantuan Network — De-anonymization Attack Matrix

This document describes the attacks that are implemented in CI and in the
offline analyzer, what they measure, and the current results. Attacks are
run over discrete-event transcripts from `fantuan-sim` and over the real
DC-Net share algebra in `fantuan-anon`.

Reproduce:

```bash
bash scripts/run-anon-analysis.sh dcnet-mesh 11     # gates + attack matrix
bash scripts/run-anon-analysis.sh attack-selective 2
cargo test --workspace                              # attack assertions in CI
```

## 1. Attack inventory

| # | Attack | Model | Where implemented | Result |
|---|--------|-------|-------------------|--------|
| 1 | Global passive adversary (GPA) | sees every frame, timing and size | `fantuan-sim::attacks`, Python `attack_matrix` | entropy = log2(N), top-1 = 1/N for `dcnet-mesh` |
| 2 | Timing correlation | correlates candidate streams with aggregate traffic | `fantuan-sim::attacks`, Python | all participants correlate equally; no candidate stands out |
| 3 | Intersection | intersects per-round candidate sets | `fantuan-sim::attacks` (`attack-selective`) | collapses to 1 when participation is selective |
| 4 | Participation linkage | links consecutive rounds by participant set | `fantuan-sim::attacks` | stable groups link, but do not identify the sender |
| 5 | N−1 collusion | colluders know all pairwise blocks of the sender | `fantuan-anon` collusion tests | attribution succeeds with N−1 colluders |
| 6 | N−k collusion | minority of colluders | `fantuan-anon` collusion tests | attribution fails; unknown pairwise blocks remain |
| 7 | Replay / forgery | replayed shares, forged signatures | `fantuan-anon`, `fantuan-msg` tests | rejected |
| 8 | Unknown signer | shares signed by unregistered keys | `fantuan-anon::driver` | rejected before collection |
| 9 | Sybil descriptors | unvouched third-party gossip | `fantuan-node::gossip` test | rejected when `require_vouch_for_gossip` is on |
| 10 | Frame flood | excessive inbound frames | `fantuan-traffic::limit` | dropped over budget, connection kept |

## 2. DC-Net specifics

- **Sender anonymity** holds against any adversary that does not control all
  but one participant: every participant transmits a pseudorandom share every
  round, and shares are derived from pairwise X25519 secrets that are never
  transmitted.
- **Message confidentiality** is *not* a DC-Net property: the XOR of all
  shares is public to anyone who observes the round. Do not send secrets
  through a DC-Net round expecting content secrecy; use the relay layer with
  OpenPGP encryption for that.
- **N−1 collusion** identifies the sender. Rounds therefore select
  participants by trust and cap the participant count; deployments with
  hostile majorities should require `min_round_trust >= 1`.
- **Selective participation** is the weakest point: if a node joins every
  round while others come and go, the intersection attack isolates it. The
  scheduler currently invites every connected, non-evicted peer, which keeps
  the candidate set stable; operators should avoid manual selective
  participation patterns.

## 3. Traffic analysis

- Frame padding to fixed buckets removes length leakage from padded
  connections (buckets 256..8192 bytes).
- Cover traffic is indistinguishable from padded data at the frame level and
  removes the "silence" signal of an idle link.
- Epoch batching and bounded jitter blur exact send times (mix-lite).
- Residual: a global passive adversary still observes long-term volume and
  round cadence. A full mixnet with layered routing and per-hop delays is
  future work.

## 4. Reputation and eviction

- Rounds expire after 15 s; missing shares produce strikes.
- Three strikes evict a peer from future rounds (`MAX_STRIKES = 3`).
- Evicted peers can be reinstated manually; strikes reset after a successful
  round.

## 5. Known gaps and recommendations

1. A full mixnet is not implemented; mix-lite batching is a mitigation, not a
   proof.
2. Third-party descriptor acceptance is signature-verified but only
   vouch-gated when `require_vouch_for_gossip = true`.
3. Trust scoring depends on manually established vouches; there is no
   automatic revocation or expiry.
4. Long-run simulations (many seeds, larger round counts) should be run
   before any third-party audit.
