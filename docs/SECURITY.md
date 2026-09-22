# Fantuan Network — Security

## 1. Threat model

| Adversary | Capabilities | Mitigations (Phase 1) |
|-----------|--------------|------------------------|
| Passive network observer | observes I2P traffic timing/volume | I2P transport; traffic shaping in Phase 5 |
| Active MITM | can modify or drop traffic | Noise XX authentication; identity binding; descriptor signatures |
| Impersonator | knows a peer fingerprint, not its key | OpenPGP certificate verification; handshake binding; no unauthenticated sessions |
| Replay attacker | re-sends recorded frames | Noise nonces; session binding over handshake hash |
| Malicious peer | sends crafted descriptors/objects | strict decoding, size caps, canonical CBOR, signature verification before use |
| Malicious relay | forwards forged or replayed envelopes | per-hop signature checks, TOFU pins, monotonic nonces, freshness window, rate limits, hop limit |
| Local attacker | reads files on disk | secrets stored 0600, directories 0700, secrets zeroized on drop |

The old Chrono-shift repository carries known vulnerabilities and is
reference-only. No code is merged from it without re-derivation and tests.

## 2. Security invariants

1. No plaintext protocol frame is accepted after a session is established.
2. A session is only usable after both descriptor verification and identity
   binding succeed.
3. Secrets never appear in logs, error strings, `Debug` output or reports.
4. Every parser (CBOR, descriptor, frame header) has explicit size caps.
5. Signature checks use the verifier's stored/parsed key, never a key chosen
   by the attacker in the same message.
6. Trust decisions (Phase 2) never consume an unverified signature: gossip
   descriptors must verify their self-signature and vouches must verify
   against the signer's stored certificate.
7. Relay payloads are OpenPGP-encrypted to the destination; intermediate
   hops can verify the origin but cannot read content.
8. Relay admission is keyed by the verified origin fingerprint and TOFU-pins
   the origin certificate, so claimed identities cannot multiply quotas.
9. Local interfaces are host-local: the control socket is created with mode
   0600, and the IRC bridge should bind a loopback address. They grant full
   control of the local node and must never be exposed to a network.
10. Deletes are only honoured when signed by the same key that created the
    target object.
11. Storage nodes only ever persist `BLAKE3(ciphertext) -> ciphertext`; file
    keys travel exclusively inside relay envelopes encrypted to the
    recipient, and the cache has an explicit byte budget.
12. Chunks are verified against their owner signature and embedded hash
    before they are stored or forwarded.
13. DC-Net shares are derived from pairwise X25519 secrets and signed; an
    observer without any pair key learns nothing about the sender, and shares
    from unknown signers are rejected.
14. Shaped connections pad every frame to a fixed bucket and blend cover
    frames, so message length and exact send timing are not observable at the
    frame layer.

## 2.1 Sybil resistance

- Identities are free to create, so trust — not identity existence — decides
  influence.
- Gossip accepts third-party descriptors only when
  `require_vouch_for_gossip = true` and the forwarding peer has a stored
  vouch for the subject.
- DC-Net participants can be restricted with `min_round_trust` (0 = open,
  1 = Marginal+, 2 = Full+); evicted peers are excluded from selection.
- Relay quotas are keyed by the verified identity key, so many claimed uids
  behind one key share a single quota.

## 2.2 DoS resistance

- Per-connection token bucket (`max_frames_per_sec`, default 500); over-limit
  frames are dropped while the connection stays up.
- Bounded connections (256), writer queues (64), inbound queue (1024), relay
  tables (4096, coarse eviction), chunk cache (byte budget), round collectors
  (16) and gossip lists (64/256).
- Freshness windows and monotonic nonces reject replay floods; chunk requests
  carry a hop limit and a per-(hash, requester) dedup table.

## 3. Key handling

- Node identity lives in `~/.fantuan/identity/`:
  - `cert.pgp` — public OpenPGP certificate;
  - `secret.pgp` — secret key material (0600);
  - `descriptor.cbor` and `descriptor.sig`;
  - `noise.x25519` — X25519 static secret (0600).
- Files are created with restrictive permissions from the first write.
- Secret buffers use `zeroize` where the type system allows it.

## 4. Known limitations (Phase 3)

- I2P anonymity assumptions are inherited from the local i2pd router.
- Relay metadata (origin fingerprint, destination fingerprint, timing, size)
  is visible to every hop; DC-Net and traffic shaping arrive in Phase 5.
- Channel and forum metadata (senders, topics, timing, sizes) is visible to
  connected peers that subscribe to the same topic.
- Gossip reveals the local peer list to direct peers; propagation is
  bounded but not differentially private.
- History is served from the local store with a per-request cap; there is no
  global consistency guarantee between peers.
- File replication is best-effort flooding: there is no erasure coding, no
  repair of lost chunks and no incentive for nodes to keep data. Retrieval
  fails if every holder goes offline.
- DC-Net rounds require a direct full mesh between participants; shares are
  not relayed, so round size is bounded by direct connectivity.
- Traffic shaping is mix-lite (padding buckets plus cover); a global passive
  adversary can still correlate long-term traffic volumes and cover traffic
  is not yet rate-adaptive. A full mixnet is future work.
- Round participation and timing metadata remain visible to connected peers;
  only the sender of an extracted message is hidden.
- Trust scoring uses locally stored vouches; revoked or stale vouches are not
  yet expired automatically.
- No forward-secret ratchet yet: each session uses a fresh Noise handshake
  and rekeys after the configured frame budget.

## 5. Reporting

Security issues are reported privately to the maintainers. Adversarial tests
must be added with every security fix and are listed in `docs/TESTING.md`.
