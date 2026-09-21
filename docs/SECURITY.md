# Fantuan Network — Security

## 1. Threat model

| Adversary | Capabilities | Mitigations (Phase 1) |
|-----------|--------------|------------------------|
| Passive network observer | observes I2P traffic timing/volume | I2P transport; traffic shaping in Phase 5 |
| Active MITM | can modify or drop traffic | Noise XX authentication; identity binding; descriptor signatures |
| Impersonator | knows a peer fingerprint, not its key | OpenPGP certificate verification; handshake binding; no unauthenticated sessions |
| Replay attacker | re-sends recorded frames | Noise nonces; session binding over handshake hash |
| Malicious peer | sends crafted descriptors/objects | strict decoding, size caps, canonical CBOR, signature verification before use |
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
6. Trust decisions (Phase 2) never consume an unverified signature.

## 3. Key handling

- Node identity lives in `~/.fantuan/identity/`:
  - `cert.pgp` — public OpenPGP certificate;
  - `secret.pgp` — secret key material (0600);
  - `descriptor.cbor` and `descriptor.sig`;
  - `noise.x25519` — X25519 static secret (0600).
- Files are created with restrictive permissions from the first write.
- Secret buffers use `zeroize` where the type system allows it.

## 4. Known limitations (Phase 1)

- I2P anonymity assumptions are inherited from the local i2pd router.
- Message metadata (sender fingerprint, timestamp, size) is visible to the
  peer and to I2P; DC-Net and traffic shaping arrive in Phase 5.
- No forward-secret ratchet yet: each session uses a fresh Noise handshake
  and rekeys after the configured frame budget.
- Trust graph storage exists but scoring and gossip are Phase 2.

## 5. Reporting

Security issues are reported privately to the maintainers. Adversarial tests
must be added with every security fix and are listed in `docs/TESTING.md`.
