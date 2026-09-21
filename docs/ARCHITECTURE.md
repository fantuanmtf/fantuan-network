# Fantuan Network — Architecture

Status: Phase 1. This document describes the target architecture and the
crate-level rules that keep it maintainable.

## 1. Layers

```
Application     IRC / BBS / File / DM clients and local bridges
Message         Object envelope: message, forum_post, file_chunk, delete_request
Anonymous       DC-Net rounds, mix routing, padding, scheduler
Storage         content-addressed chunks, DHT, cache, replication
Identity        OpenPGP key hierarchy, descriptors, trust graph, reputation
Transport       I2P SAM v3, Noise sessions, connection pool
Network Node    peer discovery, routing, relay, workers
```

The layers are independent beyond their declared interfaces. A layer may only
depend on layers below it, plus `fantuan-core` for shared primitives.

## 2. Crates

| Crate | Layer | Depends on | Introduced |
|-------|-------|------------|------------|
| `fantuan-core` | shared | — | Phase 0 |
| `fantuan-identity` | Identity | core | Phase 1 |
| `fantuan-msg` | Message | core, identity | Phase 1 |
| `fantuan-transport` | Transport | core | Phase 1 |
| `fantuan-sim` | analysis | — | Phase 0 |
| `fantuan-node` | Node | all above | Phase 1 |
| `fantuan-storage` | Storage | core | Phase 4 |
| `fantuan-anon` | Anonymous | core, msg | Phase 5 |
| `fantuan-traffic` | Anonymous | core | Phase 5 |
| `fantuan-client` | Application | core, msg, transport | Phase 3 |

Crates are added when their phase starts; no placeholder crates are kept.

## 3. Key design decisions

1. **Real OpenPGP identity.** Keys are managed with `sequoia-openpgp`
   (nettle backend): a primary certify key plus signing and encryption
   subkeys. The primary key certifies everything else.
2. **Noise static keys are separate.** Noise requires X25519 static keys,
   which OpenPGP does not expose directly. Each node generates an
   independent X25519 static keypair; the OpenPGP signing key endorses the
   public half inside the descriptor. This avoids ambiguous key conversion.
3. **Descriptor.** A canonical CBOR document describing a node: fingerprint,
   OpenPGP certificate, X25519 Noise static key, I2P destination,
   capabilities. It is self-signed; peers verify the signature before use.
4. **Session binding.** After a Noise handshake completes, both sides send an
   identity binding message over the encrypted channel signed by the OpenPGP
   key over the handshake hash. This binds the OpenPGP identity to the exact
   session and prevents replay across sessions.
5. **CBOR envelope.** All application objects use a canonical CBOR encoding
   with one top-level tagged enum. JSON remains a reporting format only.
6. **I2P-first transport.** Nodes connect through the local i2pd SAM v3
   bridge using the `yosemite` crate. The transport layer exposes a
   `SamSession` abstraction so the crate can be replaced without touching
   callers.
7. **Offline verification.** Anonymity properties are measured with a
   discrete-event simulator (Rust) plus a Python statistical analyzer, so
   claims are reproducible without a network.

## 4. Data flow (Phase 1)

```
fantuan-node
  |  load ~/.fantuan identity + descriptor
  |  open SAM session (stream style) with persistent destination
  |
  +--> accept loop  --\
  +--> connect(dest) --+--> Noise XX handshake --> identity binding
                        |
                        v
                  CBOR Object frames (signed)
```

Both directions share one `Session` type: a Noise transport state machine
that frames, encrypts, decrypts and enforces read/write timeouts.

## 5. Reliability rules

- Every peer connection runs as two tasks: a reader and a writer owning the
  respective transport halves, connected by a bounded queue.
- Stale connections are removed by connection id, never by uid alone.
- All queues, frames and descriptors have explicit size caps.
- Shutdown is cooperative: workers observe a cancellation signal and drain
  bounded queues before exit.
