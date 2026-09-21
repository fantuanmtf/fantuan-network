# Fantuan Network — Protocol (Phase 1)

Status: Phase 1 specification. Implementation must match this document; any
change lands here first.

## 1. Layers

```
Object   CBOR application objects (signed)
   |
Session  Noise XX transport + identity binding
   |
I2P      SAM v3 stream over a persistent destination
```

## 2. Descriptor

A descriptor is a canonical CBOR map with integer keys:

| Key | Field | Type | Description |
|-----|-------|------|-------------|
| 1 | `version` | uint | descriptor format version (currently 1) |
| 2 | `uid` | text | human-readable node name |
| 3 | `fingerprint` | text | uppercase hex OpenPGP fingerprint |
| 4 | `openpgp_cert` | bytes | public OpenPGP certificate |
| 5 | `noise_x25519_pub` | bytes(32) | Noise static public key |
| 6 | `i2p_destination` | text | base64 I2P destination |
| 7 | `capabilities` | array of text | e.g. `chat`, `bbs`, `storage` |
| 8 | `created` | uint | Unix seconds |

The descriptor bytes are signed by the OpenPGP signing subkey with a
detached, binary signature. A descriptor MUST be rejected unless:

1. it decodes canonically and all required fields are present;
2. `fingerprint` matches the fingerprint of `openpgp_cert`;
3. the signature verifies under a signing-capable key of that certificate.

## 3. Session handshake

Noise pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`.

1. The initiator connects to the responder's I2P destination (SAM
   `STREAM CONNECT`); the responder accepts (`STREAM ACCEPT`).
2. Both sides run the Noise XX handshake with their per-node X25519 static
   keys.
3. Frames are Noise transport messages, each prefixed with a 4-byte
   big-endian length. Maximum frame size is 65536 bytes.

### 3.1 Identity binding

Immediately after the Noise handshake, each side sends one encrypted
`IdentityBinding` object:

```
binding_message = "fantuan-identity-binding-v1"
                  || handshake_hash (32 bytes)
                  || local_noise_static_pub (32 bytes)
```

- `handshake_hash` comes from the local Noise state and is identical on both
  sides.
- The binding carries the sender's descriptor and an OpenPGP detached
  signature over `binding_message`.

A peer MUST be rejected when:

- the descriptor signature does not verify;
- `descriptor.noise_x25519_pub` differs from the Noise static key actually
  used by the peer;
- the OpenPGP signature over the binding does not verify.

## 4. Session frames

- Frame: `u32be length || Noise transport ciphertext`.
- Nonce management and replay rejection are provided by Noise; the session
  additionally enforces an idle timeout and a maximum frame count before a
  new handshake (rekey) is required.
- A clean shutdown closes the underlying I2P stream.

## 5. Object envelope

Application objects are CBOR values with a single-key map whose key is a
text tag:

| Tag | Payload |
|-----|---------|
| `message` | `Message` |
| `forum_post` | `ForumPost` (Phase 3) |
| `file_chunk` | `FileChunk` (Phase 4) |
| `delete_request` | `DeleteRequest` (Phase 3) |
| `ping` | monotonic uint + timestamp |
| `pong` | echo of the ping timestamp |

`Message` fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | bytes(32) | BLAKE3 of the canonical body |
| `sender` | text | sender OpenPGP fingerprint |
| `timestamp` | uint | Unix seconds |
| `payload` | bytes | application payload (Phase 1: UTF-8 text) |
| `signature` | bytes | OpenPGP detached signature over `body` |

where

```
body = "fantuan-message-v1" || canonical_cbor(Message without id, signature)
```

Size caps (Phase 1): descriptor ≤ 64 KiB, frame ≤ 64 KiB, message payload
≤ 32 KiB.

## 6. Failure handling

- Handshake timeout: 10 seconds.
- Idle read timeout: 120 seconds.
- Write timeout per frame: 15 seconds.
- Any signature, size or binding failure closes the connection; errors are
  logged without secrets.
