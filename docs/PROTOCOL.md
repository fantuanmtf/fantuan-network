# Fantuan Network — Protocol (v0.1.0)

Status: implemented through Phase 6. Implementation must match this document;
any change lands here first. Known deviations of the current implementation
are listed in [section 13](#13-implementation-status-and-known-gaps-v010)
rather than silently tolerated.

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
                  || BLAKE3(canonical_descriptor) (32 bytes)
```

- `handshake_hash` comes from the local Noise state and is identical on both
  sides.
- The binding carries the sender's descriptor and an OpenPGP detached
  signature over `binding_message`; including the descriptor hash means every
  descriptor field is covered by the signature.

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
| `message` | `Message` (direct message) |
| `channel_message` | `ChannelMessage` (section 8) |
| `forum_post` | `ForumPost` (section 8) |
| `history_request` | `HistoryRequest` (section 8) |
| `history_response` | `HistoryResponse` (section 8) |
| `delete_request` | `DeleteRequest` (section 8) |
| `file_chunk` | `FileChunk` (section 10) |
| `file_manifest` | `FileManifest` (section 10, relay-only) |
| `chunk_request` | `ChunkRequest` (section 10) |
| `dc_round_start` | `DcRoundStart` (section 11) |
| `dc_round_share` | `DcRoundShare` (section 11) |
| `ping` | monotonic uint + timestamp |
| `pong` | echo of the ping timestamp |
| `gossip` | descriptors + trust vouches (section 6) |
| `relay` | end-to-end encrypted relay envelope (section 7) |

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

## 6. Gossip

Immediately after a session is established, each side sends one `gossip`
object:

```
Gossip { announcements: [Announcement; <=64], vouches: [TrustVouch; <=256] }
Announcement { descriptor: bytes, signature: bytes }   # self-signed descriptor
TrustVouch   { signer, subject, level, timestamp, signature }
```

- A node always includes its own descriptor with its detached self-signature.
- Receivers verify each announcement with `Descriptor::verify` and each vouch
  against the signer's stored certificate before storing anything.
- Newly learned descriptors are stored as `fingerprint -> descriptor` and the
  route `fingerprint -> sender` is recorded for relaying.
- When a gossip message teaches a node something new, it replies with its
  updated list and pushes it to its other peers, so knowledge propagates.
  A message that teaches nothing new is never echoed.

## 7. Relay

```
Relay { origin, to, nonce, timestamp, hops_left, signature, payload }
```

- `payload` is an OpenPGP message encrypted to the destination's
  transport-encryption subkey (`encrypt_for`), so relays never see plaintext.
- `signature` is the originator's detached OpenPGP signature over

  ```
  "fantuan-relay-v1" || len(origin) || origin || len(to) || to
                     || nonce || timestamp || len(payload) || payload
  ```

  `hops_left` is excluded so relays can decrement it.
- Admission per origin fingerprint: strictly increasing nonces, a ±60 s
  freshness window, at most 60 envelopes per 60 s window, TOFU certificate
  pinning, and at most 8 hops.
- The destination decrypts the payload and processes the inner object; a
  relay with `to` different from the local fingerprint is forwarded to the
  next hop one hop closer (`hops_left - 1`).

## 8. Channels, forums and offline delivery

```
ChannelMessage { id, sender, channel, timestamp, text, signature }
ForumPost      { id, sender, board, title, body, timestamp, signature }
HistoryRequest { topic, is_board, since }
HistoryResponse{ topic, is_board, messages[], posts[] }
DeleteRequest  { sender, target, timestamp, signature }
```

- Bodies are canonical CBOR prefixed with a domain separator
  (`fantuan-channel-v1`, `fantuan-forum-v1`); ids are BLAKE3 over the body.
- Limits: channel text ≤ 8 KiB, title 1..=256 B, forum body ≤ 32 KiB, topic
  names ≤ 64 B of `A-Za-z0-9#-_. /`.
- A node only stores and forwards objects for topics it subscribes to. The
  first time an object id is stored it is emitted locally and flooded to all
  other connected peers; later copies are dropped.
- On every new session a node sends one `HistoryRequest` per subscription
  with `since` = the newest timestamp it has stored. The peer answers with at
  most 200 messages or 100 posts, which are individually verified against the
  sender certificates before storage.
- `DeleteRequest` must be signed by the same key that created the target
  object; a node deletes the object and floods the request only when
  something was actually removed.

## 9. Local interfaces

Both interfaces are local-only and are not part of the peer protocol.

- **Control socket** (`data_dir/control.sock`, mode 0600, newline-delimited
  JSON): `status`, `post`, `forum`, `read`, `read_forum`, `send`, `peers`,
  `events`. The `events` command switches the connection to a stream of
  event lines (`channel`, `forum`, `message`, `relay`).
- **IRC bridge** (optional, bind address from `irc_addr`, loopback
  recommended): `NICK`, `USER`, `JOIN`, `PART`, `PRIVMSG`, `PING`, `QUIT`.
  `PRIVMSG #channel :text` publishes a channel message; stored channel
  events are broadcast to every IRC client that joined the channel.

## 10. Files

```
FileChunk    { file_id, index, hash, nonce, ciphertext, owner, signature }
FileManifest { file_id, owner, name, size, chunk_size, chunks[], key, created, signature }
ChunkRequest { file_id, index, hash, requester, ttl }
```

- Publishing splits the plaintext into 32 KiB chunks, encrypts each with
  ChaCha20-Poly1305 under a random per-file key using associated data
  `file_id || index`, and content-addresses the ciphertext with BLAKE3.
- The owner signs each chunk over
  `"fantuan-chunk-v1" || owner || file_id || index || hash` and signs the
  manifest over its canonical body (`"fantuan-file-v1"`).
- The manifest carries the file key. It is **never** sent as a plain object:
  direct `file_manifest` messages are ignored, and manifests are only
  accepted inside a relay envelope, encrypted to the recipient.
- Chunks are flooded once (deduplicated by the cache) so connected peers
  replicate them. Nodes only ever persist `hash -> ciphertext`.
- Retrieval sends `ChunkRequest` with TTL 8 to the DHT-closest connected
  peers. Nodes that have the chunk answer with the stored `file_chunk`
  object; nodes that do not remember a reverse path `(requester, via)` and
  forward the request one hop closer. Responses follow the reverse path back
  to the requester, which verifies every hash and decrypts.
- Limits: 128 MiB per file, 4096 chunks, names up to 256 bytes, chunk
  requests forwarded at most 8 hops.

## 11. DC-Net rounds and traffic shaping

```
DcRoundStart { channel, round_id, initiator, participants[], deadline_secs, payload_len }
DcRoundShare { channel, round_id, peer_uid, xored_payload, signature }
```

- Underlying key: each participant derives a pairwise block from
  `ECDH(static_a, static_b)` with the node's Noise X25519 keys, expanded via
  HKDF with `"fantuan-dcnet-pair-v1" || round_id || sorted uids`. XOR-ing all
  pairwise blocks across participants cancels every block.
- Rounds are a mesh: the initiator broadcasts `DcRoundStart`, every other
  participant broadcasts one neutral share, and the initiator broadcasts its
  message-carrying share **last** once every other share arrived. Every node
  XORs all shares and extracts the checksummed message frame
  (`[u32 length][BLAKE3 checksum][message][zero pad]`).
- Round ids advance by exactly one (`+1`); far-future ids are rejected.
  Simultaneous initiations are resolved by comparing initiator fingerprints
  (the smaller wins; the loser aborts before sending a message share).
- Shares are signed by the sender's OpenPGP key and verified against the
  signer's stored certificate. Unknown signers are rejected.
- Limits: 2..=16 participants, payload length 36..=4096 bytes, deadline
  ≤ 30 s. Messages longer than `payload_len - 36` are refused.
- Rounds require direct connectivity between all participants (mesh); the
  scheduler only selects currently connected, non-evicted peers.
- Expired rounds with missing shares report the missing participants; three
  strikes evict a peer from future rounds. Strikes are **cumulative over the
  lifetime of the process**, not consecutive, and no reinstate path is wired
  (see section 13.9).

### Traffic shaping

Every frame sent by a shaped connection is padded into one of the buckets
`256, 512, 1024, 2048, 4096, 8192` bytes:

```
[0x01][u32 original length][original bytes][random fill]   padded frame
[0x02][random bytes]                                       cover frame
<anything else>                                            raw frame
```

- Receivers discard cover frames and unwrap padded frames; raw frames are
  accepted for compatibility with direct one-shot sends.
- Cover traffic is generated once per cover interval toward every connected
  peer; it is indistinguishable from padded data at the frame level.
- Epoch batching (10 s) and bounded jitter (≤ 250 ms) are **specified but not
  implemented**: `EpochBatcher` and `jitter_millis` exist in
  `crates/fantuan-traffic/src/batching.rs` and have no call sites, so
  outbound frames leave immediately and unjittered (see section 13.1).
- Shaping applies only to frames up to 8187 bytes; larger objects (file
  chunks, manifests, history responses) are sent as raw frames, and one-shot
  `ping`/`send` connections bypass shaping entirely (see section 13.2).
- The shipped approximation is therefore padding buckets plus fixed-rate
  cover only; a full mixnet remains future work.

## 12. Failure handling

- Handshake timeout: 10 seconds.
- Idle read timeout: 120 seconds.
- Write timeout per frame: 15 seconds.
- Any signature, size or binding failure closes the connection; errors are
  logged without secrets. The implementation currently also closes the
  connection on non-fatal admission and routing rejections, which is stricter
  than this specification; see section 13.4.

## 13. Implementation status and known gaps (v0.1.0)

The following deviations were found in a post-Phase-6 review. They are listed
here because the conventions require unwired functionality to be either
deleted or explicitly documented, and because every security claim must be
backed by a test. None of them are silent: each has an owner phase in
`docs/ROADMAP.md`.

### 13.1 Timing shaping is not wired

`EpochBatcher`, `EPOCH_MS` and `jitter_millis` are re-exported but never
called; outbound frames are written as soon as they are dequeued
(`crates/fantuan-node/src/connection.rs`). Claims in earlier revisions of
this document, of `docs/ATTACKS.md` and of `docs/ROADMAP.md` that batching
and jitter were shipped have been corrected. Scheduled: Phase 8.

### 13.2 Size shaping has two leaks

`pad()` returns `None` above `max_payload()` = 8187 bytes and
`shape_payload` then sends the payload raw, so file chunks (up to
`MAX_OBJECT_BYTES` = 64 KiB), manifests and history responses are unpadded.
The one-shot `ping`/`send` path opens its own session and does not shape at
all. Scheduled: Phase 8.

### 13.3 Relay admission and routes do not survive a restart

The relay nonce counter starts at 1 on every process start
(`crates/fantuan-node/src/state.rs`), while receivers keep `last_nonce` per
verified origin in memory. A restarted node is therefore treated as a
replayer by peers that have not restarted. Routing tables are also rebuilt
from scratch, so a restarted node answers relay attempts with "no route".

### 13.4 Rejected objects close the connection

`handle_object` returns an error and `connection.rs` breaks the session loop
for any rejected object, including non-fatal cases such as an expired or
rate-limited relay, a relay with no route, and a channel message from an
unknown sender. Section 12 of this document describes this as intended
behaviour for signature, size and binding failures; applying it to admission
and routing rejections lets a peer (or a plain restart, see 13.3) tear down a
link it does not own. Scheduled: Phase 7.

### 13.5 Round ids advance by exactly one

`RoundTracker::mark_seen` accepts only `current + 1`. A participant that is
absent from one round, or that misses a start, desynchronises permanently:
its own starts are rejected by peers that advanced, and their starts are
rejected by it. This requires every node to observe an identical participant
set in every round, which does not hold outside a full mesh. Scheduled:
Phase 7.

### 13.6 `DcRoundStart` is unsigned

Shares are signed and verified against stored certificates, but the round
start announcing initiator, participants and channel carries no signature and
the receiving side does not check that the sending connection belongs to
`initiator`. Any connected peer can inject a round and occupy a collector
slot. Scheduled: Phase 8.

### 13.7 DC-Net shares have no forward secrecy

Pairwise blocks are `HKDF(ECDH(static_a, static_b))` over long-term X25519
static keys, keyed by `round_id`. Compromise of one participant's static key
retroactively reveals that node's pairwise blocks for every past round it
participated in, which is enough to test whether it was the sender of a given
round. Scheduled: Phase 8.

### 13.8 Extracted anonymous messages have no application path

A message extracted from a round emits `NodeEvent::Anonymous` only: it is not
stored, not flooded, not served in history and not forwarded by the IRC
bridge, and the channel label it carries is chosen by the initiator and
unauthenticated. Anonymous sending is therefore usable only as a local
display line. Scheduled: Phase 8.

### 13.9 Reputation is a one-way ratchet

`ReputationTracker::reward` and `::reinstate` have no callers anywhere in the
workspace, and strikes are cumulative rather than consecutive as the module
documentation states. Three lifetime dropouts therefore evict a peer for the
rest of the process, and the reinstate path described in section 11 does not
exist. Scheduled: Phase 7.
