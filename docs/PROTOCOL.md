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
| 1 | `version` | uint | descriptor format version (currently 2) |
| 2 | `uid` | text | human-readable node name |
| 3 | `fingerprint` | text | uppercase hex OpenPGP fingerprint (`cert_id`) |
| 4 | `openpgp_cert` | bytes | public OpenPGP certificate |
| 5 | `noise_x25519_pub` | bytes(32) | Noise static public key |
| 6 | `i2p_destination` | text | base64 I2P destination |
| 7 | `capabilities` | array of text | e.g. `chat`, `bbs`, `storage` |
| 8 | `created` | uint | Unix seconds |
| 9 | `proto_id` | bytes(32) | protocol identity (see below) |

### Protocol identity (`proto_id`)

`proto_id` is the identity the protocol uses: round namespaces, rosters, ACK
fields, KDF inputs and wire objects. It is derived from the primary public key
packet body only — never from the whole certificate:

```
proto_id = BLAKE3("fantuan-proto-id-v1" ‖ canonical_primary_public_key_packet_body)[0..32]
```

`canonical_primary_public_key_packet_body` is the primary key's OpenPGP
public-key packet body (its version, creation time, algorithm and key
material) without the packet tag/length header. Consequences, all required:

- Adding a user id, adding or rotating a subkey, re-signing a self-signature
  or extending an expiration MUST NOT change `proto_id`.
- Replacing the primary key IS an identity change: it yields a different
  `proto_id`, and the old identity is not migrated automatically.
- Wire objects carry the raw 32 bytes; the hex form
  (`fantuan-identity`'s `proto_id_hex`) is for display and diagnostics only
  and MUST NOT be used as a key, a namespace or a lookup value.

`fingerprint` remains the OpenPGP-level identifier (`cert_id`), used for
certificate lookups and evidence; trust storage keeps both, and every lookup
by `proto_id` is backed by a recomputation from the stored certificate.

The descriptor bytes are signed by the OpenPGP signing subkey with a
detached, binary signature. A descriptor MUST be rejected unless:

1. it decodes canonically and all required fields are present;
2. `fingerprint` matches the fingerprint of `openpgp_cert`;
3. `proto_id` is exactly 32 bytes and equals the value recomputed from
   `openpgp_cert` — a valid signature alone is not sufficient, because it
   only proves the key signed the value, not that the value follows from the
   key material;
4. the signature verifies under a signing-capable key of that certificate.

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
  JSON): `status`, `post`, `forum`, `read`, `read_forum`, `send`, `anon`,
  `file_put`, `file_get`, `files`, `peers`, `reinstate`, `events`. The
  `events` command switches the connection to a stream of event lines
  (`channel`, `forum`, `message`, `relay`, `anonymous`, `peer_evicted`).
  `reinstate {uid}` clears a peer's DC-Net strikes and lifts an eviction.
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

### 11.1 Round identity and context (v2)

Every round instance is identified by a triple and described by a context.
Identities inside both are protocol identities (`proto_id`, section 2), never
OpenPGP fingerprints.

```
RoundIdentity = (initiator, epoch, instance)
    initiator : proto_id, 32 raw bytes
    epoch     : u64, initiator-scoped, strictly increasing, never reused
    instance  : 16 raw bytes from the OS CSPRNG; never derived from a clock,
                a counter or persisted state

RoundContext  = (version, channel, declared_set, deadline_secs, payload_len)
    version       : u8, currently 2
    channel       : text, validated by the channel rules in section 8
    declared_set  : 2..=16 proto_ids, strictly ascending by raw bytes, no
                    duplicates (a duplicate is malformed and MUST be rejected,
                    never silently merged)
    deadline_secs : 1..=30
    payload_len   : 36..=4096 bytes

CH        = u32(len, BE) ‖ UTF-8 bytes
SET       = u32(count, BE) ‖ count × 32B, ascending
CTX_BYTES = u8(version) ‖ CH ‖ SET ‖ u64(deadline_secs, BE) ‖ u32(payload_len, BE)
CTXH      = BLAKE3("fantuan-round-context-v1" ‖ CTX_BYTES)          // 32 bytes
identity  = initiator(32B) ‖ u64(epoch, BE) ‖ instance(16B)
```

Rules that follow from the layout, all required:

- Every integer is big endian; the only length prefixes are the one on `CH`.
- Two contexts with identical fields MUST produce identical `CTX_BYTES` and
  therefore identical `CTXH`; a difference in any field MUST change both.
- A context that is decoded from the wire MUST already be canonical: an
  unsorted or duplicated declared set is rejected rather than reordered, so
  two decoders can never disagree about the bytes a context hashes.
- `CTXH` is what share signatures, ACK signatures and key derivation bind
  (sections 11.3 onward), so an object from one context can never be
  transplanted into another context that shares the same `RoundIdentity`.

### 11.2 Round admission (receiver side)

A receiver processes an inbound start in this fixed order:

```
1. stateless validation      format, version, ranges, canonical declared set
2. signature verification    over RoundIdentity ‖ CTX_BYTES
3. atomic state section      per initiator namespace
4. classification, then commit
```

Classification depends only on the epoch and the initiator's stored state:
`stale` when `epoch < watermark`; at `epoch == watermark`, `replay` when the
instance and the context hash both match the accepted round and
`equivocation` otherwise; `overflow` above `EPOCH_MAX_USABLE =
u64::MAX − 2^16`. An epoch strictly between the watermark and that bound is a
*candidate* and is accepted only when the start is authenticated, the context
is valid and the declared set contains the receiver. Membership therefore
gates the accept, never the classification: a round that names neither us nor
anyone we know is still classified by its epoch, and it never moves the
watermark — an initiator must not be able to advance our namespace by inviting
strangers.

Rules:

- Only an accept writes state. A rejection of any kind MUST NOT move the
  watermark, replace the accepted instance or context hash, enter share
  collection or extraction, or produce a reputation event.
- Unauthenticated input is never classified: it is dropped before step 3, so
  no forged start can manufacture a stale, equivocation or overflow record.
- Replay is only reported at the watermark epoch: an accepted round that a
  later epoch superseded is classified `stale`, not `replay`.
- The accepted state is made durable (append + fsync) *before* the in-memory
  copy changes. A crash may therefore leave the namespace ahead of memory,
  never behind; because a retry always mints a new epoch, being ahead costs
  nothing.
- If the durable write fails, the round MUST be refused and no state may
  change (`Admission::StoreFailed`): the watermark *is* the replay defence, so
  admitting without durability would silently drop it. Repeated failures are
  an operator condition, not a peer-visible event.
- Two receivers that see two conflicting starts for one epoch in opposite
  orders accept different contexts. That divergence is specified and carries
  no safety consequence: each receiver accepted exactly one context, refuses
  every later round under that epoch, and each records the equivocation.

### 11.3 Durable round state

Three files per data directory, all mode 0600, all integers big endian, each
record ending in an 8-byte integrity field (`BLAKE3(domain ‖ body)[..8]`; the
review called this field a CRC):

```
rounds.state (58B) : "FTNRND01"(8) ‖ version(2) ‖ own_proto_id(32) ‖ created(8) ‖ checksum(8)
rounds.log   (96B) : initiator(32) ‖ epoch(8) ‖ instance(16) ‖ context_hash(32) ‖ checksum(8)
rounds.epoch (58B) : "FTNEPO01"(8) ‖ version(2) ‖ own_proto_id(32) ‖ reserved_upto(8) ‖ checksum(8)
```

- `rounds.log` is append-only: one record per accept, fsynced before the
  accept becomes visible. Compaction rewrites one record per namespace through
  a temporary file plus rename, so an interrupted compaction leaves either the
  old log or the new one.
- `rounds.epoch` reserves a block of epochs per durable write. After a restart
  the cursor resumes at `reserved_upto + 1`, abandoning the remainder of the
  previous block: a crash may skip epochs, never repeat one.
- The marker (`rounds.state`) is the **only** bootstrap anchor. Whether the
  node's identity is fresh is supplied explicitly by the caller (its `identity
  init` path knows); directory contents are never used as a criterion.

Failure matrix (HALT means the anonymous layer must not run until an operator
acts; RECOVERABLE means the node proceeds after a defined local repair):

| Condition | Initiator (reservation) | Receiver (marker + log) |
|-----------|------------------------|-------------------------|
| Fresh identity, no state files | initialize (ACCEPT) | initialize (ACCEPT) |
| State files missing on an established node | HALT | HALT |
| Corrupt marker/reservation (bad magic, version, checksum, truncation) | HALT | HALT |
| Corrupt log record (complete record, bad checksum) | — | HALT |
| Log not strictly increasing per namespace | — | HALT |
| State belongs to another identity | HALT | HALT |
| Torn tail record | — | RECOVERABLE: discard, truncate to the last complete record |
| Crash after fsync, before publishing | RECOVERABLE: the reserved block is abandoned | RECOVERABLE: the epoch counts as accepted; a repeat is a replay, and the next epoch is still free |
| Reservation cannot be persisted at runtime | RECOVERABLE: refuse that start, hand out no epoch | — |
| Commit cannot be persisted at runtime | — | `StoreFailed`: refuse the round, old state unchanged, nothing classified, no round advances |
| Epoch beyond `EPOCH_MAX_USABLE` | HALT initiation | reject (never wrap) |
| Snapshot/backup rollback | HALT initiation once peers reject `ROLLBACK_REJECTION_LIMIT` consecutive starts, or once an equivocation is reported against this identity | **UNDETECTABLE — declared limitation**: the watermark regresses, the replay window for the affected identities reopens, and no local mechanism can tell that from a first arrival. Only instance randomness still holds: a rolled-back node never reuses key material. |

A runtime persistence failure never yields a weaker state: the old state stays
in place, no classification is produced, and no counter or round advances that
depends on the failed commit. Repeated failures are an operator condition and
do not, by themselves, escalate to HALT.

The version-1 wire objects, still in force until the remaining parts of this
section are rewritten, are:

```
DcRoundStart { channel, round_id, initiator, participants[], deadline_secs, payload_len }
DcRoundShare { channel, round_id, peer_uid, xored_payload, signature }
```

Version 2 replaces `round_id` with `RoundIdentity`, replaces the
`channel`/`participants` strings with a `RoundContext`, and makes the start and
share signatures cover the layouts above.

- Underlying key: each participant derives a pairwise block from
  `ECDH(static_a, static_b)` with the node's Noise X25519 keys, expanded via
  HKDF with `"fantuan-dcnet-pair-v1" || round_id || sorted uids`. XOR-ing all
  pairwise blocks across participants cancels every block.
- Rounds are a mesh: the initiator broadcasts `DcRoundStart`, every other
  participant broadcasts one neutral share, and the initiator broadcasts its
  message-carrying share **last** once every other share arrived. Every node
  XORs all shares and extracts the checksummed message frame
  (`[u32 length][BLAKE3 checksum][message][zero pad]`).
- Round ids are the initiator's wall-clock milliseconds, quantised to 100 ms
  (`ROUND_ID_GRANULARITY_MS`) and floored by the highest id seen, so they are
  comparable between nodes and never repeat. An id at or below the current one
  is stale; an id more than `MAX_FUTURE_SKEW_MS` (30 s) ahead is refused.
  Simultaneous initiations share one id and are resolved by comparing
  initiator fingerprints (the smaller wins; the loser aborts before sending a
  message share and retries).
- Shares are signed by the sender's OpenPGP key and verified against the
  signer's stored certificate. Unknown signers are rejected.
- Limits: 2..=16 participants, payload length 36..=4096 bytes, deadline
  ≤ 30 s. Messages longer than `payload_len - 36` are refused.
- Rounds require direct connectivity between all participants (mesh); the
  scheduler only selects currently connected, non-evicted peers.
- Expired rounds with missing shares report the missing participants; three
  strikes evict a peer from future rounds. Strikes are **consecutive**: a
  completed round clears them (`ReputationTracker::reward`, driven by
  `RoundAction::completed`). An evicted peer is reinstated with the `reinstate`
  control command, or comes back when the process restarts.
- A round of our own that expires with **no** participants is not attributed
  to anyone: it usually means our start was already stale, and blaming the
  whole participant set would let one such race evict honest peers.

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
- Any signature, size or binding failure on the peer's own material closes the
  connection; errors are logged without secrets.
- Rejections of objects the peer did not author — relayed envelopes, flooded
  channel messages and chunks, unservable chunk requests — drop the object and
  keep the session (`fantuan-node::reject::Dropped`, section 13.4).

## 13. Implementation status and known gaps (v0.1.0)

The following deviations were found in a post-Phase-6 review. They are listed
here because the conventions require unwired functionality to be either
deleted or explicitly documented, and because every security claim must be
backed by a test. None of them are silent: each has an owner phase in
`docs/ROADMAP.md`.

Entries marked **Resolved in Phase 7** are kept, with the regression test that
proves the fix, so the next review does not have to rediscover them. The
remaining entries are Phase 8/9 work.

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

**Resolved in Phase 7.** Outbound relay nonces now come from
`fantuan-node::nonce::RelayNonce`, which persists a reservation block before
handing out any nonce inside it and floors the counter at the wall clock, so a
restarted node never repeats a nonce. Peers we already know are redialled at
startup (`redial_known_peers`, default on), which rebuilds routing tables from
gossip. Regression test: `relay_resilience.rs::relay_survives_a_sender_restart`.

### 13.4 Rejected objects close the connection

**Resolved in Phase 7.** Rejections are classified: an object that is not the
peer's own — a relayed envelope, a flooded channel message or chunk, an
unservable chunk request — now returns `fantuan-node::reject::Dropped` and
drops the object while the session stays up. Signature, size, encoding and
binding failures on the peer's own material remain fatal, as section 12
requires. Regression test:
`relay_resilience.rs::rejected_relays_keep_the_session_alive`.

### 13.5 Round ids advance by exactly one

**Resolved in Phase 7.** Round ids are wall-clock milliseconds of the
initiator, quantised to [`ROUND_ID_GRANULARITY_MS`], floored by the highest id
seen. A node that observed no round is therefore not behind its peers and can
initiate: its id comes from its own clock. Simultaneous initiators land on the
same id and are resolved by the existing initiator tie-break. Ids at or below
the current one are stale; ids more than `MAX_FUTURE_SKEW_MS` ahead are
refused. Regression test:
`dcnet_partial_mesh.rs::a_node_outside_the_rounds_can_still_initiate`.

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

**Resolved in Phase 7.** `reward` is driven by completed rounds, so strikes are
consecutive as documented, and `reinstate` is reachable through the `reinstate`
control command (section 9). A round of our own that nobody joined is no
longer attributed to the participants.
