//! Fantuan Network transport layer.
//!
//! Two independent pieces:
//!
//! * `sam` — a thin wrapper over the I2P SAM v3 bridge that owns a stream
//!   session with a persistent destination.
//! * `noise` / `framing` — an authenticated Noise XX session over any byte
//!   stream, including the identity binding defined in `docs/PROTOCOL.md`.
//!
//! `pool` combines both into the node-facing connection registry.

pub mod error;
pub mod framing;
pub mod noise;
pub mod pool;
pub mod sam;

pub use error::{Result, TransportError};
pub use framing::{MAX_FRAME_BYTES, read_frame, write_frame};
pub use noise::{
    DEFAULT_MAX_FRAMES, HandshakeOutcome, MAX_NOISE_PAYLOAD, NOISE_PATTERN, NoiseSession,
    handshake_initiator, handshake_responder,
};
pub use pool::{
    ConnectionHandle, ConnectionPool, DEFAULT_MAX_CONNECTIONS, DEFAULT_WRITER_QUEUE,
    next_connection_id,
};
pub use sam::{DEFAULT_SAM_PORT, SamConfig, SamSession, generate_destination, resolve_name};
