//! Fantuan Network transport layer.
//!
//! Two independent pieces:
//!
//! * `sam` — a thin wrapper over the I2P SAM v3 bridge that owns a stream
//!   session with a persistent destination.
//! * `noise` / `session` — an authenticated Noise XX session over any byte
//!   stream, including the identity binding defined in `docs/PROTOCOL.md`.
//!
//! `pool` combines both into the node-facing connection manager.
