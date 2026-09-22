//! Fantuan Network traffic shaping.
//!
//! * `padding` — fixed-size frame buckets and cover frames;
//! * `batching` — epoch release and timing jitter (mix-lite);
//! * `limit` — token-bucket rate limiting for inbound frames.

pub mod batching;
pub mod limit;
pub mod padding;

pub use batching::{EPOCH_MS, EpochBatcher, MAX_JITTER_MS, jitter_millis};
pub use limit::RateLimiter;
pub use padding::{
    BUCKETS, COVER_MARKER, Frame, PAD_MARKER, cover_frame, is_cover, max_payload, pad, parse,
};
