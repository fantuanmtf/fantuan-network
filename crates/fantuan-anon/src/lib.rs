//! Fantuan Network anonymous layer.
//!
//! Implements mesh DC-Net rounds over X25519 pairwise shares, with monotonic
//! round tracking, share authentication, dropout detection and reputation
//! based eviction.

pub mod driver;
pub mod error;
pub mod reputation;
pub mod round;
pub mod share;

pub use driver::{
    Extracted, MAX_CONFLICT_RETRIES, ROUND_DEADLINE_SECS, RoundAction, RoundContext, RoundDriver,
    RoundFailure,
};
pub use error::{AnonError, Result};
pub use reputation::{MAX_STRIKES, ReputationTracker};
pub use round::{RoundCollector, RoundTracker};
pub use share::{
    compute_xor_share, derive_pair_share, sign_share, verify_share, xor_all, xor_in_place,
};
