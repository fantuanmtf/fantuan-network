//! Fantuan Network anonymous layer.
//!
//! Implements mesh DC-Net rounds over X25519 pairwise shares, with monotonic
//! round tracking, share authentication, dropout detection and reputation
//! based eviction.

pub mod admission;
pub mod driver;
pub mod error;
pub mod reputation;
pub mod round;
pub mod share;

pub use admission::{
    Admission, AuthenticatedRound, EPOCH_MAX_USABLE, NamespaceState, NamespaceStore,
    RoundAdmission, VolatileStore,
};
pub use driver::{
    DriverContext, Extracted, MAX_CONFLICT_RETRIES, ROUND_DEADLINE_SECS, RoundAction, RoundDriver,
    RoundFailure,
};
pub use error::{AnonError, Result};
pub use reputation::{MAX_STRIKES, ReputationTracker};
pub use round::{RoundCollector, RoundTracker};
pub use share::{
    compute_xor_share, derive_pair_share, sign_share, verify_share, xor_all, xor_in_place,
};
