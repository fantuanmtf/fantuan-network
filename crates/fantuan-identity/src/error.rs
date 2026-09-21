//! Identity layer error type.

use thiserror::Error;

/// Errors produced by the identity layer.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Shared primitive failure.
    #[error("core error: {0}")]
    Core(#[from] fantuan_core::CoreError),

    /// OpenPGP operation failed.
    #[error("openpgp error: {0}")]
    OpenPgp(String),

    /// Descriptor encoding is invalid or missing fields.
    #[error("invalid descriptor: {0}")]
    Descriptor(String),

    /// A cryptographic verification failed.
    #[error("verification failed: {0}")]
    Verification(String),

    /// Trust storage failure.
    #[error("trust storage error: {0}")]
    Trust(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, IdentityError>;
