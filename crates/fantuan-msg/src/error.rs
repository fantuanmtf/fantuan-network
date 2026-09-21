//! Message layer error type.

use thiserror::Error;

/// Errors produced by the message layer.
#[derive(Debug, Error)]
pub enum MsgError {
    /// Shared primitive failure.
    #[error("core error: {0}")]
    Core(#[from] fantuan_core::CoreError),

    /// Identity layer failure.
    #[error("identity error: {0}")]
    Identity(#[from] fantuan_identity::IdentityError),

    /// Encoding or decoding failure.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Cryptographic verification failure.
    #[error("verification failed: {0}")]
    Verification(String),

    /// A size limit was exceeded.
    #[error("size limit exceeded: {0}")]
    TooLarge(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, MsgError>;
