//! Error types shared across Fantuan Network crates.

use thiserror::Error;

/// Errors produced by shared primitives.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration parsing or validation failure.
    #[error("configuration error: {0}")]
    Config(String),

    /// Caller supplied invalid input.
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CoreError>;
