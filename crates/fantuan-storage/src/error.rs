//! Storage layer error type.

use thiserror::Error;

/// Errors produced by the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Shared primitive failure.
    #[error("core error: {0}")]
    Core(#[from] fantuan_core::CoreError),

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Message layer failure (wire objects).
    #[error("message error: {0}")]
    Msg(#[from] fantuan_msg::MsgError),

    /// Cache database failure.
    #[error("cache error: {0}")]
    Cache(String),

    /// The cache is full.
    #[error("chunk cache is full")]
    CacheFull,

    /// A chunk is missing from an assembly.
    #[error("missing chunk {0}")]
    MissingChunk(u32),

    /// Decryption or verification failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid input.
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, StorageError>;
