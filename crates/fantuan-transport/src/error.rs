//! Transport layer error type.

use thiserror::Error;

/// Errors produced by the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Shared primitive failure.
    #[error("core error: {0}")]
    Core(#[from] fantuan_core::CoreError),

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// I2P SAM failure.
    #[error("i2p sam error: {0}")]
    Sam(String),

    /// Noise protocol failure.
    #[error("noise error: {0}")]
    Noise(String),

    /// Session-level failure (rekey required, closed, ...).
    #[error("session error: {0}")]
    Session(String),

    /// Peer sent something that violates the protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, TransportError>;
