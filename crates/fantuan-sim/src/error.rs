//! Simulator error type.

use thiserror::Error;

/// Errors produced by the simulator.
#[derive(Debug, Error)]
pub enum SimError {
    /// Unknown scenario name.
    #[error("unknown scenario: {0}")]
    UnknownScenario(String),

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, SimError>;
