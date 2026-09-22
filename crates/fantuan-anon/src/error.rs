//! Anonymous layer error type.

use thiserror::Error;

/// Errors produced by the anonymous layer.
#[derive(Debug, Error)]
pub enum AnonError {
    /// Message layer failure.
    #[error("message error: {0}")]
    Msg(#[from] fantuan_msg::MsgError),

    /// Identity layer failure.
    #[error("identity error: {0}")]
    Identity(#[from] fantuan_identity::IdentityError),

    /// A share could not be computed (missing keys or invalid input).
    #[error("share error: {0}")]
    Share(String),

    /// The round state machine rejected an action.
    #[error("round error: {0}")]
    Round(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, AnonError>;
