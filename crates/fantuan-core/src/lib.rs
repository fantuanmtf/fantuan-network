//! Shared primitives for Fantuan Network.
//!
//! This crate contains no protocol logic. It provides the error type,
//! configuration handling, secure file helpers and time utilities used by
//! every other crate.

pub mod config;
pub mod error;
pub mod fs;
pub mod time;

pub use error::{CoreError, Result};
