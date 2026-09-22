//! `fantuan-node` library: identity management, peer sessions, runtime.
//!
//! The binary is a thin CLI wrapper around these modules so integration
//! tests can drive the same code paths.

pub mod admission;
pub mod anon;
pub mod connection;
pub mod control;
pub mod files;
pub mod gossip;
pub mod identity_cmd;
pub mod irc;
pub mod nonce;
pub mod peer;
pub mod reject;
pub mod relay;
pub mod run;
pub mod send;
pub mod social;
pub mod state;
pub mod store;

use anyhow::Result;
use fantuan_core::config::NodeConfig;
use std::path::{Path, PathBuf};

/// Load configuration: explicit path, or `<data_dir>/config.toml`.
pub fn load_config(explicit: Option<&Path>) -> Result<NodeConfig> {
    match explicit {
        Some(path) => Ok(NodeConfig::load(path)?),
        None => Ok(NodeConfig::load_or_default(&default_config_path())),
    }
}

/// Default configuration path (`~/.fantuan/config.toml`).
pub fn default_config_path() -> PathBuf {
    NodeConfig::default().data_dir.join("config.toml")
}
