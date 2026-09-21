//! Node configuration.
//!
//! The configuration file is TOML and lives outside the data directory by
//! convention (`~/.fantuan/config.toml`). All fields have defaults so a
//! missing file produces a working node.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default SAM bridge address of a local i2pd router.
pub const DEFAULT_SAM_ADDR: &str = "127.0.0.1:7656";

/// Default maximum frame size in bytes (64 KiB).
pub const DEFAULT_MAX_FRAME_BYTES: usize = 65536;

/// Node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// Data directory holding identity, trust database and runtime state.
    pub data_dir: PathBuf,
    /// I2P SAM bridge address.
    pub sam_addr: String,
    /// Human-readable node name used when generating a descriptor.
    pub display_name: String,
    /// Maximum accepted frame size.
    pub max_frame_bytes: usize,
    /// Handshake timeout in seconds.
    pub handshake_timeout_secs: u64,
    /// Idle connection timeout in seconds.
    pub idle_timeout_secs: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            sam_addr: DEFAULT_SAM_ADDR.to_string(),
            display_name: "fantuan-node".to_string(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            handshake_timeout_secs: 10,
            idle_timeout_secs: 120,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = crate::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| CoreError::Config(e.to_string()))
    }

    /// Load configuration if present, otherwise return defaults.
    pub fn load_or_default(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }

    /// Persist configuration to a file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).map_err(|e| CoreError::Config(e.to_string()))?;
        crate::fs::write_private_file(path, text.as_bytes())
    }

    /// Directory that holds identity material.
    pub fn identity_dir(&self) -> PathBuf {
        self.data_dir.join("identity")
    }

    /// Path of the trust database.
    pub fn trust_db_path(&self) -> PathBuf {
        self.data_dir.join("trust.sqlite")
    }
}

/// Default data directory: `$HOME/.fantuan`.
fn default_data_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".fantuan"),
        None => PathBuf::from(".fantuan"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_usable() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.sam_addr, DEFAULT_SAM_ADDR);
        assert_eq!(cfg.max_frame_bytes, DEFAULT_MAX_FRAME_BYTES);
        assert!(cfg.identity_dir().ends_with("identity"));
    }

    #[test]
    fn roundtrip_through_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let cfg = NodeConfig {
            display_name: "alice".to_string(),
            ..NodeConfig::default()
        };
        cfg.save(&path).expect("save");
        let loaded = NodeConfig::load(&path).expect("load");
        assert_eq!(loaded.display_name, "alice");
        assert_eq!(loaded.sam_addr, cfg.sam_addr);
    }

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let cfg = NodeConfig::load_or_default(Path::new("/nonexistent/fantuan.toml"));
        assert_eq!(cfg.sam_addr, DEFAULT_SAM_ADDR);
    }
}
