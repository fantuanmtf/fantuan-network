//! I2P SAM v3 session wrapper.
//!
//! Built on `yosemite`; this module is the only place that knows about SAM
//! so the dependency can be replaced without touching callers. yosemite
//! always talks to a local router, so the configured host must be loopback.

use crate::error::{Result, TransportError};
use yosemite::style::Stream as StreamStyle;
use yosemite::{DestinationKind, RouterApi, Session, SessionOptions, Stream};

/// Default SAM bridge TCP port.
pub const DEFAULT_SAM_PORT: u16 = 7656;

/// SAM session configuration.
#[derive(Debug, Clone)]
pub struct SamConfig {
    /// SAM bridge TCP port on localhost.
    pub port: u16,
    /// SAM session nickname (unique per running session).
    pub nickname: String,
    /// Publish the lease set (required to accept inbound connections).
    pub publish: bool,
}

impl Default for SamConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_SAM_PORT,
            nickname: "fantuan-node".to_string(),
            publish: true,
        }
    }
}

impl SamConfig {
    /// Parse `host:port`, rejecting non-loopback hosts.
    pub fn from_addr(addr: &str) -> Result<Self> {
        let (host, port) = addr.rsplit_once(':').ok_or_else(|| {
            TransportError::Sam(format!("invalid SAM address {addr:?}, expected host:port"))
        })?;
        let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
        if !loopback {
            return Err(TransportError::Sam(
                "the SAM bridge must be on loopback (yosemite connects to 127.0.0.1)".to_string(),
            ));
        }
        let port = port
            .parse::<u16>()
            .map_err(|e| TransportError::Sam(format!("invalid SAM port {port:?}: {e}")))?;
        Ok(Self {
            port,
            ..Self::default()
        })
    }
}

/// Generate a persistent I2P destination.
///
/// Returns `(destination, private_key)`. The private key must be stored with
/// owner-only permissions; it is the node's I2P identity.
pub async fn generate_destination(config: &SamConfig) -> Result<(String, String)> {
    RouterApi::new(config.port)
        .generate_destination()
        .await
        .map_err(|e| TransportError::Sam(e.to_string()))
}

/// Resolve an I2P name (for example `example.i2p`).
pub async fn resolve_name(config: &SamConfig, name: &str) -> Result<String> {
    RouterApi::new(config.port)
        .lookup_name(name)
        .await
        .map_err(|e| TransportError::Sam(e.to_string()))
}

/// A running SAM stream session.
pub struct SamSession {
    inner: Session<StreamStyle>,
    destination: String,
}

impl SamSession {
    /// Open a session, optionally restoring a persistent destination.
    pub async fn open(config: &SamConfig, private_key: Option<&str>) -> Result<Self> {
        let destination = match private_key {
            Some(key) => DestinationKind::Persistent {
                private_key: key.to_string(),
            },
            None => DestinationKind::Transient,
        };
        let options = SessionOptions {
            nickname: config.nickname.clone(),
            destination,
            publish: config.publish,
            samv3_tcp_port: config.port,
            ..Default::default()
        };
        let inner = Session::<StreamStyle>::new(options)
            .await
            .map_err(|e| TransportError::Sam(e.to_string()))?;
        let destination = inner.destination().to_string();
        Ok(Self { inner, destination })
    }

    /// This session's base64 destination.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Open an outbound stream to a remote destination.
    pub async fn connect(&mut self, destination: &str) -> Result<Stream> {
        self.inner
            .connect(destination)
            .await
            .map_err(|e| TransportError::Sam(e.to_string()))
    }

    /// Accept one inbound stream.
    pub async fn accept(&mut self) -> Result<Stream> {
        self.inner
            .accept()
            .await
            .map_err(|e| TransportError::Sam(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_addr_accepts_loopback() {
        let config = SamConfig::from_addr("127.0.0.1:7656").expect("parse");
        assert_eq!(config.port, 7656);
        assert!(config.publish);
        assert!(SamConfig::from_addr("localhost:1234").is_ok());
        assert!(SamConfig::from_addr("[::1]:7656").is_ok());
    }

    #[test]
    fn from_addr_rejects_remote_and_garbage() {
        assert!(SamConfig::from_addr("10.0.0.1:7656").is_err());
        assert!(SamConfig::from_addr("example.com:7656").is_err());
        assert!(SamConfig::from_addr("no-port").is_err());
        assert!(SamConfig::from_addr("127.0.0.1:not-a-port").is_err());
    }

    #[tokio::test]
    #[ignore = "requires a local i2pd router with SAM enabled"]
    async fn generate_destination_live() {
        let config = SamConfig::default();
        let (destination, private_key) = generate_destination(&config).await.expect("generate");
        assert!(!destination.is_empty());
        assert!(!private_key.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a local i2pd router with SAM enabled"]
    async fn open_session_live() {
        let config = SamConfig {
            nickname: format!("fantuan-test-{}", std::process::id()),
            ..SamConfig::default()
        };
        let session = SamSession::open(&config, None).await.expect("open");
        assert!(!session.destination().is_empty());
    }
}
