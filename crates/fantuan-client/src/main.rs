//! `fantuan` — Fantuan Network terminal client.

use anyhow::{Context, Result};
use fantuan_client::control::ControlClient;
use fantuan_core::config::NodeConfig;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let socket = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| NodeConfig::default().control_socket_path())
        .context("no control socket path")?;

    let client = ControlClient::connect(&socket).await.with_context(|| {
        format!(
            "cannot connect to the node control socket at {}; is fantuan-node running?",
            socket.display()
        )
    })?;
    fantuan_client::tui::run(client).await
}
