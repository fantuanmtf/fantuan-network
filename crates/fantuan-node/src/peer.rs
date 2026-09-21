//! Authenticated peer sessions.
//!
//! `handshake_*` runs the Noise handshake and the identity binding, so the
//! returned `BoundPeer` is authenticated. `serve` is the object loop used by
//! long-lived connections.

use anyhow::{Context, Result, bail};
use fantuan_identity::{
    Descriptor, Identity, create_binding, keys::cert_from_bytes, verify_binding,
};
use fantuan_msg::Object;
use fantuan_transport::{HandshakeOutcome, NoiseSession, handshake_initiator, handshake_responder};
use sequoia_openpgp::Cert;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// An authenticated peer connection.
pub struct BoundPeer {
    /// Established Noise session.
    pub session: NoiseSession,
    /// Verified peer descriptor.
    pub descriptor: Descriptor,
    /// Peer certificate (from the descriptor).
    pub cert: Cert,
}

impl BoundPeer {
    /// Peer OpenPGP fingerprint (uppercase hex).
    pub fn fingerprint(&self) -> &str {
        &self.descriptor.fingerprint
    }

    /// Peer display name.
    pub fn uid(&self) -> &str {
        &self.descriptor.uid
    }

    /// Peer certificate bytes, hex encoded (for trust storage).
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.descriptor.openpgp_cert)
    }
}

/// Handshake as the connecting side (Noise initiator).
pub async fn handshake_client<S>(
    stream: &mut S,
    identity: &Identity,
    timeout: Duration,
) -> Result<BoundPeer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outcome = tokio::time::timeout(
        timeout,
        handshake_initiator(stream, &identity.noise_secret()),
    )
    .await
    .context("handshake timed out")??;
    bind(stream, identity, outcome).await
}

/// Handshake as the accepting side (Noise responder).
pub async fn handshake_server<S>(
    stream: &mut S,
    identity: &Identity,
    timeout: Duration,
) -> Result<BoundPeer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outcome = tokio::time::timeout(
        timeout,
        handshake_responder(stream, &identity.noise_secret()),
    )
    .await
    .context("handshake timed out")??;
    bind(stream, identity, outcome).await
}

async fn bind<S>(
    stream: &mut S,
    identity: &Identity,
    outcome: HandshakeOutcome,
) -> Result<BoundPeer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = outcome.session;
    let binding = create_binding(identity, &outcome.handshake_hash)?;
    session.send(stream, &binding).await?;
    let peer_binding = session.recv(stream).await?;
    let descriptor = verify_binding(&peer_binding, &outcome.handshake_hash, &outcome.peer_static)
        .context("peer identity binding rejected")?;
    let cert = cert_from_bytes(&descriptor.openpgp_cert)?;

    Ok(BoundPeer {
        session,
        descriptor,
        cert,
    })
}

/// Run the object loop until the peer disconnects or stays idle too long.
///
/// Incoming messages are signature-verified before they are surfaced.
pub async fn serve<S>(stream: &mut S, peer: &mut BoundPeer, idle: Duration) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let bytes = tokio::time::timeout(idle, peer.session.recv(stream))
            .await
            .context("peer idle timeout")??;

        match Object::from_canonical_bytes(&bytes) {
            Ok(Object::Message(message)) => {
                message
                    .verify(&peer.cert)
                    .context("message signature rejected")?;
                let text = String::from_utf8_lossy(&message.payload);
                tracing::info!(peer = peer.descriptor.uid, "message received: {}", text);
                println!("[{}] {}", peer.descriptor.uid, text);
            }
            Ok(Object::Ping { timestamp, .. }) => {
                let pong = Object::Pong { timestamp }.to_canonical_bytes()?;
                peer.session.send(stream, &pong).await?;
            }
            Ok(Object::Pong { .. }) => {
                tracing::debug!(peer = peer.descriptor.uid, "pong received");
            }
            Err(error) => {
                bail!("protocol violation from {}: {error}", peer.descriptor.uid);
            }
        }
    }
}
