//! Authenticated Noise XX sessions over a byte stream.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Both sides prove possession
//! of their X25519 static key; the OpenPGP identity binding that maps the
//! static key to a fingerprint happens one layer up (see
//! `fantuan-identity`'s binding module and `docs/PROTOCOL.md`).

use crate::error::{Result, TransportError};
use crate::framing::{MAX_FRAME_BYTES, read_frame, write_frame};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncWrite};

/// Noise protocol pattern used by all sessions.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext payload per Noise transport message.
///
/// Noise limits a transport message to 65535 bytes including the 16-byte
/// AEAD tag.
pub const MAX_NOISE_PAYLOAD: usize = 65535 - 16;

/// Default frame budget before a session must rekey.
pub const DEFAULT_MAX_FRAMES: u64 = 1 << 20;

/// An established Noise transport session.
pub struct NoiseSession {
    state: TransportState,
    frames_sent: u64,
    frames_received: u64,
    max_frames: u64,
}

impl NoiseSession {
    fn new(state: TransportState, max_frames: u64) -> Self {
        Self {
            state,
            frames_sent: 0,
            frames_received: 0,
            max_frames,
        }
    }

    /// Number of frames sent so far.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Number of frames received so far.
    pub fn frames_received(&self) -> u64 {
        self.frames_received
    }

    /// True when the session should rekey before sending more frames.
    pub fn rekey_required(&self) -> bool {
        self.frames_sent >= self.max_frames || self.frames_received >= self.max_frames
    }

    /// Encrypt and send one payload.
    pub async fn send<S>(&mut self, stream: &mut S, payload: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        if payload.len() > MAX_NOISE_PAYLOAD {
            return Err(TransportError::Protocol(format!(
                "payload exceeds {MAX_NOISE_PAYLOAD} bytes"
            )));
        }
        if self.rekey_required() {
            return Err(TransportError::Session("rekey required".to_string()));
        }
        let mut ciphertext = vec![0u8; payload.len() + 16];
        let written = self
            .state
            .write_message(payload, &mut ciphertext)
            .map_err(noise_err)?;
        write_frame(stream, &ciphertext[..written]).await?;
        self.frames_sent += 1;
        Ok(())
    }

    /// Receive and decrypt one payload.
    pub async fn recv<S>(&mut self, stream: &mut S) -> Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        if self.rekey_required() {
            return Err(TransportError::Session("rekey required".to_string()));
        }
        let ciphertext = read_frame(stream).await?;
        let mut plaintext = vec![0u8; ciphertext.len()];
        let read = self
            .state
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| TransportError::Protocol(format!("decryption failed: {e}")))?;
        plaintext.truncate(read);
        self.frames_received += 1;
        Ok(plaintext)
    }
}

/// Result of a completed handshake.
pub struct HandshakeOutcome {
    /// Established transport session.
    pub session: NoiseSession,
    /// Handshake hash, identical on both sides; used by the identity binding.
    pub handshake_hash: [u8; 32],
    /// Peer X25519 static public key.
    pub peer_static: [u8; 32],
}

/// Run the initiator side of the handshake (sends the first message).
pub async fn handshake_initiator<S>(
    stream: &mut S,
    local_secret: &[u8; 32],
) -> Result<HandshakeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = start_initiator(local_secret)?;

    // -> e
    let mut buffer = vec![0u8; MAX_FRAME_BYTES];
    let written = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_err)?;
    write_frame(stream, &buffer[..written]).await?;

    // <- e, ee, s, es
    let message = read_frame(stream).await?;
    let mut payload = vec![0u8; MAX_FRAME_BYTES];
    handshake
        .read_message(&message, &mut payload)
        .map_err(noise_err)?;
    let peer_static = take_peer_static(&handshake)?;

    // -> s, se
    let written = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_err)?;
    write_frame(stream, &buffer[..written]).await?;

    finish(handshake, peer_static)
}

/// Run the responder side of the handshake (receives the first message).
pub async fn handshake_responder<S>(
    stream: &mut S,
    local_secret: &[u8; 32],
) -> Result<HandshakeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = start_responder(local_secret)?;

    // <- e
    let message = read_frame(stream).await?;
    let mut payload = vec![0u8; MAX_FRAME_BYTES];
    handshake
        .read_message(&message, &mut payload)
        .map_err(noise_err)?;

    // -> e, ee, s, es
    let mut buffer = vec![0u8; MAX_FRAME_BYTES];
    let written = handshake
        .write_message(&[], &mut buffer)
        .map_err(noise_err)?;
    write_frame(stream, &buffer[..written]).await?;

    // <- s, se
    let message = read_frame(stream).await?;
    handshake
        .read_message(&message, &mut payload)
        .map_err(noise_err)?;
    let peer_static = take_peer_static(&handshake)?;

    finish(handshake, peer_static)
}

fn builder() -> Result<Builder<'static>> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|e| TransportError::Noise(format!("invalid pattern: {e}")))?;
    Ok(Builder::new(params))
}

fn start_initiator(local_secret: &[u8; 32]) -> Result<HandshakeState> {
    builder()?
        .local_private_key(local_secret)
        .map_err(noise_err)?
        .build_initiator()
        .map_err(noise_err)
}

fn start_responder(local_secret: &[u8; 32]) -> Result<HandshakeState> {
    builder()?
        .local_private_key(local_secret)
        .map_err(noise_err)?
        .build_responder()
        .map_err(noise_err)
}

fn take_peer_static(handshake: &HandshakeState) -> Result<[u8; 32]> {
    let static_key = handshake.get_remote_static().ok_or_else(|| {
        TransportError::Protocol("handshake completed without a peer static key".to_string())
    })?;
    static_key
        .try_into()
        .map_err(|_| TransportError::Protocol("peer static key is not 32 bytes".to_string()))
}

fn finish(handshake: HandshakeState, peer_static: [u8; 32]) -> Result<HandshakeOutcome> {
    if !handshake.is_handshake_finished() {
        return Err(TransportError::Protocol(
            "handshake messages did not complete the pattern".to_string(),
        ));
    }
    let hash = handshake.get_handshake_hash();
    let handshake_hash: [u8; 32] = hash
        .try_into()
        .map_err(|_| TransportError::Protocol("unexpected handshake hash size".to_string()))?;
    let state = handshake.into_transport_mode().map_err(noise_err)?;
    Ok(HandshakeOutcome {
        session: NoiseSession::new(state, DEFAULT_MAX_FRAMES),
        handshake_hash,
        peer_static,
    })
}

fn noise_err(e: snow::Error) -> TransportError {
    TransportError::Noise(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let keypair = builder().unwrap().generate_keypair().unwrap();
        (
            keypair.private.as_slice().try_into().unwrap(),
            keypair.public.as_slice().try_into().unwrap(),
        )
    }

    async fn handshake_pair() -> (
        HandshakeOutcome,
        HandshakeOutcome,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (mut client, mut server) = tokio::io::duplex(MAX_FRAME_BYTES * 2);
        let (client_secret, client_public) = keypair();
        let (server_secret, server_public) = keypair();

        let (client_outcome, server_outcome) = tokio::join!(
            handshake_initiator(&mut client, &client_secret),
            handshake_responder(&mut server, &server_secret),
        );
        let client_outcome = client_outcome.expect("initiator");
        let server_outcome = server_outcome.expect("responder");

        assert_eq!(client_outcome.peer_static, server_public);
        assert_eq!(server_outcome.peer_static, client_public);
        assert_eq!(client_outcome.handshake_hash, server_outcome.handshake_hash);

        (client_outcome, server_outcome, client, server)
    }

    #[tokio::test]
    async fn handshake_binds_both_static_keys() {
        let (client, server, _c, _s) = handshake_pair().await;
        assert_ne!(client.peer_static, server.peer_static);
    }

    #[tokio::test]
    async fn session_roundtrip_both_directions() {
        let (mut client, mut server, mut cstream, mut sstream) = handshake_pair().await;

        let send_a = async {
            client
                .session
                .send(&mut cstream, b"ping from client")
                .await
                .expect("send");
        };
        let recv_b = async { server.session.recv(&mut sstream).await.expect("recv") };
        let (_, received) = tokio::join!(send_a, recv_b);
        assert_eq!(received, b"ping from client");

        let send_b = async {
            server
                .session
                .send(&mut sstream, b"pong from server")
                .await
                .expect("send");
        };
        let recv_a = async { client.session.recv(&mut cstream).await.expect("recv") };
        let (_, received) = tokio::join!(send_b, recv_a);
        assert_eq!(received, b"pong from server");
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let (mut client, mut server, _cstream, _sstream) = handshake_pair().await;

        let mut captured: Vec<u8> = Vec::new();
        client
            .session
            .send(&mut captured, b"secret")
            .await
            .expect("send");
        captured[7] ^= 0xff;

        let mut reader: &[u8] = &captured;
        assert!(server.session.recv(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn replayed_frame_is_rejected() {
        let (mut client, mut server, _cstream, _sstream) = handshake_pair().await;

        let mut captured: Vec<u8> = Vec::new();
        client
            .session
            .send(&mut captured, b"once")
            .await
            .expect("send");

        let mut reader: &[u8] = &captured;
        let first = server.session.recv(&mut reader).await.expect("first");
        assert_eq!(first, b"once");

        let mut replay: &[u8] = &captured;
        assert!(
            server.session.recv(&mut replay).await.is_err(),
            "a replayed transport frame must not decrypt twice"
        );
    }

    #[tokio::test]
    async fn garbage_frame_is_rejected() {
        let (_client, mut server, mut cstream, mut sstream) = handshake_pair().await;
        cstream.write_all(&64u32.to_be_bytes()).await.unwrap();
        cstream.write_all(&[0xab; 64]).await.unwrap();
        assert!(server.session.recv(&mut sstream).await.is_err());
    }

    #[tokio::test]
    async fn oversized_payload_is_rejected() {
        let (mut client, _server, mut cstream, _sstream) = handshake_pair().await;
        let payload = vec![0u8; MAX_NOISE_PAYLOAD + 1];
        assert!(client.session.send(&mut cstream, &payload).await.is_err());
    }

    #[tokio::test]
    async fn rekey_budget_is_enforced() {
        let (client, _server, mut cstream, _sstream) = handshake_pair().await;
        let mut session = client.session;
        session.max_frames = 2;
        session.send(&mut cstream, b"one").await.expect("one");
        session.send(&mut cstream, b"two").await.expect("two");
        assert!(session.rekey_required());
        assert!(session.send(&mut cstream, b"three").await.is_err());
    }
}
