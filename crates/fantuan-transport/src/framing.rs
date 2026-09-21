//! Length-prefixed framing shared by the handshake and transport phases.
//!
//! Frame: `u32be length || payload`. Zero-length frames are rejected, and a
//! hard cap bounds allocations caused by hostile input.

use crate::error::{Result, TransportError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted frame size (64 KiB), matching the protocol document.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Write one length-prefixed frame and flush it.
pub async fn write_frame<S>(stream: &mut S, payload: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Err(TransportError::Protocol(
            "refusing to write an empty frame".to_string(),
        ));
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(TransportError::Protocol(format!(
            "frame exceeds {MAX_FRAME_BYTES} bytes"
        )));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame.
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TransportError::Protocol(format!(
            "invalid frame length {length}"
        )));
    }
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer).await?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_frame(&mut a, b"hello").await.expect("write");
        assert_eq!(read_frame(&mut b).await.expect("read"), b"hello");
    }

    #[tokio::test]
    async fn empty_frame_is_rejected() {
        let (mut a, _b) = tokio::io::duplex(64);
        assert!(write_frame(&mut a, b"").await.is_err());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, _b) = tokio::io::duplex(1);
        let payload = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(write_frame(&mut a, &payload).await.is_err());
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let length = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&length).await.expect("write length");
        });
        assert!(read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&5u32.to_be_bytes()).await.expect("write");
            a.write_all(b"ab").await.expect("write");
            a.shutdown().await.expect("shutdown");
        });
        assert!(read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn zero_length_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.expect("write");
        assert!(read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn multiple_frames_in_sequence() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_frame(&mut a, b"one").await.expect("write");
        write_frame(&mut a, b"two").await.expect("write");
        assert_eq!(read_frame(&mut b).await.expect("read"), b"one");
        assert_eq!(read_frame(&mut b).await.expect("read"), b"two");
        // Closing the writer end must surface as EOF, not a hang.
        drop(a);
        let mut eof = [0u8; 1];
        assert_eq!(b.read(&mut eof).await.unwrap_or(0), 0);
    }
}
