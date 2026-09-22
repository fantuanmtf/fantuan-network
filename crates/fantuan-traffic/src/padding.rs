//! Frame padding and cover traffic.
//!
//! Wire format, applied to every frame that flows through a shaped
//! connection:
//!
//! ```text
//! [0x01][u32 original length][original bytes][random fill]  padded data
//! [0x02][random bytes]                                      cover traffic
//! <anything else>                                           raw frame
//! ```
//!
//! Padded frames are exactly one of the size buckets, so an observer cannot
//! distinguish message lengths. Raw frames are accepted for backward
//! compatibility with direct one-shot sends (CLI ping/message); they are
//! never emitted by shaped connections.

/// Marker for a padded data frame.
pub const PAD_MARKER: u8 = 0x01;
/// Marker for a cover frame.
pub const COVER_MARKER: u8 = 0x02;
/// Allowed frame sizes.
pub const BUCKETS: [usize; 6] = [256, 512, 1024, 2048, 4096, 8192];

/// Largest payload that can be padded.
pub fn max_payload() -> usize {
    BUCKETS[BUCKETS.len() - 1] - 5
}

/// Classification of a received frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A padded data frame; the payload is the original bytes.
    Data(&'a [u8]),
    /// A cover frame that must be discarded.
    Cover,
    /// A raw undigested frame (direct send path).
    Raw(&'a [u8]),
    /// Malformed shaped frame.
    Invalid,
}

/// Pad `payload` into the smallest fitting bucket.
///
/// Returns `None` when the payload is too large or the OS RNG fails; callers
/// may then send the payload raw.
pub fn pad(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let needed = 5 + payload.len();
    let bucket = BUCKETS.iter().copied().find(|size| *size >= needed)?;
    let mut frame = vec![0u8; bucket];
    frame[0] = PAD_MARKER;
    frame[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    frame[5..5 + payload.len()].copy_from_slice(payload);
    getrandom::fill(&mut frame[5 + payload.len()..]).ok()?;
    Some(frame)
}

/// True when the frame is a cover frame.
pub fn is_cover(frame: &[u8]) -> bool {
    frame.first() == Some(&COVER_MARKER)
}

/// Generate a cover frame of the given bucket size (clamped to `BUCKETS`).
pub fn cover_frame(bucket: usize) -> Vec<u8> {
    let size = BUCKETS
        .iter()
        .copied()
        .find(|candidate| *candidate >= bucket)
        .unwrap_or(BUCKETS[BUCKETS.len() - 1]);
    let mut frame = vec![0u8; size];
    frame[0] = COVER_MARKER;
    getrandom::fill(&mut frame[1..]).ok();
    frame
}

/// Parse a received frame.
pub fn parse(frame: &[u8]) -> Frame<'_> {
    match frame.first() {
        Some(&PAD_MARKER) => {
            if frame.len() < 5 {
                return Frame::Invalid;
            }
            let length = u32::from_be_bytes(match frame[1..5].try_into() {
                Ok(bytes) => bytes,
                Err(_) => return Frame::Invalid,
            }) as usize;
            if 5 + length <= frame.len() {
                Frame::Data(&frame[5..5 + length])
            } else {
                Frame::Invalid
            }
        }
        Some(&COVER_MARKER) => Frame::Cover,
        Some(_) => Frame::Raw(frame),
        None => Frame::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_parse_roundtrip() {
        for payload in [b"x".to_vec(), vec![7u8; 200], vec![9u8; 1000]] {
            let frame = pad(&payload).expect("pad");
            assert!(BUCKETS.contains(&frame.len()));
            match parse(&frame) {
                Frame::Data(decoded) => assert_eq!(decoded, payload.as_slice()),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    }

    #[test]
    fn oversized_payload_is_not_padded() {
        assert!(pad(&vec![0u8; max_payload() + 1]).is_none());
        assert!(pad(&[]).is_none());
    }

    #[test]
    fn malformed_padded_frames_are_invalid() {
        assert_eq!(parse(&[]), Frame::Invalid);
        assert_eq!(parse(&[PAD_MARKER]), Frame::Invalid);
        let mut frame = pad(b"hello").expect("pad");
        frame[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse(&frame), Frame::Invalid);
    }

    #[test]
    fn raw_and_cover_frames_are_recognized() {
        assert_eq!(parse(b"\xa1rest"), Frame::Raw(b"\xa1rest"));
        let cover = cover_frame(256);
        assert_eq!(cover.len(), 256);
        assert_eq!(parse(&cover), Frame::Cover);
        assert!(is_cover(&cover));
        assert!(!is_cover(b"\xa1"));
    }

    #[test]
    fn padding_is_randomized() {
        let first = pad(b"same payload").expect("first");
        let second = pad(b"same payload").expect("second");
        assert_eq!(first.len(), second.len());
        assert_ne!(first, second, "padding must vary between frames");
    }
}
