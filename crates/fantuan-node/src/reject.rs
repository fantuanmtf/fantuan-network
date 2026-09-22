//! Error classification for inbound objects.
//!
//! A session carries objects that the peer did not author: relayed envelopes,
//! flooded channel messages and file chunks are signed by third parties, and
//! a peer may legitimately ask for a chunk we cannot serve. Rejecting one of
//! those says nothing about the peer we received it from, so it must drop the
//! object and keep the session. Closing the session instead — the behaviour
//! before this module existed — let any peer tear down a link it did not own,
//! and made a node's own restart look like an attack.
//!
//! Session-level violations stay fatal: undecodable frames, size-limit
//! breaches, and signature or binding failures on the peer's *own* objects
//! (`docs/PROTOCOL.md` §12).

use anyhow::Error;
use std::fmt;

/// Marker for an error that drops one object and keeps the session alive.
#[derive(Debug)]
pub struct Dropped {
    reason: String,
}

impl Dropped {
    /// An object we refuse to process, with no underlying error.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Mark an existing error as non-fatal for the session.
    ///
    /// Takes anything `Display`, because call sites hold concrete error types
    /// (message, identity, storage) rather than `anyhow::Error`.
    pub fn wrap<E: fmt::Display>(error: E) -> Error {
        Error::new(Self::new(error.to_string()))
    }

    /// Fatal when the object is the peer's own, dropped when it is a third
    /// party's (a relayed envelope or a flooded object we merely carried).
    pub fn classify<E: fmt::Display>(error: E, own: bool) -> Error {
        if own {
            Error::msg(error.to_string())
        } else {
            Self::wrap(error)
        }
    }

    /// True when this error must only drop the current object.
    pub fn is(error: &Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }

    /// Human-readable reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for Dropped {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "object dropped: {}", self.reason)
    }
}

impl std::error::Error for Dropped {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn wrapped_errors_are_recognised() {
        let error = Dropped::wrap(anyhow!("no route to 42"));
        assert!(Dropped::is(&error));
        assert!(format!("{error:#}").contains("no route to 42"));
    }

    #[test]
    fn plain_errors_stay_fatal() {
        assert!(!Dropped::is(&anyhow!("decode failed")));
    }

    #[test]
    fn classify_keeps_a_peers_own_violation_fatal() {
        let own = Dropped::classify("bad signature", true);
        assert!(!Dropped::is(&own));
        assert!(format!("{own:#}").contains("bad signature"));
        let third_party = Dropped::classify("bad signature", false);
        assert!(Dropped::is(&third_party));
    }
}
