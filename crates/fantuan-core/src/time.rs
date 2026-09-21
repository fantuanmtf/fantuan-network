//! Time helpers.
//!
//! All protocol timestamps are Unix seconds. Clock skew handling is the
//! caller's responsibility; this module only centralizes the source.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds (0 on a pre-epoch clock).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current Unix time in milliseconds (0 on a pre-epoch clock).
pub fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_after_2020() {
        // 2020-01-01T00:00:00Z
        assert!(now_unix() > 1_577_836_800);
        assert!(now_unix_millis() > 1_577_836_800_000);
    }
}
