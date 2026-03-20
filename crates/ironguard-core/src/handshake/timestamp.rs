use std::time::{SystemTime, UNIX_EPOCH};

pub type TAI64N = [u8; 12];

pub const ZERO: TAI64N = [0u8; 12];

// TAI64 epoch offset: 2^62 + 10 (TAI is 10 seconds ahead of UTC at UNIX epoch).
const TAI64_EPOCH: u64 = 0x400000000000000a;

/// Returns the current time encoded as a TAI64N timestamp (big-endian, 8-byte
/// seconds + 4-byte nanoseconds).
pub fn now() -> TAI64N {
    let sysnow = SystemTime::now();
    let delta = sysnow
        .duration_since(UNIX_EPOCH)
        .expect("system time is before UNIX epoch");

    let tai64_secs = delta.as_secs() + TAI64_EPOCH;
    let tai64_nano = delta.subsec_nanos();

    let mut res = [0u8; 12];
    res[..8].copy_from_slice(&tai64_secs.to_be_bytes());
    res[8..].copy_from_slice(&tai64_nano.to_be_bytes());
    res
}

/// Returns `true` if `new` is strictly greater than `old` under lexicographic
/// (big-endian) comparison, which is correct for TAI64N.
pub fn compare(old: &TAI64N, new: &TAI64N) -> bool {
    for i in 0..12 {
        if new[i] > old[i] {
            return true;
        }
        if new[i] < old[i] {
            return false;
        }
    }
    // Equal — not strictly greater.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_monotonic() {
        let t1 = now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = now();
        assert!(compare(&t1, &t2));
        assert!(!compare(&t2, &t1));
    }

    #[test]
    fn test_zero_comparison() {
        let t = now();
        assert!(compare(&ZERO, &t));
    }

    #[test]
    fn test_equal_not_greater() {
        let t = now();
        assert!(!compare(&t, &t));
    }
}
