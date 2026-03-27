// Batch accumulator for amortizing channel and syscall overhead.
//
// Collects `PacketRef` values and flushes them as a batch when a count,
// size, or timeout threshold is reached.

use std::time::{Duration, Instant};

use super::pool::PacketRef;

/// Default maximum number of packets per batch.
pub const DEFAULT_BATCH_MAX_COUNT: usize = 64;

/// Default maximum total bytes per batch.
pub const DEFAULT_BATCH_MAX_BYTES: usize = 65536;

/// Default flush timeout in microseconds.
///
/// 50us keeps the write workers responsive enough to drain the TUN/UDP
/// channels at line rate. Higher values (e.g., 250us) improve batch sizes
/// for the UDP write path but starve the TUN write path, causing packet
/// drops in the download direction.
pub const DEFAULT_BATCH_FLUSH_TIMEOUT_US: u64 = 50;

/// Collects `PacketRef` values and flushes them as a batch when a count,
/// size, or timeout threshold is reached.
///
/// This amortizes per-packet channel send and syscall overhead by delivering
/// packets in groups rather than one at a time.
pub struct BatchAccumulator {
    packets: Vec<PacketRef>,
    total_bytes: usize,
    max_count: usize,
    max_bytes: usize,
    flush_timeout: Duration,
    created: Instant,
}

impl BatchAccumulator {
    /// Create a new accumulator with explicit thresholds.
    pub fn new(max_count: usize, max_bytes: usize, flush_timeout: Duration) -> Self {
        Self {
            packets: Vec::with_capacity(max_count),
            total_bytes: 0,
            max_count,
            max_bytes,
            flush_timeout,
            created: Instant::now(),
        }
    }

    /// Add a packet to the batch, updating the running byte total.
    pub fn push(&mut self, pref: PacketRef) {
        self.total_bytes += pref.len as usize;
        self.packets.push(pref);
    }

    /// Returns `true` if any flush threshold has been reached:
    /// count >= max_count, total_bytes >= max_bytes, or elapsed >= flush_timeout.
    ///
    /// An empty accumulator never needs flushing -- the timeout only applies
    /// when at least one packet is waiting.
    pub fn should_flush(&self) -> bool {
        if self.packets.is_empty() {
            return false;
        }
        self.packets.len() >= self.max_count
            || self.total_bytes >= self.max_bytes
            || self.created.elapsed() >= self.flush_timeout
    }

    /// Drain the accumulated packets and reset state for the next batch.
    ///
    /// Returns the collected packets. After this call the accumulator is empty
    /// with a fresh timestamp.
    pub fn flush(&mut self) -> Vec<PacketRef> {
        self.total_bytes = 0;
        self.created = Instant::now();
        std::mem::take(&mut self.packets)
    }

    /// Number of packets currently accumulated.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Returns `true` if no packets are accumulated.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

impl Default for BatchAccumulator {
    fn default() -> Self {
        Self::new(
            DEFAULT_BATCH_MAX_COUNT,
            DEFAULT_BATCH_MAX_BYTES,
            Duration::from_micros(DEFAULT_BATCH_FLUSH_TIMEOUT_US),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::pool::PacketRef;

    fn pref(len: u16) -> PacketRef {
        PacketRef {
            pool_idx: 0,
            offset: 0,
            len,
            peer_idx: 0,
        }
    }

    #[test]
    fn test_empty_flush_returns_empty() {
        let mut acc = BatchAccumulator::default();
        assert!(acc.flush().is_empty());
        assert!(acc.is_empty());
    }

    #[test]
    fn test_count_threshold_triggers_flush() {
        let mut acc = BatchAccumulator::new(2, 65536, Duration::from_millis(50));
        acc.push(pref(100));
        assert!(!acc.should_flush());
        acc.push(pref(100));
        assert!(acc.should_flush());
        let batch = acc.flush();
        assert_eq!(batch.len(), 2);
        assert!(acc.is_empty());
    }

    #[test]
    fn test_bytes_threshold_triggers_flush() {
        let mut acc = BatchAccumulator::new(64, 200, Duration::from_millis(50));
        acc.push(pref(150));
        assert!(!acc.should_flush());
        acc.push(pref(100));
        assert!(acc.should_flush()); // 250 >= 200
    }

    #[test]
    fn test_flush_resets_state() {
        let mut acc = BatchAccumulator::default();
        acc.push(pref(100));
        acc.push(pref(200));
        let _ = acc.flush();
        assert_eq!(acc.len(), 0);
        assert!(!acc.should_flush());
    }

    #[test]
    fn test_timeout_triggers_flush() {
        let mut acc = BatchAccumulator::new(64, 65536, Duration::from_nanos(1));
        acc.push(pref(100));
        std::thread::sleep(Duration::from_micros(10));
        assert!(acc.should_flush());
    }
}
