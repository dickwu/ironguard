// Per-peer reorder buffer that ensures in-order delivery of packets processed
// in parallel by the crypto pool. Supports DropMarkers for auth failures.
//
// Packets arrive with sequence numbers that may be out of order (due to parallel
// crypto workers completing at different rates). The buffer accumulates them and
// drains contiguous runs starting from the next expected sequence number,
// skipping slots marked as dropped (e.g., authentication failures).

use std::collections::BTreeMap;

use super::pool::PacketRef;

/// Maximum number of outstanding out-of-order packets the buffer will hold.
/// Packets arriving with a sequence number >= next_seq + MAX_REORDER_WINDOW
/// are silently dropped.
pub const MAX_REORDER_WINDOW: usize = 256;

/// Per-peer reorder buffer.
///
/// `window` maps sequence numbers to `Option<PacketRef>`:
/// - `Some(pref)` -- a packet awaiting delivery
/// - `None` -- a DropMarker (auth failure; slot will be skipped during drain)
pub struct ReorderBuffer {
    next_seq: u64,
    // Visible to tests for assertions (e.g., verifying overflow drops).
    #[cfg(not(test))]
    window: BTreeMap<u64, Option<PacketRef>>,
    #[cfg(test)]
    pub(crate) window: BTreeMap<u64, Option<PacketRef>>,
}

impl ReorderBuffer {
    /// Create an empty reorder buffer starting at sequence number 0.
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            window: BTreeMap::new(),
        }
    }

    /// Insert a successfully processed packet at the given sequence number.
    ///
    /// Silently ignored if:
    /// - `seq` is below `next_seq` (already consumed or duplicate)
    /// - `seq` is too far ahead (`>= next_seq + MAX_REORDER_WINDOW`)
    pub fn insert(&mut self, seq: u64, pref: PacketRef) {
        if seq < self.next_seq {
            return;
        }
        if seq >= self.next_seq + MAX_REORDER_WINDOW as u64 {
            return;
        }
        self.window.entry(seq).or_insert(Some(pref));
    }

    /// Mark a sequence number as dropped (e.g., authentication failure).
    ///
    /// During `drain`, drop-marked slots are skipped (not yielded) but still
    /// allow `next_seq` to advance past them.
    ///
    /// Silently ignored if `seq` is below `next_seq` or beyond the window.
    pub fn mark_dropped(&mut self, seq: u64) {
        if seq < self.next_seq {
            return;
        }
        if seq >= self.next_seq + MAX_REORDER_WINDOW as u64 {
            return;
        }
        self.window.entry(seq).or_insert(None);
    }

    /// Drain a contiguous run of packets starting from `next_seq`.
    ///
    /// Yields each `PacketRef` whose slot contains `Some(pref)`. Slots
    /// containing `None` (DropMarkers) are removed and skipped without
    /// yielding. Advances `next_seq` past all consumed slots.
    pub fn drain(&mut self) -> impl Iterator<Item = PacketRef> + '_ {
        DrainIter { buf: self }
    }
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator returned by [`ReorderBuffer::drain`]. Yields contiguous packets
/// from `next_seq`, advancing the buffer's cursor as it goes.
struct DrainIter<'a> {
    buf: &'a mut ReorderBuffer,
}

impl Iterator for DrainIter<'_> {
    type Item = PacketRef;

    fn next(&mut self) -> Option<PacketRef> {
        loop {
            // Check if the next expected sequence is present in the window.
            let entry = self.buf.window.remove(&self.buf.next_seq)?;
            self.buf.next_seq += 1;
            match entry {
                Some(pref) => return Some(pref),
                // DropMarker -- skip this slot and continue to the next.
                None => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::pool::PacketRef;

    fn pref(idx: u16) -> PacketRef {
        PacketRef {
            pool_idx: idx,
            offset: 0,
            len: 100,
            peer_idx: 0,
        }
    }

    #[test]
    fn test_in_order_delivery() {
        let mut rb = ReorderBuffer::new();
        rb.insert(0, pref(10));
        rb.insert(1, pref(11));
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].pool_idx, 10);
        assert_eq!(drained[1].pool_idx, 11);
    }

    #[test]
    fn test_out_of_order_reorder() {
        let mut rb = ReorderBuffer::new();
        rb.insert(1, pref(11));
        assert_eq!(rb.drain().count(), 0);
        rb.insert(0, pref(10));
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].pool_idx, 10);
        assert_eq!(drained[1].pool_idx, 11);
    }

    #[test]
    fn test_drop_marker_skips_slot() {
        let mut rb = ReorderBuffer::new();
        rb.insert(1, pref(11));
        rb.mark_dropped(0);
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].pool_idx, 11);
    }

    #[test]
    fn test_duplicate_seq_ignored() {
        let mut rb = ReorderBuffer::new();
        rb.insert(0, pref(10));
        let _ = rb.drain().count(); // consumes seq 0, next_seq = 1
        rb.insert(0, pref(99)); // should be ignored (seq < next_seq)
        assert_eq!(rb.drain().count(), 0);
    }

    #[test]
    fn test_window_overflow_dropped() {
        let mut rb = ReorderBuffer::new();
        rb.insert(MAX_REORDER_WINDOW as u64 + 10, pref(1));
        assert_eq!(rb.drain().count(), 0);
        assert!(rb.window.is_empty()); // was dropped, not stored
    }

    #[test]
    fn test_gap_with_multiple_drops() {
        let mut rb = ReorderBuffer::new();
        rb.insert(3, pref(33));
        rb.mark_dropped(0);
        rb.mark_dropped(1);
        rb.mark_dropped(2);
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].pool_idx, 33);
    }
}
