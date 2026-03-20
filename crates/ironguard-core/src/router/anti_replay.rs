// Implementation of RFC 6479.
// https://tools.ietf.org/html/rfc6479

use core::mem;

// Use u64 words for the bitmap (64-bit target).
type Word = u64;
const REDUNDANT_BIT_SHIFTS: usize = 6;

const SIZE_OF_WORD: usize = mem::size_of::<Word>() * 8;

const BITMAP_BITLEN: usize = 2048;
const BITMAP_LEN: usize = BITMAP_BITLEN / SIZE_OF_WORD;
const BITMAP_INDEX_MASK: u64 = BITMAP_LEN as u64 - 1;
const BITMAP_LOC_MASK: u64 = (SIZE_OF_WORD - 1) as u64;
const WINDOW_SIZE: u64 = (BITMAP_BITLEN - SIZE_OF_WORD) as u64;

pub struct AntiReplay {
    bitmap: [Word; BITMAP_LEN],
    last: u64,
}

impl Default for AntiReplay {
    fn default() -> Self {
        AntiReplay::new()
    }
}

impl AntiReplay {
    pub fn new() -> Self {
        debug_assert_eq!(1 << REDUNDANT_BIT_SHIFTS, SIZE_OF_WORD);
        debug_assert_eq!(BITMAP_BITLEN % SIZE_OF_WORD, 0);
        AntiReplay {
            last: 0,
            bitmap: [0; BITMAP_LEN],
        }
    }

    // Returns true if check is passed, i.e., not a replay or too old.
    //
    // Unlike RFC 6479, zero is allowed.
    fn check(&self, seq: u64) -> bool {
        // Larger is always good.
        if seq > self.last {
            return true;
        }

        if self.last - seq > WINDOW_SIZE {
            return false;
        }

        let bit_location = seq & BITMAP_LOC_MASK;
        let index = (seq >> REDUNDANT_BIT_SHIFTS) & BITMAP_INDEX_MASK;

        self.bitmap[index as usize] & (1 << bit_location) == 0
    }

    // Should only be called if check returns true.
    fn update_store(&mut self, seq: u64) {
        debug_assert!(self.check(seq));

        let index = seq >> REDUNDANT_BIT_SHIFTS;

        if seq > self.last {
            let index_cur = self.last >> REDUNDANT_BIT_SHIFTS;
            let diff = index - index_cur;

            if diff >= BITMAP_LEN as u64 {
                self.bitmap = [0; BITMAP_LEN];
            } else {
                for i in 0..diff {
                    let real_index = (index_cur + i + 1) & BITMAP_INDEX_MASK;
                    self.bitmap[real_index as usize] = 0;
                }
            }

            self.last = seq;
        }

        let index = index & BITMAP_INDEX_MASK;
        let bit_location = seq & BITMAP_LOC_MASK;
        self.bitmap[index as usize] |= 1 << bit_location;
    }

    /// Checks and marks a sequence number in the replay filter.
    ///
    /// Returns `true` if the sequence number is valid (not a replay and within
    /// the sliding window). Returns `false` if it is a replay or too old.
    pub fn update(&mut self, seq: u64) -> bool {
        if self.check(seq) {
            self.update_store(seq);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential() {
        let mut ar = AntiReplay::new();
        for i in 0..2048 {
            assert!(ar.update(i), "seq {i} should be accepted");
        }
    }

    #[test]
    fn test_replay_rejected() {
        let mut ar = AntiReplay::new();
        assert!(ar.update(0));
        assert!(!ar.update(0), "replay should be rejected");
    }

    #[test]
    fn test_window_boundary() {
        let mut ar = AntiReplay::new();
        assert!(ar.update(2000));
        assert!(ar.update(17), "within window should be accepted");
        assert!(!ar.update(15), "outside window should be rejected");
    }

    #[test]
    fn test_large_jump() {
        let mut ar = AntiReplay::new();
        assert!(ar.update(0));
        assert!(ar.update(100_000));
        assert!(!ar.update(0), "very old seq rejected after big jump");
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut ar = AntiReplay::new();
        assert!(ar.update(10));
        assert!(ar.update(5));
        assert!(ar.update(8));
        assert!(!ar.update(5), "replay within window rejected");
    }
}
