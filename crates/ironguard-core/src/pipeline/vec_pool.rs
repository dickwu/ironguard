// Recycling pool of `Vec<u8>` buffers for hot-path allocation avoidance.
//
// Pre-allocates a fixed number of `Vec<u8>` at startup. I/O workers pop
// buffers from the pool instead of calling `vec![0; size]`, and write
// workers push them back after use. Falls back to normal heap allocation
// when the pool is exhausted or the requested size exceeds the pool's
// buffer capacity.
//
// This eliminates ~30K malloc/free cycles per second on the TUN and UDP
// I/O paths at typical throughput (173 Mbps, 1420-byte MTU).

use crossbeam_queue::ArrayQueue;

/// Default pool size: enough for the full pipeline depth
/// (TUN read + UDP read + channel buffers + crypto workers).
const DEFAULT_POOL_SIZE: usize = 1024;

/// Default per-buffer capacity in bytes. Covers MTU 1420/1500 with
/// protocol overhead (SIZE_MESSAGE_PREFIX + AEAD tag + padding).
/// Jumbo frames (MTU > ~1900) fall back to heap allocation.
const DEFAULT_BUF_CAPACITY: usize = 2048;

/// Recycling pool of `Vec<u8>` buffers.
///
/// Workers call [`alloc_zeroed`] or [`alloc_uninit`] to obtain a buffer,
/// and [`recycle`] to return it after use. The pool is lock-free (backed
/// by [`crossbeam_queue::ArrayQueue`]) so contention is minimal even with
/// multiple concurrent workers.
pub struct VecPool {
    free: ArrayQueue<Vec<u8>>,
    buf_capacity: usize,
}

impl VecPool {
    /// Create a pool of `pool_size` pre-allocated Vecs, each with
    /// `buf_capacity` bytes of backing storage.
    pub fn new(pool_size: usize, buf_capacity: usize) -> Self {
        let free = ArrayQueue::new(pool_size);
        for _ in 0..pool_size {
            let _ = free.push(vec![0u8; buf_capacity]);
        }
        Self { free, buf_capacity }
    }

    /// Allocate a zeroed Vec from the pool.
    ///
    /// Returns a pool buffer resized and zeroed to `size`, or a fresh heap
    /// allocation if the pool is empty or `size` exceeds the pool's buffer
    /// capacity.
    pub fn alloc_zeroed(&self, size: usize) -> Vec<u8> {
        if size > self.buf_capacity {
            return vec![0u8; size];
        }
        match self.free.pop() {
            Some(mut v) => {
                v.resize(size, 0);
                v
            }
            None => vec![0u8; size],
        }
    }

    /// Allocate a Vec from the pool **without** zeroing its contents.
    ///
    /// The returned buffer has `len == size` but its bytes are undefined
    /// (may contain data from a previous packet). Use only when **all**
    /// bytes will be overwritten before reading.
    ///
    /// Falls back to a fresh zeroed allocation if the pool is empty or
    /// the requested size exceeds pool capacity.
    pub fn alloc_uninit(&self, size: usize) -> Vec<u8> {
        if size > self.buf_capacity {
            return vec![0u8; size];
        }
        match self.free.pop() {
            Some(mut v) => {
                let actual = size.min(v.capacity());
                // SAFETY: The Vec was pre-allocated (zeroed) at pool creation or
                // recycled (contains valid u8 values from prior use). Setting len
                // within capacity is sound because every bit pattern is a valid u8.
                unsafe { v.set_len(actual) };
                v
            }
            None => vec![0u8; size],
        }
    }

    /// Return a Vec to the pool for reuse.
    ///
    /// The Vec's length is cleared but its backing memory is retained.
    /// Vecs with insufficient or excessive capacity are dropped rather
    /// than recycled.
    pub fn recycle(&self, mut v: Vec<u8>) {
        v.clear();
        // Only recycle Vecs whose capacity is in the expected range.
        // Reject empty Vecs (from std::mem::take, capacity 0) and
        // oversized Vecs (e.g., jumbo frames) to prevent memory bloat.
        if v.capacity() >= self.buf_capacity && v.capacity() <= self.buf_capacity * 4 {
            let _ = self.free.push(v);
        }
    }
}

impl Default for VecPool {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_SIZE, DEFAULT_BUF_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_zeroed_returns_correct_size() {
        let pool = VecPool::new(4, 128);
        let v = pool.alloc_zeroed(64);
        assert_eq!(v.len(), 64);
        assert!(v.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_uninit_returns_correct_len() {
        let pool = VecPool::new(4, 128);
        let v = pool.alloc_uninit(64);
        assert_eq!(v.len(), 64);
    }

    #[test]
    fn test_recycle_and_reuse() {
        let pool = VecPool::new(2, 128);
        let a = pool.alloc_zeroed(64);
        let _b = pool.alloc_zeroed(64);
        // Pool is now empty — both buffers in use
        pool.recycle(a);
        // Should be able to allocate again from the recycled buffer
        let c = pool.alloc_zeroed(64);
        assert_eq!(c.len(), 64);
    }

    #[test]
    fn test_oversized_request_falls_back_to_heap() {
        let pool = VecPool::new(4, 128);
        let v = pool.alloc_zeroed(256);
        assert_eq!(v.len(), 256);
    }

    #[test]
    fn test_exhausted_pool_falls_back_to_heap() {
        let pool = VecPool::new(1, 128);
        let _a = pool.alloc_zeroed(64); // takes the only buffer
        let b = pool.alloc_zeroed(64); // pool empty, falls back
        assert_eq!(b.len(), 64);
    }

    #[test]
    fn test_recycle_rejects_empty_vecs() {
        let pool = VecPool::new(2, 128);
        let _a = pool.alloc_zeroed(64);
        let _b = pool.alloc_zeroed(64);
        // Recycle an empty Vec (from std::mem::take)
        pool.recycle(Vec::new());
        // The empty Vec should NOT be returned — pool is still empty
        // Next alloc should fall back to heap (zeroed)
        let c = pool.alloc_uninit(64);
        assert_eq!(c.len(), 64);
    }

    #[test]
    fn test_recycle_rejects_oversized_vecs() {
        let pool = VecPool::new(2, 128);
        let _a = pool.alloc_zeroed(64);
        let _b = pool.alloc_zeroed(64);
        // Create an oversized Vec (>4x capacity)
        let big = vec![0u8; 128 * 5];
        pool.recycle(big);
        // Pool should still be empty
        let c = pool.alloc_zeroed(64);
        assert_eq!(c.len(), 64);
        assert!(c.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_uninit_preserves_stale_data() {
        let pool = VecPool::new(1, 128);
        let mut v = pool.alloc_zeroed(64);
        v[0] = 0xAB;
        v[63] = 0xCD;
        pool.recycle(v);

        let v2 = pool.alloc_uninit(64);
        // Stale data should be present (not zeroed)
        assert_eq!(v2[0], 0xAB);
        assert_eq!(v2[63], 0xCD);
    }
}
