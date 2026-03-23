// Two-tier pre-allocated buffer pool for zero-allocation packet processing.
//
// Small pool: high-throughput path for typical MTU-sized packets (<=2048 bytes).
// Large pool: overflow path for jumbo frames or reassembly (<=65536 bytes).
//
// Free lists are backed by `crossbeam_queue::ArrayQueue` (lock-free, bounded FIFO).
// `PacketGuard` provides RAII semantics: dropping a guard returns its buffer index
// to the appropriate free list automatically.

use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

/// Number of small buffers pre-allocated.
pub const SMALL_POOL_SIZE: usize = 8192;

/// Byte capacity of each small buffer.
pub const SMALL_BUF_SIZE: usize = 2048;

/// Number of large buffers pre-allocated.
pub const LARGE_POOL_SIZE: usize = 128;

/// Byte capacity of each large buffer.
pub const LARGE_BUF_SIZE: usize = 65536;

/// Compact 8-byte reference to a buffer in the pool.
///
/// Designed to fit in a single register for cheap copies.
/// - `pool_idx`: index into the pool's backing storage (small: 0..SMALL_POOL_SIZE, large: SMALL_POOL_SIZE..)
/// - `offset`: byte offset within the buffer where valid data starts
/// - `len`: number of valid bytes starting at `offset`
/// - `peer_idx`: index of the peer this packet is associated with
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PacketRef {
    pub pool_idx: u16,
    pub offset: u16,
    pub len: u16,
    pub peer_idx: u16,
}

/// RAII guard for a buffer slot. Dropping the guard returns the index to the
/// pool's free list, making the slot available for reuse.
///
/// Implements `AsRef<[u8]>` and `AsMut<[u8]>` for reading and writing buffer
/// contents.
pub struct PacketGuard<'a> {
    pool: &'a BufferPool,
    idx: u16,
    buf: &'a mut [u8],
}

impl<'a> PacketGuard<'a> {
    /// The pool index of the buffer this guard holds.
    pub fn pool_idx(&self) -> u16 {
        self.idx
    }
}

impl AsRef<[u8]> for PacketGuard<'_> {
    fn as_ref(&self) -> &[u8] {
        self.buf
    }
}

impl AsMut<[u8]> for PacketGuard<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buf
    }
}

impl Drop for PacketGuard<'_> {
    fn drop(&mut self) {
        let idx = self.idx as usize;
        if idx < SMALL_POOL_SIZE {
            // Return to the small free list. push() only fails if the queue is
            // full, which cannot happen because each index is allocated at most
            // once (guarded by the RAII lifecycle).
            let _ = self.pool.small_free.push(self.idx);
        } else {
            let _ = self.pool.large_free.push(self.idx);
        }
    }
}

/// Two-tier pre-allocated buffer pool.
///
/// Buffers are allocated once at construction and never moved. The free lists
/// track which slots are available. `alloc_small` / `alloc_large` pop from the
/// appropriate free list; dropping a `PacketGuard` pushes the index back.
///
/// # Layout
///
/// Indices `0..SMALL_POOL_SIZE` address small buffers (each `SMALL_BUF_SIZE` bytes).
/// Indices `SMALL_POOL_SIZE..SMALL_POOL_SIZE+LARGE_POOL_SIZE` address large buffers
/// (each `LARGE_BUF_SIZE` bytes).
pub struct BufferPool {
    /// Backing storage for small buffers, flattened into one contiguous allocation.
    small_storage: Box<[u8]>,
    /// Backing storage for large buffers, flattened into one contiguous allocation.
    large_storage: Box<[u8]>,
    /// Lock-free FIFO free list for small buffer indices (0..SMALL_POOL_SIZE).
    small_free: Arc<ArrayQueue<u16>>,
    /// Lock-free FIFO free list for large buffer indices (SMALL_POOL_SIZE..).
    large_free: Arc<ArrayQueue<u16>>,
}

// SAFETY: All mutable access to buffer slices is mediated through `PacketGuard`,
// which holds a unique `&mut [u8]` reference for exactly one slot at a time.
// The free lists (`ArrayQueue`) are themselves `Send + Sync`. No two guards can
// alias the same slot because each index is popped from the free list on alloc
// and pushed back on drop — the RAII lifecycle guarantees exclusivity.
unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}

impl BufferPool {
    /// Create a new two-tier buffer pool with all slots initially free.
    pub fn new() -> Self {
        let small_storage = vec![0u8; SMALL_POOL_SIZE * SMALL_BUF_SIZE].into_boxed_slice();
        let large_storage = vec![0u8; LARGE_POOL_SIZE * LARGE_BUF_SIZE].into_boxed_slice();

        let small_free = Arc::new(ArrayQueue::new(SMALL_POOL_SIZE));
        for i in 0..SMALL_POOL_SIZE {
            let _ = small_free.push(i as u16);
        }

        let large_free = Arc::new(ArrayQueue::new(LARGE_POOL_SIZE));
        for i in 0..LARGE_POOL_SIZE {
            let _ = large_free.push((SMALL_POOL_SIZE + i) as u16);
        }

        Self {
            small_storage,
            large_storage,
            small_free,
            large_free,
        }
    }

    /// Allocate a small buffer (up to `SMALL_BUF_SIZE` bytes).
    ///
    /// Returns `None` if all small slots are currently in use.
    pub fn alloc_small(&self) -> Option<PacketGuard<'_>> {
        let idx = self.small_free.pop()?;
        let start = idx as usize * SMALL_BUF_SIZE;
        let end = start + SMALL_BUF_SIZE;
        // SAFETY: `idx` was popped from the free list, so no other `PacketGuard`
        // holds a reference to this range. We cast away the shared reference's
        // immutability to produce a unique `&mut [u8]`. Exclusivity is enforced
        // by the free list: the index cannot be allocated again until the guard
        // is dropped and the index is pushed back.
        let buf = unsafe {
            let ptr = self.small_storage.as_ptr().add(start) as *mut u8;
            std::slice::from_raw_parts_mut(ptr, end - start)
        };
        Some(PacketGuard {
            pool: self,
            idx,
            buf,
        })
    }

    /// Allocate a large buffer (up to `LARGE_BUF_SIZE` bytes).
    ///
    /// Returns `None` if all large slots are currently in use.
    pub fn alloc_large(&self) -> Option<PacketGuard<'_>> {
        let idx = self.large_free.pop()?;
        let local_idx = idx as usize - SMALL_POOL_SIZE;
        let start = local_idx * LARGE_BUF_SIZE;
        let end = start + LARGE_BUF_SIZE;
        // SAFETY: same reasoning as `alloc_small` — the free list guarantees
        // exclusive access to this buffer range.
        let buf = unsafe {
            let ptr = self.large_storage.as_ptr().add(start) as *mut u8;
            std::slice::from_raw_parts_mut(ptr, end - start)
        };
        Some(PacketGuard {
            pool: self,
            idx,
            buf,
        })
    }

    /// Look up a buffer by its pool index (read-only).
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of range.
    pub fn get(&self, idx: u16) -> &[u8] {
        let idx = idx as usize;
        if idx < SMALL_POOL_SIZE {
            let start = idx * SMALL_BUF_SIZE;
            &self.small_storage[start..start + SMALL_BUF_SIZE]
        } else {
            let local = idx - SMALL_POOL_SIZE;
            assert!(local < LARGE_POOL_SIZE, "pool index out of range");
            let start = local * LARGE_BUF_SIZE;
            &self.large_storage[start..start + LARGE_BUF_SIZE]
        }
    }

    /// Look up a buffer by its pool index (mutable).
    ///
    /// # Safety
    ///
    /// The caller must ensure no other reference (mutable or immutable) to this
    /// buffer slot exists. In practice, prefer using `PacketGuard` for safe
    /// mutable access -- this method is intended for advanced use cases where the
    /// caller manages exclusivity externally (e.g., via `PacketRef` ownership).
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of range.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self, idx: u16) -> &mut [u8] {
        let idx_usize = idx as usize;
        if idx_usize < SMALL_POOL_SIZE {
            let start = idx_usize * SMALL_BUF_SIZE;
            // SAFETY: caller guarantees exclusive access.
            unsafe {
                let ptr = self.small_storage.as_ptr().add(start) as *mut u8;
                std::slice::from_raw_parts_mut(ptr, SMALL_BUF_SIZE)
            }
        } else {
            let local = idx_usize - SMALL_POOL_SIZE;
            assert!(local < LARGE_POOL_SIZE, "pool index out of range");
            let start = local * LARGE_BUF_SIZE;
            // SAFETY: caller guarantees exclusive access.
            unsafe {
                let ptr = self.large_storage.as_ptr().add(start) as *mut u8;
                std::slice::from_raw_parts_mut(ptr, LARGE_BUF_SIZE)
            }
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_returns_valid_index() {
        let pool = BufferPool::new();
        let guard = pool
            .alloc_small()
            .expect("alloc_small should succeed on a fresh pool");
        assert!(
            (guard.pool_idx() as usize) < SMALL_POOL_SIZE,
            "pool_idx should be within small pool range"
        );
    }

    #[test]
    fn test_alloc_free_cycle() {
        let pool = BufferPool::new();

        // Allocate all small buffers to fill the pool
        let mut guards: Vec<_> = (0..SMALL_POOL_SIZE)
            .map(|_| pool.alloc_small().expect("should succeed"))
            .collect();

        // Pool is now exhausted
        assert!(pool.alloc_small().is_none(), "pool should be exhausted");

        // Drop one guard to free a slot
        guards.pop();

        // Should be able to allocate again (FIFO — don't assert exact index)
        assert!(
            pool.alloc_small().is_some(),
            "alloc should succeed after freeing a buffer"
        );
    }

    #[test]
    fn test_pool_exhaustion_returns_none() {
        let pool = BufferPool::new();

        // Allocate all small buffers
        let _guards: Vec<_> = (0..SMALL_POOL_SIZE)
            .map(|_| pool.alloc_small().expect("should succeed"))
            .collect();

        // Next allocation must fail
        assert!(
            pool.alloc_small().is_none(),
            "alloc_small should return None when pool is exhausted"
        );
    }

    #[test]
    fn test_large_buffer_alloc() {
        let pool = BufferPool::new();
        let guard = pool
            .alloc_large()
            .expect("alloc_large should succeed on a fresh pool");
        assert!(
            (guard.pool_idx() as usize) >= SMALL_POOL_SIZE,
            "large buffer pool_idx should be >= SMALL_POOL_SIZE"
        );
    }

    #[test]
    fn test_buffer_read_write() {
        let pool = BufferPool::new();
        let mut guard = pool.alloc_small().expect("alloc should succeed");

        let data = b"wireguard packet payload";
        guard.as_mut()[..data.len()].copy_from_slice(data);

        assert_eq!(
            &guard.as_ref()[..data.len()],
            data,
            "data read back should match what was written"
        );
    }
}
