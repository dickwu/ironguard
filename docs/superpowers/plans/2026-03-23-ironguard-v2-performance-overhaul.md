# IronGuard v2 Performance Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace IronGuard's broken hybrid worker architecture with a 3-stage decoupled pipeline using AES-256-GCM, achieving 5-10+ Gbps throughput on Linux and 1-3 Gbps on macOS.

**Architecture:** Three async-decoupled stages (IO Reader -> Crypto Pool -> IO Writer) connected by bounded channels with batch dispatch. Crypto workers are dedicated OS threads doing pure compute with zero I/O. QUIC/TLS 1.3 handshake establishes sessions; raw UDP carries data-plane traffic with a native IronGuard frame format (16-byte header, epoch-based rekey).

**Tech Stack:** Rust 2024, Tokio async runtime, `ring` (AES-256-GCM), `quinn`/`rustls` (QUIC/TLS 1.3), `crossbeam-channel` (MPMC work queue), `crossbeam-queue` (lock-free buffer pool), `tun-rs` 2.8 (GSO/GRO on Linux)

**Spec:** `docs/superpowers/specs/2026-03-23-ironguard-v2-performance-overhaul-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `ironguard-core/src/pipeline/mod.rs` | Pipeline module exports |
| `ironguard-core/src/pipeline/pool.rs` | Two-tier buffer pool (2KB small + 64KB large), PacketRef, PacketGuard |
| `ironguard-core/src/pipeline/io.rs` | TransportIO trait, UdpBatchIO, QuicBatchIO implementations |
| `ironguard-core/src/pipeline/reorder.rs` | Per-peer reorder buffer with DropMarker support |
| `ironguard-core/src/pipeline/batch.rs` | Batch accumulator (flush timer, count/size thresholds) |
| `ironguard-core/src/session/mod.rs` | Session module exports |
| `ironguard-core/src/session/quic.rs` | QUIC endpoint, TLS config, DataPlaneInit/Ack protocol |
| `ironguard-core/src/session/keys.rs` | Epoch-based key derivation from TLS exporter + fresh entropy |
| `ironguard-core/src/session/state.rs` | Per-peer session state machine, RekeyInit/RekeyAck, MigrationProbe/Ack |
| `ironguard-core/src/router/messages_v2.rs` | New 16-byte frame header (Type/Flags/ReceiverID/Counter) |
| `ironguard-core/benches/pipeline.rs` | Criterion benchmarks for pool, crypto, pipeline throughput |
| `ironguard-platform/src/capabilities.rs` | PlatformCapabilities runtime detection |

### Modified Files

| File | Change |
|------|--------|
| `ironguard-core/src/router/send.rs` | AES-256-GCM, new frame header, AAD binding |
| `ironguard-core/src/router/receive.rs` | AES-256-GCM, new frame header, DropMarker emission |
| `ironguard-core/src/router/device.rs` | Remove `block_on_io`, channel-based I/O dispatch |
| `ironguard-core/src/router/worker.rs` | Pure compute loop (no I/O calls) |
| `ironguard-core/src/router/constants.rs` | New header sizes, batch constants |
| `ironguard-core/src/router/messages.rs` | Keep for legacy-wireguard feature flag |
| `ironguard-core/src/constants.rs` | Updated SIZE_MESSAGE_PREFIX, rekey constants |
| `ironguard-core/src/workers.rs` | New Stage 1/3 async tasks using pipeline |
| `ironguard-core/src/device.rs` | QUIC session instead of handshake device |
| `ironguard-core/src/timers.rs` | Adaptive tick rate (100ms/1s) |
| `ironguard-core/src/lib.rs` | Add `pub mod pipeline`, `pub mod session` |
| `ironguard-core/Cargo.toml` | Add `criterion` dev-dep, `crossbeam-queue` dep |
| `ironguard-platform/src/macos/tun.rs` | Split AsyncFd via dup() |
| `ironguard-platform/src/linux/tun.rs` | Multi-queue TUN, GSO/GRO support |
| `ironguard-platform/src/linux/udp.rs` | sendmmsg/recvmmsg, UDP GSO |
| `ironguard-platform/src/lib.rs` | Add `pub mod capabilities` |
| `ironguard-platform/Cargo.toml` | Add `crossbeam-queue` dep |
| `ironguard-cli/src/main.rs` | Updated startup flow for v2 protocol |
| `ironguard-config/src/types.rs` | Updated QuicConfig, epoch config fields |
| `Cargo.toml` | Add workspace deps: crossbeam-queue, criterion |

### Deleted Files (Phase 4)

| File | Replaced By |
|------|-------------|
| `ironguard-core/src/handshake/noise.rs` | `session/quic.rs` |
| `ironguard-core/src/handshake/macs.rs` | QUIC retry tokens |
| `ironguard-core/src/handshake/messages.rs` | `router/messages_v2.rs` |
| `ironguard-core/src/handshake/peer.rs` | `session/state.rs` |
| `ironguard-core/src/handshake/device.rs` | `session/quic.rs` |
| `ironguard-core/src/handshake/pq.rs` | Native TLS PQ |
| `ironguard-core/src/handshake/timestamp.rs` | Not needed |
| `ironguard-core/src/handshake/ratelimiter.rs` | QUIC retry tokens |

---

## Phase 1: AES-256-GCM + Buffer Pool

### Task 1: Buffer Pool — Core Data Structures

**Files:**
- Create: `crates/ironguard-core/src/pipeline/mod.rs`
- Create: `crates/ironguard-core/src/pipeline/pool.rs`
- Modify: `crates/ironguard-core/src/lib.rs` (add `pub mod pipeline`)
- Modify: `crates/ironguard-core/Cargo.toml` (add `crossbeam-queue = "0.3"`)

- [ ] **Step 1: Write failing tests for PacketRef and BufferPool**

In `crates/ironguard-core/src/pipeline/pool.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_returns_valid_index() {
        let pool = BufferPool::new();
        let guard = pool.alloc_small().expect("pool should have capacity");
        assert!(guard.pref.pool_idx < SMALL_POOL_SIZE as u16);
    }

    #[test]
    fn test_alloc_free_cycle() {
        let pool = BufferPool::new();
        let idx = {
            let guard = pool.alloc_small().unwrap();
            guard.pref.pool_idx
        }; // guard dropped here, index returned to pool
        let guard2 = pool.alloc_small().unwrap();
        assert_eq!(guard2.pref.pool_idx, idx); // same index reused
    }

    #[test]
    fn test_pool_exhaustion_returns_none() {
        let pool = BufferPool::new();
        let mut guards = Vec::new();
        for _ in 0..SMALL_POOL_SIZE {
            guards.push(pool.alloc_small().unwrap());
        }
        assert!(pool.alloc_small().is_none());
    }

    #[test]
    fn test_large_buffer_alloc() {
        let pool = BufferPool::new();
        let guard = pool.alloc_large().expect("large pool should have capacity");
        assert!(guard.pref.pool_idx >= SMALL_POOL_SIZE as u16);
    }

    #[test]
    fn test_buffer_read_write() {
        let pool = BufferPool::new();
        let mut guard = pool.alloc_small().unwrap();
        let buf = pool.get_mut(guard.pref.pool_idx);
        buf[0..5].copy_from_slice(b"hello");
        let read = pool.get(guard.pref.pool_idx);
        assert_eq!(&read[0..5], b"hello");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ironguard-core pipeline::pool::tests -v`
Expected: Compilation error (module and structs don't exist yet)

- [ ] **Step 3: Implement BufferPool, PacketRef, PacketGuard**

Create `crates/ironguard-core/src/pipeline/mod.rs`:

```rust
pub mod pool;
```

Create `crates/ironguard-core/src/pipeline/pool.rs`:

```rust
use std::cell::UnsafeCell;
use crossbeam_queue::ArrayQueue;

pub const SMALL_POOL_SIZE: usize = 8192;
pub const SMALL_BUF_SIZE: usize = 2048;
pub const LARGE_POOL_SIZE: usize = 128;
pub const LARGE_BUF_SIZE: usize = 65536;

#[derive(Clone, Copy, Debug)]
pub struct PacketRef {
    pub pool_idx: u16,
    pub offset: u16,
    pub len: u16,
    pub peer_idx: u16,
}

pub struct PacketGuard<'a> {
    pub pref: PacketRef,
    pool: &'a BufferPool,
}

impl Drop for PacketGuard<'_> {
    fn drop(&mut self) {
        self.pool.free(self.pref.pool_idx);
    }
}

pub struct BufferPool {
    small: Box<[UnsafeCell<[u8; SMALL_BUF_SIZE]>]>,
    large: Box<[UnsafeCell<[u8; LARGE_BUF_SIZE]>]>,
    small_free: ArrayQueue<u16>,
    large_free: ArrayQueue<u16>,
}

// Safety: BufferPool is Send+Sync because each index is exclusively
// owned by either the free list or a PacketGuard, never both.
unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}

impl BufferPool {
    pub fn new() -> Self {
        let small: Vec<UnsafeCell<[u8; SMALL_BUF_SIZE]>> =
            (0..SMALL_POOL_SIZE).map(|_| UnsafeCell::new([0u8; SMALL_BUF_SIZE])).collect();
        let large: Vec<UnsafeCell<[u8; LARGE_BUF_SIZE]>> =
            (0..LARGE_POOL_SIZE).map(|_| UnsafeCell::new([0u8; LARGE_BUF_SIZE])).collect();

        let small_free = ArrayQueue::new(SMALL_POOL_SIZE);
        for i in 0..SMALL_POOL_SIZE {
            let _ = small_free.push(i as u16);
        }
        let large_free = ArrayQueue::new(LARGE_POOL_SIZE);
        for i in 0..LARGE_POOL_SIZE {
            let _ = large_free.push((SMALL_POOL_SIZE + i) as u16);
        }

        Self {
            small: small.into_boxed_slice(),
            large: large.into_boxed_slice(),
            small_free,
            large_free,
        }
    }

    pub fn alloc_small(&self) -> Option<PacketGuard<'_>> {
        self.small_free.pop().map(|idx| PacketGuard {
            pref: PacketRef { pool_idx: idx, offset: 0, len: 0, peer_idx: 0 },
            pool: self,
        })
    }

    pub fn alloc_large(&self) -> Option<PacketGuard<'_>> {
        self.large_free.pop().map(|idx| PacketGuard {
            pref: PacketRef { pool_idx: idx, offset: 0, len: 0, peer_idx: 0 },
            pool: self,
        })
    }

    fn free(&self, idx: u16) {
        let idx_usize = idx as usize;
        if idx_usize < SMALL_POOL_SIZE {
            let _ = self.small_free.push(idx);
        } else {
            let _ = self.large_free.push(idx);
        }
    }

    pub fn get(&self, idx: u16) -> &[u8] {
        let idx_usize = idx as usize;
        if idx_usize < SMALL_POOL_SIZE {
            unsafe { &*self.small[idx_usize].get() }
        } else {
            let large_idx = idx_usize - SMALL_POOL_SIZE;
            unsafe { &*self.large[large_idx].get() }
        }
    }

    pub fn get_mut(&self, idx: u16) -> &mut [u8] {
        let idx_usize = idx as usize;
        if idx_usize < SMALL_POOL_SIZE {
            unsafe { &mut *self.small[idx_usize].get() }
        } else {
            let large_idx = idx_usize - SMALL_POOL_SIZE;
            unsafe { &mut *self.large[large_idx].get() }
        }
    }
}
```

Add `pub mod pipeline;` to `crates/ironguard-core/src/lib.rs`.
Add `crossbeam-queue = "0.3"` to `crates/ironguard-core/Cargo.toml` deps.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ironguard-core pipeline::pool::tests -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-core/src/pipeline/ crates/ironguard-core/src/lib.rs crates/ironguard-core/Cargo.toml
git commit -m "feat(pipeline): add two-tier buffer pool with PacketGuard RAII"
```

---

### Task 2: AES-256-GCM Cipher Swap

**Files:**
- Modify: `crates/ironguard-core/src/router/send.rs`
- Modify: `crates/ironguard-core/src/router/receive.rs`

- [ ] **Step 1: Verify existing router tests pass with ChaCha20**

Run: `cargo test -p ironguard-core router::tests -v`
Expected: All 7 tests PASS (baseline)

- [ ] **Step 2: Swap cipher constant in send.rs**

In `crates/ironguard-core/src/router/send.rs`, change line 16:

```rust
// Before:
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

// After:
use ring::aead::{Aad, AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
```

And update every occurrence of `CHACHA20_POLY1305` to `AES_256_GCM` in the file (the `UnboundKey::new` call).

- [ ] **Step 3: Swap cipher constant in receive.rs**

Same change in `crates/ironguard-core/src/router/receive.rs` line 14:

```rust
// Before:
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

// After:
use ring::aead::{Aad, AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
```

Update every occurrence of `CHACHA20_POLY1305` to `AES_256_GCM`.

- [ ] **Step 4: Run router tests to verify they pass**

Run: `cargo test -p ironguard-core router::tests -v`
Expected: All 7 tests PASS (AES-256-GCM is API-compatible with ChaCha20 in ring)

- [ ] **Step 5: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests PASS. The handshake tests use their own crypto (snow/Noise) and are unaffected.

- [ ] **Step 6: Commit**

```bash
git add crates/ironguard-core/src/router/send.rs crates/ironguard-core/src/router/receive.rs
git commit -m "feat(crypto): swap ChaCha20-Poly1305 to AES-256-GCM (2.5-3.6x faster)"
```

---

### Task 3: New Frame Header (messages_v2.rs)

**Files:**
- Create: `crates/ironguard-core/src/router/messages_v2.rs`
- Modify: `crates/ironguard-core/src/router/mod.rs` (add `pub mod messages_v2`)

- [ ] **Step 1: Write failing tests for v2 frame header**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size_is_16_bytes() {
        assert_eq!(std::mem::size_of::<FrameHeader>(), 16);
    }

    #[test]
    fn test_header_roundtrip() {
        let hdr = FrameHeader::new_data(0xDEAD_BEEF, 42);
        let bytes = hdr.as_bytes();
        let parsed = FrameHeader::from_bytes(bytes).unwrap();
        assert_eq!(parsed.msg_type(), TYPE_DATA);
        assert_eq!(parsed.receiver_id(), 0xDEAD_BEEF);
        assert_eq!(parsed.counter(), 42);
    }

    #[test]
    fn test_batch_header_size_is_20_bytes() {
        assert_eq!(std::mem::size_of::<BatchHeader>(), 20);
    }

    #[test]
    fn test_header_as_aad() {
        let hdr = FrameHeader::new_data(1, 0);
        let aad = hdr.as_aad();
        assert_eq!(aad.len(), 16);
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p ironguard-core router::messages_v2::tests -v`
Expected: Compilation error

- [ ] **Step 3: Implement FrameHeader and BatchHeader**

Create `crates/ironguard-core/src/router/messages_v2.rs`:

```rust
pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_KEEPALIVE: u8 = 0x02;
pub const TYPE_CONTROL: u8 = 0x03;
pub const TYPE_BATCH: u8 = 0x04;

pub const HEADER_SIZE: usize = 16;
pub const BATCH_HEADER_SIZE: usize = 20;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FrameHeader {
    pub f_type: u8,
    pub f_flags: u8,
    pub f_reserved: [u8; 2],
    pub f_receiver: [u8; 4],
    pub f_counter: [u8; 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BatchHeader {
    pub frame: FrameHeader,
    pub f_batch_count: [u8; 2],
    pub f_total_len: [u8; 2],
}

impl FrameHeader {
    pub fn new_data(receiver_id: u32, counter: u64) -> Self {
        Self {
            f_type: TYPE_DATA,
            f_flags: 0,
            f_reserved: [0; 2],
            f_receiver: receiver_id.to_le_bytes(),
            f_counter: counter.to_le_bytes(),
        }
    }

    pub fn msg_type(&self) -> u8 {
        self.f_type
    }

    pub fn receiver_id(&self) -> u32 {
        u32::from_le_bytes(self.f_receiver)
    }

    pub fn counter(&self) -> u64 {
        u64::from_le_bytes(self.f_counter)
    }

    pub fn as_bytes(&self) -> &[u8; HEADER_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; HEADER_SIZE]) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn as_aad(&self) -> &[u8] {
        self.as_bytes()
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ironguard-core router::messages_v2::tests -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-core/src/router/messages_v2.rs crates/ironguard-core/src/router/mod.rs
git commit -m "feat(protocol): add IronGuard v2 frame header (16-byte, Type/Flags/ReceiverID/Counter)"
```

---

### Task 4: Criterion Benchmarks

**Files:**
- Create: `crates/ironguard-core/benches/pipeline.rs`
- Modify: `crates/ironguard-core/Cargo.toml` (add criterion dev-dep and `[[bench]]`)

- [ ] **Step 1: Add criterion dependency**

Add to `crates/ironguard-core/Cargo.toml`:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "pipeline"
harness = false
```

- [ ] **Step 2: Write benchmarks**

Create `crates/ironguard-core/benches/pipeline.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ironguard_core::pipeline::pool::BufferPool;
use ring::aead::{Aad, AES_256_GCM, LessSafeKey, Nonce, UnboundKey, BoundKey, SealingKey, OpeningKey, NonceSequence, NONCE_LEN};

fn bench_buffer_pool_alloc_free(c: &mut Criterion) {
    let pool = BufferPool::new();
    c.bench_function("buffer_pool_alloc_free", |b| {
        b.iter(|| {
            let guard = pool.alloc_small().unwrap();
            black_box(guard.pref.pool_idx);
            // guard dropped here, returns to pool
        });
    });
}

fn bench_aes_gcm_1500(c: &mut Criterion) {
    let key_bytes = [0x42u8; 32];
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let mut buf = vec![0u8; 1500 + 16]; // payload + tag space
    let nonce_bytes = [0u8; 12];

    c.bench_function("aes_256_gcm_seal_1500", |b| {
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let _ = key.seal_in_place_append_tag(nonce, Aad::from(&[0u8; 16]), &mut buf[..1500]);
        });
    });
}

criterion_group!(benches, bench_buffer_pool_alloc_free, bench_aes_gcm_1500);
criterion_main!(benches);
```

- [ ] **Step 3: Run benchmarks**

Run: `cargo bench -p ironguard-core --bench pipeline`
Expected: Benchmark results. Buffer pool < 20ns, AES-GCM-256 seal < 200ns for 1500 bytes.

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-core/benches/ crates/ironguard-core/Cargo.toml
git commit -m "bench: add Criterion benchmarks for buffer pool and AES-256-GCM"
```

---

## Phase 2: 3-Stage Pipeline

### Task 5: Reorder Buffer

**Files:**
- Create: `crates/ironguard-core/src/pipeline/reorder.rs`
- Modify: `crates/ironguard-core/src/pipeline/mod.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_delivery() {
        let mut rb = ReorderBuffer::new();
        rb.insert(0, PacketRef { pool_idx: 10, offset: 0, len: 100, peer_idx: 0 });
        rb.insert(1, PacketRef { pool_idx: 11, offset: 0, len: 100, peer_idx: 0 });
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].pool_idx, 10);
        assert_eq!(drained[1].pool_idx, 11);
    }

    #[test]
    fn test_out_of_order_reorder() {
        let mut rb = ReorderBuffer::new();
        rb.insert(1, PacketRef { pool_idx: 11, offset: 0, len: 100, peer_idx: 0 });
        assert_eq!(rb.drain().count(), 0); // seq 0 missing
        rb.insert(0, PacketRef { pool_idx: 10, offset: 0, len: 100, peer_idx: 0 });
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn test_drop_marker_skips_slot() {
        let mut rb = ReorderBuffer::new();
        rb.insert(1, PacketRef { pool_idx: 11, offset: 0, len: 100, peer_idx: 0 });
        rb.mark_dropped(0);
        let drained: Vec<_> = rb.drain().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].pool_idx, 11);
    }

    #[test]
    fn test_window_overflow_drops_old() {
        let mut rb = ReorderBuffer::new();
        // insert seq way beyond window
        rb.insert(MAX_REORDER_WINDOW as u64 + 10, PacketRef { pool_idx: 1, offset: 0, len: 0, peer_idx: 0 });
        assert_eq!(rb.drain().count(), 0); // too far ahead, dropped
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p ironguard-core pipeline::reorder::tests -v`
Expected: Compilation error

- [ ] **Step 3: Implement ReorderBuffer**

Create `crates/ironguard-core/src/pipeline/reorder.rs`:

```rust
use std::collections::BTreeMap;
use super::pool::PacketRef;

pub const MAX_REORDER_WINDOW: usize = 256;

pub struct ReorderBuffer {
    next_seq: u64,
    window: BTreeMap<u64, Option<PacketRef>>, // None = DropMarker
}

impl ReorderBuffer {
    pub fn new() -> Self {
        Self { next_seq: 0, window: BTreeMap::new() }
    }

    pub fn insert(&mut self, seq: u64, pref: PacketRef) {
        if seq < self.next_seq {
            return; // already delivered or skipped
        }
        if (seq - self.next_seq) as usize >= MAX_REORDER_WINDOW {
            return; // too far ahead, drop
        }
        self.window.insert(seq, Some(pref));
    }

    pub fn mark_dropped(&mut self, seq: u64) {
        if seq < self.next_seq {
            return;
        }
        self.window.insert(seq, None);
    }

    pub fn drain(&mut self) -> impl Iterator<Item = PacketRef> + '_ {
        let mut result = Vec::new();
        while let Some(entry) = self.window.first_key_value() {
            if *entry.0 != self.next_seq {
                break;
            }
            let (_, pref_opt) = self.window.pop_first().unwrap();
            self.next_seq += 1;
            if let Some(pref) = pref_opt {
                result.push(pref);
            }
            // None = DropMarker, skip silently
        }
        result.into_iter()
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ironguard-core pipeline::reorder::tests -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-core/src/pipeline/reorder.rs crates/ironguard-core/src/pipeline/mod.rs
git commit -m "feat(pipeline): add per-peer reorder buffer with DropMarker support"
```

---

### Task 6: Pipeline Workers — Decouple Crypto from I/O

**Files:**
- Modify: `crates/ironguard-core/src/router/worker.rs`
- Modify: `crates/ironguard-core/src/router/receive.rs`
- Modify: `crates/ironguard-core/src/router/send.rs`
- Modify: `crates/ironguard-core/src/router/device.rs`
- Modify: `crates/ironguard-core/src/workers.rs`

This is the largest task — it rewires the entire data path. The key change: `sequential_work()` in send.rs and receive.rs no longer calls I/O directly. Instead, it pushes the processed packet to a bounded channel that a dedicated writer task consumes.

- [ ] **Step 1: Add channel fields to DeviceInner**

In `crates/ironguard-core/src/router/device.rs`, add to `DeviceInner`:

```rust
// New: channels for decoupled I/O
pub(super) tun_write_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
pub(super) udp_write_tx: tokio::sync::mpsc::Sender<(Vec<u8>, E)>,
```

- [ ] **Step 2: Replace block_on_io in receive.rs sequential_work**

In `ReceiveJob::sequential_work()`, replace the `block_on_io(inbound.write(...))` call with:

```rust
let packet = packet[..inner].to_vec();
let _ = peer.device.tun_write_tx.try_send(packet);
// try_send is non-blocking. If channel full, packet is dropped (backpressure).
```

Remove the `block_on_io` import and usage from this file.

- [ ] **Step 3: Replace block_on_io in send.rs sequential_work**

In `SendJob::sequential_work()`, replace the `block_on_io(w.write(...))` call with:

```rust
let _ = peer.device.udp_write_tx.try_send((wire_msg.to_vec(), endpoint));
```

- [ ] **Step 4: Remove block_on_io from device.rs**

Delete the `block_on_io` function from `crates/ironguard-core/src/router/device.rs`.

- [ ] **Step 5: Add dedicated writer tasks in workers.rs**

Add to `crates/ironguard-core/src/workers.rs`:

```rust
pub async fn tun_write_worker<T: tun::Writer>(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    writer: T,
) {
    while let Some(packet) = rx.recv().await {
        let _ = writer.write(&packet).await;
    }
}

pub async fn udp_write_worker<E: Endpoint, B: udp::UdpWriter<E>>(
    mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, E)>,
    writer: B,
) {
    while let Some((msg, endpoint)) = rx.recv().await {
        let _ = writer.write(&msg, &endpoint).await;
    }
}
```

- [ ] **Step 6: Wire channels in device.rs new() and spawn writer tasks**

In `DeviceHandle::new()`, create the channels and store senders in `DeviceInner`. In `WireGuard::up()` or equivalent, spawn the writer tasks into the runtime.

- [ ] **Step 7: Run router tests**

Run: `cargo test -p ironguard-core router::tests -v`
Expected: All 7 tests PASS (the dummy backend's writer is now driven by the dedicated task)

- [ ] **Step 8: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests PASS

- [ ] **Step 9: Commit**

```bash
git add crates/ironguard-core/src/router/ crates/ironguard-core/src/workers.rs
git commit -m "feat(pipeline): decouple crypto workers from I/O via bounded channels

Workers are now pure compute. Dedicated async TUN/UDP writer tasks
consume from bounded mpsc channels. block_on_io is eliminated."
```

---

### Task 7: Split TUN AsyncFd (macOS)

**Files:**
- Modify: `crates/ironguard-platform/src/macos/tun.rs`

- [ ] **Step 1: Use dup() to create separate read/write fds**

In `MacosTun::create()`, after creating the TUN device, dup the fd:

```rust
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::{AsyncReadExt, Interest};

// Reader gets the original fd with READABLE interest
let read_fd = Arc::new(AsyncFd::with_interest(&tun_device, Interest::READABLE)?);

// Writer gets a dup'd fd with WRITABLE interest
let raw = tun_device.as_raw_fd();
let write_raw = unsafe { libc::dup(raw) };
if write_raw < 0 {
    return Err(std::io::Error::last_os_error().into());
}
// Create a separate AsyncFd for writing
let write_fd = Arc::new(AsyncFd::with_interest(
    unsafe { OwnedFd::from_raw_fd(write_raw) },
    Interest::WRITABLE,
)?);
```

- [ ] **Step 2: Update MacosTunReader to use read_fd, MacosTunWriter to use write_fd**

- [ ] **Step 3: Run macOS TUN test**

Run: `cargo test -p ironguard-platform macos -- --ignored` (requires root)
Expected: Test passes with split fds

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-platform/src/macos/tun.rs
git commit -m "fix(macos): split TUN AsyncFd via dup() to eliminate readiness contention"
```

---

## Phase 3: Batch Accumulator

### Task 8: Batch Accumulator

**Files:**
- Create: `crates/ironguard-core/src/pipeline/batch.rs`
- Modify: `crates/ironguard-core/src/pipeline/mod.rs`

- [ ] **Step 1: Write tests for batch accumulator**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_single_packet_flushes_immediately_at_threshold() {
        let mut acc = BatchAccumulator::new(2, 4096, Duration::from_millis(50));
        acc.push(PacketRef { pool_idx: 0, offset: 0, len: 100, peer_idx: 0 });
        assert!(acc.should_flush().is_none()); // not at threshold yet
        acc.push(PacketRef { pool_idx: 1, offset: 0, len: 100, peer_idx: 0 });
        let batch = acc.flush();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_flush_returns_empty_when_no_packets() {
        let mut acc = BatchAccumulator::new(64, 65536, Duration::from_millis(50));
        let batch = acc.flush();
        assert!(batch.is_empty());
    }
}
```

- [ ] **Step 2-5: Implement, test, commit** (same TDD pattern)

```bash
git commit -m "feat(pipeline): add batch accumulator with count/size/timeout flush"
```

---

## Phase 4: QUIC Session Module

### Task 9: Session Key Derivation

**Files:**
- Create: `crates/ironguard-core/src/session/mod.rs`
- Create: `crates/ironguard-core/src/session/keys.rs`

- [ ] **Step 1: Write tests for epoch-based key derivation**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_keys_are_directional() {
        let exporter = [0x42u8; 64];
        let (client_send, client_recv) = derive_initial_keys(&exporter, Role::Client);
        let (server_send, server_recv) = derive_initial_keys(&exporter, Role::Server);
        // Client's send = Server's recv
        assert_eq!(client_send, server_recv);
        assert_eq!(client_recv, server_send);
        // Send != recv
        assert_ne!(client_send, client_recv);
    }

    #[test]
    fn test_epoch_keys_differ_from_initial() {
        let exporter = [0x42u8; 64];
        let (init_send, _) = derive_initial_keys(&exporter, Role::Client);
        let entropy_a = [0xAA; 32];
        let entropy_b = [0xBB; 32];
        let (epoch_send, _) = derive_epoch_keys(&exporter, 1, &entropy_a, &entropy_b, Role::Client);
        assert_ne!(init_send, epoch_send);
    }

    #[test]
    fn test_different_entropy_produces_different_keys() {
        let exporter = [0x42u8; 64];
        let (keys_a, _) = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Client);
        let (keys_b, _) = derive_epoch_keys(&exporter, 1, &[0xCC; 32], &[0xDD; 32], Role::Client);
        assert_ne!(keys_a, keys_b);
    }
}
```

- [ ] **Step 2-5: Implement using ring::hkdf, test, commit**

```bash
git commit -m "feat(session): add epoch-based key derivation from TLS exporter"
```

---

### Task 10: Session State Machine

**Files:**
- Create: `crates/ironguard-core/src/session/state.rs`

Implements RekeyInit/RekeyAck and MigrationProbe/MigrationAck protocol messages. Tests cover the full rekey lifecycle and migration flow.

- [ ] **Step 1-5: TDD for RekeyInit/RekeyAck/MigrationProbe/MigrationAck structs and state transitions**

```bash
git commit -m "feat(session): add rekey and migration state machines"
```

---

### Task 11: QUIC Handshake Endpoint

**Files:**
- Create: `crates/ironguard-core/src/session/quic.rs`
- Modify: `crates/ironguard-core/src/device.rs`

Implements the QUIC handshake flow: connect, exchange DataPlaneInit/Ack, derive initial keys, spawn rekey timer. This replaces the Noise handshake in `handshake/device.rs`.

- [ ] **Step 1-5: TDD for QUIC session establishment using quinn**

```bash
git commit -m "feat(session): add QUIC/TLS 1.3 handshake endpoint with DataPlaneInit/Ack"
```

---

### Task 12: Delete Old Handshake Modules

**Files:**
- Delete: `crates/ironguard-core/src/handshake/` (entire directory)
- Modify: `crates/ironguard-core/src/lib.rs` (remove `pub mod handshake`, add `pub mod session`)
- Modify: `crates/ironguard-core/Cargo.toml` (remove `snow`, `chacha20poly1305`, `blake2s_simd`, `blake2b_simd`)

- [ ] **Step 1: Remove handshake module and deps**
- [ ] **Step 2: Verify workspace builds**

Run: `cargo build --workspace`
Expected: Clean build with no references to deleted modules

- [ ] **Step 3: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests PASS (handshake tests are gone, replaced by session tests)

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: remove legacy WireGuard handshake modules (~900 lines)

Replaced by QUIC/TLS 1.3 session module. Removed deps: snow,
chacha20poly1305, blake2s_simd, blake2b_simd."
```

---

## Phase 5: Platform I/O Optimization

### Task 13: Linux Multi-Queue TUN + GSO/GRO

**Files:**
- Modify: `crates/ironguard-platform/src/linux/tun.rs`
- Create: `crates/ironguard-platform/src/capabilities.rs`
- Modify: `crates/ironguard-platform/src/lib.rs`

- [ ] **Step 1: Add PlatformCapabilities struct**

```rust
pub struct PlatformCapabilities {
    pub tun_multi_queue: bool,
    pub tun_gso_gro: bool,
    pub udp_sendmmsg: bool,
    pub udp_gso: bool,
    pub max_tun_queues: usize,
}

impl PlatformCapabilities {
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                tun_multi_queue: true,
                tun_gso_gro: Self::check_kernel_version(6, 2),
                udp_sendmmsg: true,
                udp_gso: true,
                max_tun_queues: num_cpus::get(),
            }
        }
        #[cfg(target_os = "macos")]
        {
            Self {
                tun_multi_queue: false,
                tun_gso_gro: false,
                udp_sendmmsg: false,
                udp_gso: false,
                max_tun_queues: 1,
            }
        }
    }
}
```

- [ ] **Step 2: Update Linux TUN to support multi-queue**

In `LinuxTun::create()`, create N readers (one per CPU) using `tun-rs` multi-queue support. Return `Vec<Reader>` with N entries instead of 1.

- [ ] **Step 3: Add GSO/GRO support to Linux TUN**

Use `tun-rs::recv_multiple()` and `send_multiple()` with `GROTable` when `tun_gso_gro` capability is detected.

- [ ] **Step 4: Test and commit**

```bash
git commit -m "feat(linux): add multi-queue TUN, GSO/GRO, platform capability detection"
```

---

### Task 14: Linux sendmmsg/recvmmsg for UDP

**Files:**
- Modify: `crates/ironguard-platform/src/linux/udp.rs`

- [ ] **Step 1-4: Add batched UDP I/O using libc::sendmmsg/recvmmsg, test, commit**

```bash
git commit -m "feat(linux): add sendmmsg/recvmmsg for batched UDP I/O"
```

---

### Task 15: macOS utun Buffer Tuning

**Files:**
- Modify: `crates/ironguard-platform/src/macos/tun.rs`

- [ ] **Step 1: Add utun buffer size tuning at device creation**

After creating the TUN device, increase the socket buffer:

```rust
use std::process::Command;
// Increase utun kernel buffer (requires root)
let _ = Command::new("sysctl")
    .args(["-w", "net.local.dgram.recvspace=262144"])
    .output();
```

Or better, use `setsockopt(SO_RCVBUF)` on the utun control socket if accessible.

- [ ] **Step 2: Commit**

```bash
git commit -m "fix(macos): increase utun buffer size to prevent download stall"
```

---

## Phase 6: Polish + Tune

### Task 16: MTU Alignment

**Files:**
- Modify: `crates/ironguard-core/src/constants.rs`
- Modify: `crates/ironguard-cli/src/main.rs` (verify MTU after TUN creation)

- [ ] **Step 1: Update constants**

```rust
pub const TUN_MTU: usize = 1420; // Conservative: covers IPv4 (1440) and IPv6 (1420) outer headers
pub const SIZE_MESSAGE_PREFIX: usize = 16; // New frame header size (was 64)
```

- [ ] **Step 2: Add MTU verification in CLI startup**

After TUN device creation, verify the MTU matches expectations:

```rust
let actual_mtu = tun_device.mtu()?;
if actual_mtu != TUN_MTU as i32 {
    log::warn!("TUN MTU mismatch: requested {}, got {}", TUN_MTU, actual_mtu);
}
```

- [ ] **Step 3: Commit**

```bash
git commit -m "fix: set TUN MTU to 1420, verify with ioctl, update SIZE_MESSAGE_PREFIX"
```

---

### Task 17: Adaptive Timer Tick

**Files:**
- Modify: `crates/ironguard-core/src/timers.rs`

- [ ] **Step 1: Add adaptive tick logic**

In the timer tick loop, check if the peer has recent activity:

```rust
let tick = if peer.has_recent_activity(now) {
    Duration::from_millis(100) // active: fine-grained
} else {
    Duration::from_secs(1)     // idle: coarse
};
```

- [ ] **Step 2: Add QUIC keepalive interaction**

In handshake-only mode, IronGuard timers handle keepalive. In full-QUIC mode, disable IronGuard keepalive timer.

- [ ] **Step 3: Run timer tests**

Run: `cargo test -p ironguard-core timers -v`
Expected: All 20 existing tests PASS, new adaptive logic tested

- [ ] **Step 4: Commit**

```bash
git commit -m "perf: adaptive timer tick (100ms active, 1s idle)"
```

---

### Task 18: Release Build Benchmarks + Integration Test

**Files:**
- Modify: `crates/ironguard-core/benches/pipeline.rs` (add pipeline throughput bench)

- [ ] **Step 1: Add end-to-end pipeline throughput benchmark using dummy backend**

```rust
fn bench_pipeline_throughput(c: &mut Criterion) {
    // Create dummy TUN pair, configure WireGuard device, pump N packets
    // Measure throughput in Gbps-equivalent
}
```

- [ ] **Step 2: Run release benchmarks**

Run: `cargo bench -p ironguard-core --bench pipeline`
Expected: buffer_pool < 20ns, aes_gcm < 200ns, pipeline > 5 Gbps equivalent

- [ ] **Step 3: Commit**

```bash
git commit -m "bench: add end-to-end pipeline throughput benchmark"
```

---

## Review Errata (Must-Read Before Implementing)

These corrections were identified during plan review and MUST be applied by the implementing engineer:

### E1: Task 2 — AAD binding required with cipher swap
When swapping to AES-256-GCM, also update `seal_in_place_separate_tag` / `open_in_place` calls to pass the frame header as `Aad::from(header.as_bytes())` instead of `Aad::empty()`. The spec requires the full 16-byte header as AAD. Add a test that modifying a header byte after encryption causes decryption to fail.

### E2: Task 6 — DeviceInner field changes
Step 1 must also **remove** the `inbound: T` field from `DeviceInner` (replacing it with `tun_write_tx`). The `DeviceHandle::new()` signature changes: it accepts the TUN writer to spawn the writer task, but stores only the channel sender. Similarly for `outbound` → `udp_write_tx`.

### E3: Task 6 — send.rs does NOT use block_on_io
Step 3 is wrong: `SendJob::sequential_work` calls `peer.send_raw()`, not `block_on_io`. Replace: change `peer.send_raw(wire_msg)` to `peer.device.udp_write_tx.try_send((wire_msg.to_vec(), endpoint))`.

### E4: Task 6 — Spawn site for writer tasks
Step 6 references `WireGuard::up()` which doesn't exist. The spawn site is in `crates/ironguard-cli/src/main.rs`, after constructing the `WireGuard` device. Spawn `tun_write_worker` and `udp_write_worker` as Tokio tasks there.

### E5: Task 3 — Feature flag scaffolding
When adding `messages_v2.rs`, also gate `pub mod messages;` behind `#[cfg(feature = "legacy-wireguard")]` in `router/mod.rs`. Add `legacy-wireguard = ["dep:snow", "dep:chacha20poly1305", "dep:blake2s_simd", "dep:blake2b_simd"]` to `ironguard-core/Cargo.toml` features. Update imports in `router/device.rs` and `workers.rs` to use `messages_v2`.

### E6: Task 1 — Pool test ordering assumption
`test_alloc_free_cycle` assumes LIFO reuse. `ArrayQueue` is FIFO. Fix: use a pool of size 1 for this test, or assert `pool.alloc_small().is_some()` instead of checking the exact index.

### E7: Tasks 8, 10, 11 — Incomplete implementations
These tasks have elided implementation code ("Step 1-5: TDD for..."). The implementing agent must:
- **Task 8 (BatchAccumulator):** Define struct with fields `packets: Vec<PacketRef>`, `max_count: usize`, `max_bytes: usize`, `timeout: Duration`, `created: Instant`. Implement `push()`, `should_flush() -> bool`, `flush() -> Vec<PacketRef>`.
- **Task 10 (Session State):** Define `RekeyState` enum (`Idle`, `InitSent { epoch, entropy }`, `Active { epoch }`), `MigrationState` enum (`Stable`, `Probing { challenge }`, `Migrated`). Implement state transition methods with explicit test cases for happy path, auth failure, and rollback.
- **Task 11 (QUIC Endpoint):** Use `quinn::Endpoint::connect()` for client, `quinn::Endpoint::accept()` for server. After handshake, exchange `DataPlaneInit`/`DataPlaneAck` as QUIC datagrams. Derive keys using `session::keys::derive_initial_keys()`. Test with two in-process endpoints over loopback.

### E8: cargo test filter syntax
All `cargo test -p ironguard-core router::tests -v` commands should be `cargo test -p ironguard-core -- router::tests -v` (with `--` separator before the filter).

### E9: Criterion benchmark imports
Remove unused imports (`BoundKey`, `SealingKey`, `OpeningKey`, `NonceSequence`, `NONCE_LEN`). Use `seal_in_place_separate_tag` instead of `seal_in_place_append_tag` to avoid buffer sizing issues.

### E10: crossbeam-queue workspace dependency
Add `crossbeam-queue = "0.3"` to `[workspace.dependencies]` in root `Cargo.toml`, then reference as `crossbeam-queue = { workspace = true }` in crate-level Cargo.toml files (matching existing convention).

### E11: Module registration
- Task 8: Add `pub mod batch;` to `pipeline/mod.rs`
- Task 9: Create `session/mod.rs` with `pub mod keys;`
- Task 10: Add `pub mod state;` to `session/mod.rs`
- Task 11: Add `pub mod quic;` to `session/mod.rs`

### E12: PlatformCapabilities fallback
Add `#[cfg(not(any(target_os = "linux", target_os = "macos")))]` block returning all capabilities as `false`. Define `check_kernel_version()` using `libc::uname()`.

---

## Verification Checklist

After all phases:

- [ ] `cargo build --workspace` — clean build
- [ ] `cargo test --workspace` — all tests pass
- [ ] `cargo clippy --workspace -- -D warnings` — no warnings
- [ ] `cargo fmt --all -- --check` — formatted
- [ ] `cargo bench -p ironguard-core --bench pipeline` — meets targets
- [ ] Download path works (bidirectional iperf3 with real TUN)
- [ ] Release build throughput > 1 Gbps on macOS, > 5 Gbps on Linux
