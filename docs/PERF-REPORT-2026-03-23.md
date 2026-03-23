# IronGuard Performance Report

**Date:** 2026-03-23
**Tunnel:** `wg-iron` (10.0.1.0/24) — macOS (Apple M4 Pro, 12 cores) <-> Linux (i7-12700K, 20 cores)
**Network:** LAN (10.101.0.0/24), both machines on same subnet
**Build:** debug profile (unoptimized), 15MB binary
**Crypto:** ChaCha20-Poly1305 via `ring` + `snow` (Noise_IKpsk2)

---

## Test Results

### TCP Throughput

| Test | Direction | Streams | Throughput | Notes |
|------|-----------|---------|------------|-------|
| 1. Single stream upload | client -> server | 1 | **72.54 Mbps** | Ramp-up from 9 to 111 Mbps, settled ~75 Mbps |
| 2. Single stream download | server -> client | 1 | **~0 Mbps** | CRITICAL: stalls after handshake |
| 3. Parallel upload | client -> server | 4 | **85.61 Mbps** | Even distribution ~21 Mbps/stream |
| 4. Tuned window (256K) | client -> server | 1 | **64.29 Mbps** | Slightly lower than default window |

### UDP Throughput

| Test | Target Rate | Achieved | Jitter | Packet Loss |
|------|------------|----------|--------|-------------|
| 5. UDP 100M | 100 Mbps | **100.00 Mbps** | 0 ms | 0/129,532 (0%) |
| 6. UDP 500M | 500 Mbps | **500.00 Mbps** | 0 ms | 0/647,446 (0%) |
| 7. UDP 1G | 1 Gbps | **853.14 Mbps** | 0 ms | 0/1,105,098 (0%) |

### Latency

| Metric | Tunnel (10.0.1.x) | Direct LAN (10.101.0.x) | Overhead |
|--------|-------------------|------------------------|----------|
| Min | 4.5 ms | 3.2 ms | +1.3 ms |
| Avg | 10.4 ms | 15.9 ms | -5.5 ms* |
| Max | 49.5 ms | 64.5 ms | -15 ms* |
| Loss | 2.0% | 0% | +2.0% |

*LAN baseline had high variance during measurement.

### Baseline Comparison (Direct LAN, no tunnel)

| Metric | Direct LAN | IronGuard Tunnel | Efficiency |
|--------|-----------|-----------------|------------|
| TCP Upload | 102.87 Mbps | 72.54 Mbps | **70.5%** |
| TCP Download | N/A (stalled) | ~0 Mbps | **BROKEN** |
| UDP 1G | N/A | 853 Mbps | N/A |

### Interface Counters (Server-Side wg-iron)

| Direction | Bytes | Packets | Errors | Dropped |
|-----------|-------|---------|--------|---------|
| RX (from client) | 642 MB | 518,454 | 0 | 0 |
| TX (to client) | 13 MB | 251,272 | 0 | 0 |

The massive RX/TX asymmetry (642 MB vs 13 MB) confirms the download direction issue is real.

---

## Findings

### CRITICAL: Server-to-Client (Download) Path Broken Under Sustained Load

**Symptom:** TCP download throughput drops to 0 Mbps after initial handshake. Tested both with iperf3 `-R` (reverse mode) and with iperf3 server on client side — same result. Small packets (ping, netcat) work fine bidirectionally.

**Evidence:** Server-side TUN TX counters show only 13 MB vs 642 MB RX, confirming the write path to TUN stalls under bulk load.

**Probable root causes (in order of likelihood):**

1. **TUN write backpressure not handled** — `tun_worker` reads from TUN and encrypts, but the reverse path (decrypt -> TUN write) in `udp_worker`/router may not handle `WouldBlock` correctly when the TUN device's kernel buffer fills up. The macOS `utun` write path may be blocking or silently dropping when the write buffer is full.

2. **Single-writer contention** — `MacosTunWriter` shares an `Arc<AsyncFd>` with the reader. Under bulk decrypt load, the writer and reader may contend on the `AsyncFd` readiness notifications. Linux's `LinuxTunWriter` has the same architecture.

3. **Flow control mismatch** — The router's decrypt path may process packets faster than the TUN can consume them, with no backpressure mechanism to slow down the peer.

### GOOD: Upload Path Performs Well

72 Mbps single-stream through userspace crypto on a debug build is respectable. The upload path (TUN read -> encrypt -> UDP send) has clean zero-copy with `SIZE_MESSAGE_PREFIX` offset.

### GOOD: UDP Handles 853 Mbps with Zero Loss

The raw UDP path can push nearly 1 Gbps with zero packet loss and zero jitter. The crypto path is not the bottleneck — it's the TUN write path.

### NOTE: Debug Build Penalty

All tests used `cargo build` (debug profile, no optimizations). A release build (`--release`) would give:
- 5-10x improvement on crypto operations (ChaCha20-Poly1305)
- Better inlining and branch prediction
- Estimated throughput improvement: 2-4x

---

## Improvement Checkpoints

### CP-1: Fix Download Path (CRITICAL)
**Priority:** P0 — blocks real-world usage
**Files:** `crates/ironguard-core/src/router/receive.rs`, `crates/ironguard-core/src/workers.rs`
**Action:**
- Audit the `udp_worker` -> router decrypt -> TUN write path for backpressure handling
- Add flow control: if TUN write returns `WouldBlock`, buffer or apply backpressure to the decrypt pipeline
- Consider separate `AsyncFd` instances for TUN read vs write to avoid readiness notification contention
- Add per-direction throughput counters to `PeerInner` for debugging

### CP-2: Release Build Benchmarks
**Priority:** P1
**Action:**
- Re-run all iperf3 tests with `cargo build --release`
- Expected: 2-4x TCP improvement, 150+ Mbps upload target
- Compare crypto throughput with `ring` benchmarks to identify if we're CPU-bound

### CP-3: Multi-Reader TUN Architecture
**Priority:** P2
**Files:** `crates/ironguard-platform/src/macos/tun.rs`, `linux/tun.rs`
**Action:**
- Currently `PlatformTun::create()` returns `Vec<Reader>` but only creates 1 reader
- For high throughput: create N readers (one per CPU core) using `dup()` or multiple FD registrations
- This enables parallel TUN read -> encrypt on multiple cores

### CP-4: Batch Crypto Operations
**Priority:** P2
**Files:** `crates/ironguard-core/src/router/send.rs`, `receive.rs`
**Action:**
- Current: encrypt/decrypt one packet at a time
- Improvement: batch multiple packets into a single crypto pass using `ring::aead::SealingKey` with vectored operations
- Could 2x throughput on bulk transfers

### CP-5: Zero-Copy Receive Path
**Priority:** P3
**Files:** `crates/ironguard-core/src/workers.rs`
**Action:**
- The receive path currently allocates `Vec<u8>` per packet in `udp_worker`
- Pre-allocate a buffer pool and use `bytes::BytesMut` for zero-copy decrypt
- Reduces allocator pressure under high packet rates

### CP-6: TUN MTU Alignment
**Priority:** P3
**Action:**
- Packets > 1400 bytes through the tunnel fail (100% loss at sizes 1400+)
- The WireGuard transport header + AEAD tag eat into the MTU
- Effective payload MTU = TUN MTU (1500) - WG overhead (60 bytes) = 1440
- Config should auto-set TUN MTU to 1420 and clamp IP packets accordingly
- Current: MTU set to 1420 in config but TUN device reports MTU 1500

### CP-7: Persistent Keepalive Timer Validation
**Priority:** P3
**Action:**
- Under sustained upload, verify keepalive timers don't fire unnecessarily
- Profile timer tick CPU usage during bulk transfer (currently 100ms poll)

---

## Environment Details

```
Server: Linux ai 6.17.0-14-generic, i7-12700K (20 cores), 10.0.1.1
Client: macOS Darwin 25.3.0, Apple M4 Pro (12 cores), 10.0.1.2
Tunnel: wg-iron, MTU 1420/1500, port 51820, ChaCha20-Poly1305
Build:  debug profile (unoptimized), ironguard v0.1.0
Tool:   iperf3 3.x, ping, netcat
```
