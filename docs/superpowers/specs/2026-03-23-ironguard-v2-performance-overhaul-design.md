# IronGuard v2: Performance Overhaul & Native Protocol Design

**Date:** 2026-03-23
**Status:** Approved
**Scope:** Full performance overhaul (CP-1 through CP-7) + protocol redesign
**Target:** 5-10+ Gbps throughput, both platforms (macOS + Linux)

---

## 1. Problem Statement

IronGuard's current architecture has a critical download path failure (0 Mbps under sustained load) and several performance bottlenecks identified in the [performance report](../../PERF-REPORT-2026-03-23.md).

### Root Causes

1. **Router worker OS threads block on TUN writes.** `ReceiveJob::sequential_work` calls `block_on_io` -> `handle.block_on(tun_writer.write())`. When the TUN kernel buffer fills, all `num_cpus` workers stall, halting the decrypt pipeline entirely.

2. **Single shared TUN fd.** Reader and Writer share one `Arc<AsyncFd<TunDevice>>`. Edge-triggered kqueue readiness contention between directions.

3. **Crossbeam blocking send stalls Tokio.** `udp_worker` (Tokio task) calls `crossbeam_channel::send()` (blocking) to dispatch to the work queue. When workers are stuck on TUN writes, the 4096-slot queue fills and blocks the Tokio runtime.

4. **macOS utun buffer is 8KB.** `net.local.dgram.recvspace` defaults to 8192 bytes, filling instantly under load.

5. **Per-packet heap allocation + per-packet key construction.** Fresh `Vec<u8>` per UDP recv, new `LessSafeKey` per decrypt.

### Additional Performance Constraints

- ChaCha20-Poly1305 is 2.5-3.6x slower than AES-256-GCM on CPUs with AES-NI/ARM AES extensions (all x86-64 since 2010, Apple Silicon, ARM Cortex-A7x+)
- One IP packet per encrypted message (no batching)
- 16-byte transport header per packet
- Double encryption in QUIC mode (WireGuard + TLS 1.3)
- No GSO/GRO or sendmmsg/recvmmsg utilization

---

## 2. Key Decision: Drop WireGuard Protocol Compatibility

IronGuard v2 adopts a native protocol. WireGuard compatibility is available behind a `legacy-wireguard` feature flag but is not the default.

### What This Unlocks

| Change | Impact |
|--------|--------|
| AES-256-GCM default cipher | 2.5-3.6x crypto throughput |
| Batch encryption (64 pkts/AEAD) | Up to 64x fewer AEAD operations |
| Compact frame header (down from 16) | Reduced per-packet overhead |
| QUIC handshake + raw UDP data | Eliminates double encryption |
| TLS 1.3 key exchange | Certificate auth, 0-RTT, native PQ |
| QUIC retry tokens | Replaces MAC1/MAC2/cookie system |

### What We Lose

| Loss | Mitigation |
|------|------------|
| Interop with standard WireGuard clients | `legacy-wireguard` feature flag; users run IronGuard on both ends |
| WireGuard's formal verification | TLS 1.3 via rustls is audited (Cure53, Alpha-Omega); AES-256-GCM is NIST/FIPS validated |
| `wg(8)` CLI compatibility | IronGuard has its own CLI (`ironguard status` etc.) |
| PSK authentication model | Replaced by certificate-based mutual TLS (more flexible) |

---

## 3. Pipeline Architecture

### 3-Stage Decoupled Pipeline

Replace the current hybrid architecture (OS threads + `block_on_io`) with a fully decoupled, 3-stage pipeline where no stage ever blocks on another stage's I/O.

```
                    RECEIVE PATH (download)

 ┌────────────┐   batch    ┌─────────────┐   batch    ┌────────────┐
 | UDP Reader |----------> | Crypto Pool |----------> | TUN Writer |
 | (async)    |  Vec<Ref>  | (OS threads)|  Vec<Ref>  | (async)    |
 | recvmmsg   |            | AES-256-GCM |            | GSO/GRO    |
 +------------+            | pure compute|            +------------+
                           +-------------+

                    SEND PATH (upload)

 ┌────────────┐   batch    ┌─────────────┐   batch    ┌────────────┐
 | TUN Reader |----------> | Crypto Pool |----------> | UDP Writer |
 | (async)    |  Vec<Ref>  | (OS threads)|  Vec<Ref>  | (async)    |
 | GSO/GRO    |            | AES-256-GCM |            | sendmmsg   |
 +------------+            | pure compute|            +------------+
                           +-------------+
```

### Stage Responsibilities

**Stage 1: I/O Readers (async Tokio tasks)**
- Read from TUN/UDP into pre-allocated pool buffers
- Assign per-peer sequence numbers
- Batch packets (16-64 per channel send)
- Never block, never touch crypto

**Stage 2: Crypto Pool (dedicated OS threads)**
- Decrypt/encrypt via `ring::aead::AES_256_GCM`
- Pure compute: zero I/O, zero async, zero blocking
- Receives and emits `Vec<PacketRef>` batches
- `num_cpus` workers on `crossbeam_channel` (same as current, minus the I/O)

**Stage 3: I/O Writers (async Tokio tasks)**
- Consume encrypted/decrypted packets from bounded channel
- Per-peer reorder buffer for in-order TUN delivery
- Handle backpressure with per-peer tail-drop (newest packets dropped first for the most-active peer, preserving fairness). Control/keepalive frames bypass the data queue and are never dropped.
- Never touch crypto keys

### Key Invariants

- No stage ever blocks waiting on another stage's I/O
- Bounded channels between every stage (backpressure = drop, not block)
- Crypto workers never touch file descriptors
- I/O tasks never touch crypto keys
- Each stage scales independently

---

## 4. IronGuard v2 Protocol Specification

### 4.1 Handshake: QUIC/TLS 1.3

A dedicated QUIC connection (via quinn/rustls) handles authentication, cipher negotiation, and key derivation.

```
Client --- QUIC Initial (ClientHello) ---------> Server
  - cipher suites: AES_256_GCM, CHACHA20_POLY1305
  - key_share: X25519 + ML-KEM-768 (hybrid PQ)
  - ALPN: "ironguard/1"
  - client certificate (if mutual auth)

Client <-- QUIC Handshake (ServerHello) --------- Server
  - selected cipher: AES_256_GCM
  - server certificate
  - NewSessionTicket (for 0-RTT)

Client --- DataPlaneInit { data_port, session_id, receiver_id } --->
Client <-- DataPlaneAck  { data_port, session_id, receiver_id } ----

=== Raw UDP data plane active (AES-256-GCM) ===

QUIC connection stays alive for: rekey, keepalive, migration, control
```

### 4.2 Key Derivation

Roles are explicit: the TLS client and server derive directional keys using role-specific labels to prevent both sides encrypting with the same key.

```
exporter_secret = TLS-Exporter("ironguard/data-keys/v1", "", 64)

// Client derives:
client_send_key = HKDF-Expand(exporter_secret, "ironguard-client-to-server", 32)
client_recv_key = HKDF-Expand(exporter_secret, "ironguard-server-to-client", 32)

// Server derives (reversed):
server_send_key = HKDF-Expand(exporter_secret, "ironguard-server-to-client", 32)
server_recv_key = HKDF-Expand(exporter_secret, "ironguard-client-to-server", 32)
```

Each side's send_key equals the other side's recv_key. The labels are role-specific to prevent nonce reuse if both sides happen to start counters at zero.

### 4.3 Key Rotation

**Important:** TLS 1.3 exporter secrets are fixed for the lifetime of a connection — `TLS-Exporter()` returns the same value regardless of `KeyUpdate`. Therefore, key rotation CANNOT use `KeyUpdate` to derive fresh data-plane keys.

**Rekey mechanism: Epoch-based rotation via QUIC control messages.**

Each rekey epoch introduces fresh entropy and new receiver IDs:

```
Initiator ---[QUIC DATAGRAM: RekeyInit {
    epoch: u32,                    // monotonic epoch counter
    fresh_entropy: [u8; 32],       // random nonce for this epoch
    new_receiver_id: u32,          // receiver ID for new decryption state
}]---> Responder

Responder ---[QUIC DATAGRAM: RekeyAck {
    epoch: u32,
    fresh_entropy: [u8; 32],
    new_receiver_id: u32,
}]---> Initiator
```

**Key derivation for epoch N:**

```
epoch_secret = HKDF-Expand(
    exporter_secret,
    "ironguard-epoch" || epoch.to_le_bytes() || initiator_entropy || responder_entropy,
    64
)

// Directional keys (same role-specific label pattern as initial keys)
client_send_key_N = HKDF-Expand(epoch_secret, "ironguard-client-to-server", 32)
client_recv_key_N = HKDF-Expand(epoch_secret, "ironguard-server-to-client", 32)
```

Each epoch produces provably different keys because `fresh_entropy` from both sides is mixed in. Counters reset to zero per epoch (safe because each epoch has unique keys).

**Receiver ID lifecycle per rekey:**

1. `RekeyInit` carries the initiator's new `receiver_id` for the next epoch
2. `RekeyAck` carries the responder's new `receiver_id`
3. Both sides install the new keypair as `KeyWheel.next`
4. On first authenticated packet received with the new key, `confirm_key()` promotes `next -> current -> previous`
5. Previous receiver IDs are retired after a grace period (2x rekey interval)

| Trigger | Action |
|---------|--------|
| 120 seconds elapsed | Send RekeyInit with fresh entropy + new receiver ID |
| 2^63 packets sent | Same (conservative counter exhaustion backstop) |
| 2^60 bytes encrypted | Same (AES-GCM safety limit per NIST SP 800-38D) |
| Connection migration | See Section 4.3.2 |

The existing `KeyWheel` (next/current/previous) is retained. The `REJECT_AFTER_MESSAGES` constant is set to `2^63 - 1024`.

### 4.3.2 Raw UDP Data-Plane Migration

In handshake-only mode, QUIC migration only covers the control connection. The raw UDP data plane uses a separate 5-tuple that must be migrated independently.

**Migration flow:**

1. When the QUIC control connection migrates (NAT rebind, IP change), the migrating side detects the new source address via `conn.remote_address()` changes
2. The migrating side sends an authenticated QUIC DATAGRAM: `MigrationProbe { data_port, challenge: [u8; 16] }`
3. The other side responds with `MigrationAck { challenge_response, new_data_endpoint }` via QUIC
4. On receiving `MigrationAck`, the migrating side switches its raw UDP send path to the new endpoint
5. The other side accepts raw UDP packets from the new source address only after validating the probe/ack exchange

**Rollback:** If `MigrationAck` is not received within 5 seconds, the old data-plane endpoint is retained. The control channel (QUIC) continues working regardless.

**Existing WireGuard roaming behavior is preserved:** When a valid authenticated data-plane packet arrives from a new source address, `PeerInner.endpoint` is updated opportunistically (same as WireGuard). The probe/ack exchange provides explicit migration; the roaming update provides implicit migration for cases where only the data-plane path changes.

### 4.3.1 0-RTT Resumption Security

TLS 1.3 0-RTT data is susceptible to replay attacks. IronGuard handles this as follows:

- **0-RTT is used for control messages only** (DataPlaneInit/DataPlaneAck), not for data-plane traffic
- Data-plane keys are derived after full handshake completion (1-RTT), never from early data secrets
- The QUIC-level retry token provides address validation during 0-RTT
- The anti-replay bitmap is reset on new session establishment (new exporter = new keys = fresh bitmap)
- If 0-RTT is replayed, the worst case is a duplicate DataPlaneInit, which the server discards (idempotent)

### 4.4 Frame Format

#### Single-Packet Frame (16-byte header)

The header retains 32-bit receiver IDs (preventing collision at scale) and 64-bit counters (preventing nonce reuse risk). The type field is compacted from WireGuard's 32-bit to 8-bit, adding a flags byte.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type (8)  |    Flags (8)  |         Reserved (16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Receiver ID (32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Counter (64)                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Encrypted Payload (variable)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      AEAD Tag (128 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Bits | Description |
|-------|------|-------------|
| Type | 8 | `0x01` data, `0x02` keepalive, `0x03` control, `0x04` batch |
| Flags | 8 | `0x01` compressed (reserved for future) |
| Reserved | 16 | Must be zero, available for future extensions |
| Receiver ID | 32 | Peer lookup via DashMap (collision-safe at any scale) |
| Counter | 64 | Nonce / anti-replay sequence (matches existing anti-replay bitmap) |

**Nonce construction:** 12 bytes = `[0x00; 4] || counter.to_le_bytes()`

**AEAD Additional Authenticated Data (AAD):** The entire 16-byte header is passed as AAD to `AES_256_GCM.seal_in_place()` / `open_in_place()`. This binds the type, flags, receiver ID, and counter to the ciphertext, preventing header tampering without tag invalidation.

The nonce uses only the counter, not the session_id. Each key is unique (derived from a unique TLS exporter), so counter uniqueness within a key lifetime guarantees nonce uniqueness. This matches the standard AES-GCM nonce construction pattern.

**Why 32-bit receiver ID (not 16-bit):** With 3 active receiver IDs per peer (KeyWheel next/current/previous), 1000 peers = 3000 IDs. At 16 bits (65K space), collision probability per new ID is ~4.5%. At 32 bits (4B space), it is negligible.

**Why 64-bit counter (not 32-bit):** AES-GCM has catastrophic nonce reuse properties. A 32-bit counter wraps after 4B packets, which at 10 Gbps (~833K pps) is only ~86 minutes. While rekey happens at 120s, a race between counter exhaustion and rekey completion could produce nonce reuse. A 64-bit counter eliminates this risk entirely.

#### Batch Frame (20-byte header)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type=0x04   |    Flags (8)  |         Reserved (16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Receiver ID (32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Counter (64)                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Batch Count (16)        |     Total Payload Len (16)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  AEAD(key, nonce,                                             |
|    aad = full 20-byte header (type..batch_count..total_len),  |
|    plaintext = [pkt1_len:u16|pkt1_data|pkt2_len:u16|pkt2|...] |
|  )                                                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      AEAD Tag (128 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Important: Batching is a syscall optimization, NOT a wire-format change.**

UDP GSO segments a large send into multiple independent UDP datagrams on the wire. The receiver cannot reliably reassemble them into one ciphertext. Therefore:

- **Each UDP datagram on the wire contains exactly one AEAD-authenticated message** (single-packet frame OR a small batch that fits in one datagram)
- **Batching amortizes syscall overhead, not crypto overhead.** Multiple independently-encrypted frames are gathered into a single `sendmmsg`/GSO syscall
- The batch frame format above is used ONLY when the entire batch fits within a single UDP datagram (max ~1400 bytes without jumbo frames — typically 1 packet)
- For the common case (1400+ byte packets), each packet is individually encrypted with its own AEAD tag and sent as a separate datagram within a batched syscall

**Syscall batching (primary optimization):**

```
// Stage 3 (UDP Writer) gathers N independently-encrypted frames:
let frames: Vec<&[u8]> = batch.iter().map(|ref| pool.get(ref)).collect();
sendmmsg(socket, &frames);  // one syscall, N datagrams
```

**Wire-format batching (small packets only):**

The batch frame format is used when multiple small inner packets (e.g., ACKs, DNS queries < 200 bytes each) can fit in a single ~1400-byte datagram. This amortizes both the AEAD tag (16 bytes) and frame header (16 bytes) per batch. The batch frame MUST fit within a single UDP datagram (no reassembly protocol).

**Loss amplification:** A single corrupted bit in a wire-format batch frame drops all packets in that batch. On lossy links, disable wire-format batching. Recommended: `wire_batch = false` when measured loss > 0.1%. Syscall batching (sendmmsg/GSO) is always safe since each datagram is independently authenticated.

**Batching heuristic:**
1. Accumulate packets for up to `BATCH_FLUSH_TIMEOUT` (default 50us)
2. Flush when: buffer reaches max batch payload size, or 64 packets, or timeout expires
3. Single packets sent as non-batched frames (no wasted overhead)
4. Auto mode: per-packet at low rates, batched above 100 Kpps

### 4.5 Post-Quantum

X25519 + ML-KEM-768 hybrid via TLS 1.3 `key_share` extension. Negotiated automatically by rustls with `aws-lc-rs` backend. No custom PQ code. Defense-in-depth: if either primitive breaks, the other provides security.

### 4.6 DoS Mitigation

QUIC retry tokens (RFC 9000 Section 8.1) replace WireGuard's MAC1/MAC2/cookie mechanism. The QUIC stack handles address validation, amplification attack prevention, and connection-level rate limiting.

---

## 5. Buffer Pool

### Design

Pre-allocated fixed-size buffer pool eliminates all per-packet heap allocation.

```rust
// Two-tier buffer pool: small buffers for individual packets, large for batch assembly
const SMALL_POOL_SIZE: usize = 8192;
const SMALL_BUF_SIZE: usize = 2048;    // MTU + headers + AEAD tag + padding

const LARGE_POOL_SIZE: usize = 128;
const LARGE_BUF_SIZE: usize = 65536;   // max UDP GSO segment / batch assembly

struct PacketRef {               // 8 bytes, passed by value
    pool_idx: u16,               // which buffer (0..8191 small, 8192+ large)
    offset: u16,                 // data start within buffer
    len: u16,                    // data length
    peer_idx: u16,               // peer for routing/ordering
}

struct BufferPool {
    small: Box<[UnsafeCell<[u8; SMALL_BUF_SIZE]>; SMALL_POOL_SIZE]>,  // ~16 MB
    large: Box<[UnsafeCell<[u8; LARGE_BUF_SIZE]>; LARGE_POOL_SIZE]>,  // ~8 MB
    small_free: crossbeam_queue::ArrayQueue<u16>,
    large_free: crossbeam_queue::ArrayQueue<u16>,
}
```

Individual packets use small buffers. Batch frame assembly and GRO super-packet reception use large buffers. The `pool_idx` range distinguishes the tier: `0..SMALL_POOL_SIZE` for small, `SMALL_POOL_SIZE..` for large.

### Operations

| Operation | Cost | Mechanism |
|-----------|------|-----------|
| `alloc()` | ~10ns | Pop from lock-free ArrayQueue |
| `free(idx)` | ~10ns | Push to lock-free ArrayQueue |
| `get(idx)` | 0ns | Index arithmetic, direct pointer |

### Safety Invariants

The pool uses `UnsafeCell` for interior mutability. Safety is guaranteed by these invariants:

1. **Exclusive ownership:** Each buffer index is either in the free list OR in a live `PacketRef`, never both. The `ArrayQueue` enforces this (pop removes, push adds).
2. **No Clone/Copy on PacketRef:** `PacketRef` is move-only. A `PacketGuard` wrapper auto-returns the index to the free list on drop, preventing leaks.
3. **Bounds checking:** `pool_idx` is always in `0..POOL_SIZE`. The `alloc()` function only returns indices that were originally placed in the free list during initialization.
4. **No aliasing:** Only one stage holds a `PacketRef` for a given buffer at any time. The channel transfer moves ownership between stages.

```rust
struct PacketGuard<'a> {
    pref: PacketRef,
    pool: &'a BufferPool,
}

impl Drop for PacketGuard<'_> {
    fn drop(&mut self) {
        self.pool.free(self.pref.pool_idx);
    }
}
```

### Backpressure

Pool exhaustion = natural backpressure. When `alloc()` returns `None`, the reader drops the incoming packet. TCP retransmits. No blocking, no unbounded queuing.

---

## 6. Platform I/O

### Linux (highest throughput ceiling)

| Feature | Mechanism | Impact |
|---------|-----------|--------|
| Multi-queue TUN | `tun-rs` multiple fds per device | N reader tasks (1 per core) |
| GSO/GRO | `IFF_VNET_HDR`, `recv_multiple`/`send_multiple` | 2.2x throughput (Tailscale data) |
| sendmmsg/recvmmsg | Batch up to 64 datagrams per syscall | 25% additional |
| UDP GSO | `UDP_SEGMENT` sockopt | One syscall for 64KB of datagrams |
| Split TUN fds | `dup()` for read vs write | No readiness contention |

### macOS (limited by utun API)

| Feature | Mechanism | Impact |
|---------|-----------|--------|
| Split AsyncFd | `dup()` for read vs write | Fixes readiness contention |
| utun buffer tuning | `net.local.dgram.recvspace=262144` | Fixes immediate 0 Mbps stall |
| Buffer pool | Same as Linux | Eliminates per-packet alloc |
| Batched crypto dispatch | Accumulate 16-64 packets | Reduces channel overhead |
| Tight-loop TUN write | Drain channel without yielding | Reduces context switches |

**Realistic macOS ceiling: 1-3 Gbps** (per-packet syscall is the fundamental limit).

### Transport Abstraction

```rust
pub trait TransportIO: Send + Sync + 'static {
    type Error: Error;
    async fn recv_batch(
        &self, pool: &BufferPool, batch: &mut Vec<PacketRef>, max: usize,
    ) -> Result<usize, Self::Error>;
    async fn send_batch(
        &self, pool: &BufferPool, batch: &[PacketRef],
    ) -> Result<usize, Self::Error>;
}
```

Implementations: `UdpBatchIO` (sendmmsg/recvmmsg, GSO), `QuicBatchIO` (individual datagram calls via quinn).

### Runtime Capability Detection

```rust
pub struct PlatformCapabilities {
    pub tun_multi_queue: bool,     // Linux: yes, macOS: no
    pub tun_gso_gro: bool,        // Linux 6.2+: yes, macOS: no
    pub udp_sendmmsg: bool,       // Linux: yes, macOS: no
    pub udp_gso: bool,            // Linux 4.18+: yes, macOS: no
    pub max_tun_queues: usize,    // Linux: num_cpus, macOS: 1
}
```

Pipeline adapts at startup based on detected capabilities, not compile-time flags.

---

## 7. QUIC Integration

### Dual Role

QUIC serves two purposes, selectable per deployment:

**Mode 1: Handshake-only (default)**
- QUIC establishes the TLS 1.3 session and derives data-plane keys
- Data flows over raw UDP with IronGuard framing
- QUIC connection stays alive for rekey, keepalive, migration, control
- Maximum throughput: 5-10+ Gbps (no QUIC overhead on data path)

**Mode 2: Full QUIC transport (firewall bypass)**
- All traffic flows through QUIC unreliable datagrams
- Single encryption layer (QUIC TLS, no IronGuard AEAD on top)
- DPI evasion: configurable SNI, ALPN="h3", real certificates
- Maximum throughput: 1-3 Gbps (quinn per-packet processing ceiling)

### QUIC-Specific Config

```rust
pub struct QuicConfig {
    pub relay_addr: SocketAddr,
    pub port: u16,
    pub mode: QuicMode,                // HandshakeOnly | FullTransport
    pub sni: Option<String>,           // default: server hostname
    pub alpn: Option<String>,          // default: "ironguard/1", or "h3" for DPI evasion
    pub cert_path: Option<PathBuf>,    // real cert for DPI evasion
    pub key_path: Option<PathBuf>,
    pub datagram_only: bool,           // disable stream fallback
}
```

### Buffer Integration

Copy boundary at QUIC edge is accepted. One memcpy per packet (~1400 bytes) at 1 Mpps = 1.4 GB/s, negligible vs quinn's internal overhead.

---

## 8. Per-Peer Ordering and Anti-Replay

### Reorder Buffer in Writer Task

```
Crypto Pool (parallel, unordered)
         |
    Vec<PacketRef> with per-peer sequence numbers
         |
    ┌────┴─────┐
    | Reorder  |  (per-peer, in writer task)
    | Buffer   |
    └────┬─────┘
         |
    In-order delivery to TUN
```

1. Stage 1 assigns monotonic per-peer sequence numbers before dispatching to crypto
2. Stage 2 processes packets in any order, preserves sequence in PacketRef
3. **On auth failure or anti-replay rejection, Stage 2 emits an explicit `DropMarker { peer_idx, seq }` to Stage 3** so the reorder buffer can skip that slot instead of waiting indefinitely
4. Stage 3 maintains per-peer `ReorderBuffer` (BTreeMap, max window 256)
5. The reorder buffer drains contiguous runs: when the next expected seq arrives (or a DropMarker for it), it advances and delivers all ready packets

Anti-replay bitmap checked during decrypt (Stage 2), before reorder buffer. Failed packets emit DropMarkers rather than being silently dropped, preventing permanent holes in the sequence.

**Timeout fallback:** If a sequence slot is neither filled nor explicitly dropped within 50ms, the reorder buffer skips it (covers the case where a DropMarker is lost due to channel backpressure).

---

## 9. MTU Alignment

IronGuard v2 overhead per encapsulated packet:

```
IPv4 outer:
  IP header:           20 bytes
  UDP header:            8 bytes
  IronGuard header:     16 bytes
  AEAD tag:             16 bytes
  Total overhead:       60 bytes
  Effective MTU = 1500 - 60 = 1440

IPv6 outer:
  IP header:           40 bytes
  UDP header:            8 bytes
  IronGuard header:     16 bytes
  AEAD tag:             16 bytes
  Total overhead:       80 bytes
  Effective MTU = 1500 - 80 = 1420
```

Set TUN MTU to **1420** (conservative, covers both IPv4 and IPv6 outer headers). This matches WireGuard's established default. Verify with `SIOCGIFMTU` ioctl after creation. Log a warning if the kernel reports a different MTU than requested.

---

## 10. Timer Tuning

Adaptive tick rate:

| Peer State | Tick Interval | Timers Checked |
|-----------|---------------|----------------|
| Active (recent data) | 100ms | retransmit_handshake, zero_key_material |
| Idle (no recent data) | 1s | All 5 timers |

Use `tokio::time::interval` with `MissedTickBehavior::Skip`.

### Keepalive Interaction with QUIC

| Mode | Data-plane keepalive | QUIC keepalive |
|------|---------------------|----------------|
| Handshake-only (default) | IronGuard timers on raw UDP data plane | QUIC idle timeout = 300s (control channel only) |
| Full QUIC transport | Disabled (QUIC handles it) | QUIC keepalive = `persistent_keepalive` value |

In handshake-only mode, the QUIC connection is a control channel with a long idle timeout. The raw UDP data plane uses IronGuard's own keepalive timers. In full QUIC mode, all keepalive is delegated to QUIC's built-in mechanism.

---

## 11. Workspace Changes

### New Module Structure

```
ironguard-core/src/
  session/              (NEW: replaces handshake/)
    quic.rs             QUIC endpoint, TLS config, connection management
    keys.rs             TLS exporter -> data-plane key derivation
    state.rs            Per-peer session state machine
    mod.rs
  router/               (REVISED)
    send.rs             AES-256-GCM, new frame format, batch path
    receive.rs          AES-256-GCM, new frame format, batch path
    batch.rs            (NEW) Batch accumulator and frame codec
    messages.rs         (REVISED) New frame header with type/flags fields
    device.rs           (REVISED) No block_on_io, channel-based I/O
    worker.rs           (REVISED) Pure compute, no I/O
    peer.rs             (UNCHANGED) KeyWheel still works
    anti_replay.rs      (UNCHANGED) RFC 6479 bitmap
    route.rs            (UNCHANGED) treebitmap LPM
    queue.rs            (UNCHANGED) parallel/sequential queue
  pipeline/             (NEW)
    pool.rs             Buffer pool with lock-free free list
    io.rs               TransportIO trait and implementations
    reorder.rs          Per-peer reorder buffer
    mod.rs
  workers.rs            (REVISED) Batch-aware, uses pipeline
  device.rs             (REVISED) QUIC session instead of handshake device
  timers.rs             (MINOR) Adaptive tick rate
  constants.rs          (REVISED) New header sizes, batch constants
```

### Deleted Modules (~900 lines)

```
handshake/noise.rs      -> replaced by session/quic.rs
handshake/macs.rs       -> replaced by QUIC retry tokens
handshake/messages.rs   -> replaced by new frame format
handshake/peer.rs       -> replaced by session/state.rs
handshake/device.rs     -> replaced by session/quic.rs
handshake/pq.rs         -> native TLS PQ (zero custom code)
handshake/timestamp.rs  -> not needed (QUIC handles timing)
handshake/ratelimiter.rs -> replaced by QUIC retry tokens
```

### Dependency Changes

**Removed:** `snow`, `chacha20poly1305`, `blake2s_simd`, `blake2b_simd`
**Retained:** `ring` (AES-256-GCM), `quinn`, `rustls`, `x25519-dalek`, `zeroize`, `subtle`, `dashmap`, `treebitmap`, `spin`, `parking_lot`
**No new crates needed** (ring, quinn, rustls already in workspace)

---

## 12. Testing Strategy

### Unit/Integration Tests

| Test | What It Validates |
|------|-------------------|
| Buffer pool alloc/free | Correctness, no double-free, no leak |
| Frame codec round-trip | Encode -> decode for single and batch frames |
| AES-256-GCM encrypt/decrypt | Correctness with test vectors |
| Reorder buffer | In-order delivery, window overflow, gap handling |
| Anti-replay | Bitmap correctness (existing tests, unchanged) |
| Crypto-key routing | LPM correctness (existing tests, unchanged) |
| QUIC handshake | Key derivation, session establishment, 0-RTT |
| Full pipeline (dummy backend) | End-to-end via DummyTransportIO |

### Benchmark Suite (Criterion)

| Benchmark | Target |
|-----------|--------|
| `bench_buffer_pool` | < 20ns alloc/free cycle |
| `bench_aes_gcm_1500` | < 200ns per packet |
| `bench_batch_encrypt_64` | < 10us for 64 packets |
| `bench_pipeline_throughput` | > 5 Gbps via dummy |
| `bench_reorder_buffer` | < 5us for 64 packets |
| `bench_frame_codec` | < 100ns encode/decode |

### Integration (Real Network)

- Loopback iperf3 with real TUN (requires root)
- Bidirectional throughput (must verify download direction works)
- Sustained 10s stress test at max rate
- QUIC mode: verify 1+ Gbps
- Release build benchmarks at each phase

---

## 13. Implementation Phases

### Phase 1: AES-256-GCM + Buffer Pool

- Swap `CHACHA20_POLY1305` -> `AES_256_GCM` in send.rs/receive.rs
- Implement `BufferPool` with lock-free free list and `PacketGuard` RAII wrapper
- Add Criterion benchmarks
- **Note:** This immediately breaks WireGuard wire compatibility. Both endpoints must run IronGuard v2. The `legacy-wireguard` feature flag retains ChaCha20-Poly1305 in a parallel code path.
- Update `SIZE_MESSAGE_PREFIX` from 64 to match new frame header requirements
- **Gate:** 2-3x throughput improvement in crypto benchmarks

### Phase 2: 3-Stage Pipeline

- New `pipeline/` module (pool.rs, io.rs, reorder.rs)
- Replace `block_on_io` with channel-based I/O dispatch
- Dedicated TUN writer task, dedicated UDP writer task
- Crypto workers become pure compute
- **Gate:** Download path works, bidirectional throughput confirmed

### Phase 3: New Frame Format + Batching

- Implement new frame header with type/flags/receiver_id/counter (messages.rs)
- Batch frame codec (batch.rs)
- Batch accumulator in TUN reader
- Batch dispatch over channels
- **Gate:** Batch encryption benchmark shows 10x+ improvement

### Phase 4: QUIC Handshake + Session Module

- New `session/` module replaces `handshake/`
- QUIC-based key derivation (TLS exporter -> KeyWheel)
- DataPlaneInit/DataPlaneAck protocol
- Certificate auth, 0-RTT resumption
- Delete old handshake modules
- **Gate:** Successful handshake + data transfer with new protocol

### Phase 5: Platform I/O Optimization

- Linux: multi-queue TUN, GSO/GRO, sendmmsg/recvmmsg, UDP GSO
- macOS: split AsyncFd, utun buffer tuning
- Runtime capability detection
- **Gate:** 5+ Gbps on Linux, 1+ Gbps on macOS (release build)

### Phase 6: Polish + Tune

- MTU alignment (set TUN to 1420, verify with ioctl)
- Adaptive timer tick (100ms active, 1s idle)
- Profiling: flamegraph, perf stat on iperf3 runs
- Release build benchmarks for all configurations
- **Gate:** No regressions, all benchmarks green
