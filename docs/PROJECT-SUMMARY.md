# IronGuard Project Summary

## Overview

IronGuard is a modern, cross-platform WireGuard implementation in pure Rust (edition 2024). It implements the full WireGuard protocol with a v2 high-performance pipeline, optional QUIC-based session management, and post-quantum key exchange (ML-KEM-768).

**Codebase:** ~15,750 lines of Rust across 4 workspace crates
**Tests:** 173 passing (with `--features quic`), 0 failures
**Commits:** 37 (since initial scaffold)

## Architecture

```
ironguard-platform  (OS abstractions -- no protocol logic)
       |
ironguard-core      (pure WireGuard protocol -- generic over platform traits)
       |
ironguard-config    (JSON/conf parsing -- no runtime dependencies)
       |
ironguard-cli       (binary -- wires everything together)
```

### Platform Layer (`ironguard-platform`)

| Module | Status | Notes |
|--------|--------|-------|
| macOS (utun) | Working | Split AsyncFd via `dup()`, 262KB recv buffer tuning |
| Linux (tun-rs) | Working | Multi-queue TUN, GSO/GRO batch I/O (`send_multiple`/`recv_multiple`) |
| Linux (UDP) | Working | `sendmmsg`/`recvmmsg` batch I/O, `SO_MARK` support |
| Dummy | Working | In-memory stubs for full-stack testing without sockets |
| QUIC transport | Working | quinn-based, full transport or handshake-only modes |
| Capabilities | Working | Runtime detection of GSO/GRO, sendmmsg, multi-queue, kernel version |

### Core Protocol (`ironguard-core`)

| Component | Status | Notes |
|-----------|--------|-------|
| WireGuard device | Working | Generic over `T: Tun` and `B: Udp`, no OS dependencies |
| Noise handshake | Working | Noise_IKpsk2 via `snow`, gated behind `legacy-wireguard` feature |
| Router | Working | Crypto-key routing with `treebitmap` LPM (IPv4 + IPv6) |
| AES-256-GCM | Working | Default cipher, 2.5-3.6x faster than ChaCha20 on modern CPUs |
| v2 Frame Header | Working | 16-byte header: Type/Flags/Reserved/ReceiverID/Counter |
| Buffer Pool | Working | Two-tier pre-allocated (8192 x 2KB + 128 x 64KB), lock-free free lists |
| Batch Accumulator | Working | Flush on count (64), size (64KB), or timeout (50us) |
| Reorder Buffer | Working | Per-peer BTreeMap with window size 256, DropMarker support |
| TransportIO trait | Working | Abstracts batch send/receive for UDP and QUIC |
| Pipeline integration | Working | BufferPool wired into workers, BatchAccumulator in write paths |
| Frame type handling | Working | TYPE_DATA, TYPE_KEEPALIVE, TYPE_CONTROL (logged), TYPE_BATCH (split) |
| Timers | Working | 5 deadline-based timers per peer, adaptive tick (100ms/1s) |
| Anti-replay | Working | RFC 6479 sliding window bitmap |
| DoS mitigation | Working | MAC1/MAC2/cookie, per-IP token bucket rate limiter |
| Post-quantum | Working | ML-KEM-768 hybrid key exchange (`pq` feature) |

### Session Management (`ironguard-core/session`)

| Component | Status | Notes |
|-----------|--------|-------|
| Key derivation | Working | HKDF-SHA256, directional labels, epoch-based rekeying |
| State machine | Working | Idle/Stable/Rekeying/Migrating with constant-time verification |
| QUIC handshake | Working | TLS 1.3 via quinn, DataPlaneInit/Ack datagrams |
| SessionManager | Working | Arc-safe with interior mutability, per-peer sessions |
| Accept loop | Working | Background task for inbound QUIC connections |
| Rekey timer | Working | 30s check interval, 120s rekey threshold |
| Wildcard peers | Working | Server-side peers without endpoints accept from any IP |
| Connect timeout | Working | 5-second QUIC handshake timeout |

### CLI Commands

| Command | Status | Notes |
|---------|--------|-------|
| `up` | Working (macOS) | Legacy WireGuard with Noise handshake |
| `up-v2` | Working (macOS + Linux) | QUIC session + raw UDP data plane |
| `down` | Working | PID file + SIGTERM |
| `status` | Working | Config-based status display |
| `genkey` / `pubkey` / `genpsk` | Working | X25519 key operations |
| `pq-genkey` / `pq-pubkey` | Working | ML-KEM-768 key operations (requires `pq` feature) |
| `validate` | Working | Semantic config validation |
| `import` / `export` | Working | WireGuard `.conf` <-> `wg.json` bidirectional |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `legacy-wireguard` | Yes | Classic Noise_IKpsk2 handshake via `snow` |
| `quic` | No | QUIC transport, SessionManager, accept loop, rekey timer |
| `pq` | No | Post-quantum ML-KEM-768 hybrid key exchange |

## Build & Test

```bash
cargo build --workspace                          # Default (legacy handshake)
cargo build --workspace --features quic           # With QUIC sessions
cargo test --workspace --features quic            # 173 tests
cargo clippy --workspace --features quic -- -D warnings  # Zero warnings
```

## Linux-Specific Capabilities

Tested on Ubuntu 25.10, kernel 6.17, 20 cores:

- TUN device creation (multi-queue shared fd)
- GSO/GRO batch TUN I/O via `tun-rs` `send_multiple`/`recv_multiple`
- `sendmmsg`/`recvmmsg` batch UDP I/O
- `IFF_VNET_HDR` offload detection via `TUNGETIFF` ioctl
- Kernel version detection for GSO/GRO support (requires 6.2+)
- All 4 privileged TUN tests passing as root

## v2 Performance Design

The v2 pipeline targets 5-10+ Gbps on Linux and 1-3 Gbps on macOS:

1. **IO Reader** (async) -- reads packets from TUN/UDP using pool-allocated buffers
2. **Crypto** -- AES-256-GCM encrypt/decrypt (2.5-3.6x faster than ChaCha20)
3. **IO Writer** (async) -- batches outgoing packets via BatchAccumulator before syscall

Key optimizations:
- Pre-allocated two-tier buffer pool eliminates per-packet allocation
- Batch I/O amortizes syscall overhead (sendmmsg, GSO/GRO)
- Epoch-based rekey via QUIC control messages (no double encryption)
- Adaptive timer ticks reduce CPU wake-ups at idle

## Remaining Work

### Production Readiness
- [ ] End-to-end iperf3 benchmarks on real hardware (tunnel established, data plane needs debugging)
- [ ] True `IFF_MULTI_QUEUE` TUN (currently shared-fd emulation)
- [ ] Daemonize support (currently foreground-only)
- [ ] Linux `cmd_up` for legacy WireGuard path (currently macOS-only)

### Tunnel Debugging (in progress)
- QUIC session establishment: **working** (client connects, server accepts, keys installed)
- Data plane packet flow: **needs debugging** (encrypted packets not yet flowing through tunnel)
- Root cause likely: key agreement mismatch between client/server roles or endpoint routing

## Spec & Plan Documents

- Design spec: `docs/superpowers/specs/2026-03-23-ironguard-v2-performance-overhaul-design.md`
- Implementation plan: `docs/superpowers/plans/2026-03-23-ironguard-v2-performance-overhaul.md`
