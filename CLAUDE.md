# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IronGuard is a modern, cross-platform WireGuard implementation in pure Rust (edition 2024). It implements crypto-key routing, anti-replay, per-peer timers with a v2 high-performance pipeline (AES-256-GCM AEAD), QUIC-based session management for key exchange, and post-quantum key exchange (ML-KEM-768). IronGuard uses its own QUIC-based protocol for session establishment and rekeying.

Currently supports macOS (utun via tun-rs). Linux planned. Requires Rust 1.85+.

## Build & Test

```bash
cargo build --workspace                                        # Default build (includes QUIC)
cargo build --workspace --no-default-features                  # Minimal (v2 core only, no QUIC)
cargo test --workspace                                         # Run all tests
cargo test -p ironguard-core                                   # Single crate
cargo test -p ironguard-core router::tests                     # Single test module
cargo clippy --workspace -- -D warnings                        # Lint (CI treats warnings as errors)
cargo fmt --all -- --check                                     # Format check
```

### Feature Flags

| Flag | Crate | Description |
|------|-------|-------------|
| `quic` | `ironguard-core`, `ironguard-platform` | **Default.** QUIC transport (quinn) and QUIC-based session management (`session::manager`, `session::quic`). |
| `pq` | `ironguard-core` | Post-quantum ML-KEM-768 hybrid key exchange. |

## Workspace Structure

Four crates, layered bottom-up:

```
ironguard-platform  (OS abstractions — no protocol logic)
       |
ironguard-core      (pure WireGuard protocol — generic over platform traits)
       |
ironguard-config    (JSON/conf parsing — no runtime dependencies)
       |
ironguard-cli       (binary — wires everything together)
```

## Architecture

### Platform Layer (`ironguard-platform`)

Three async trait families abstract all OS I/O:

- **`Tun`** (`tun.rs`) — `Reader` (read IP packets with offset), `Writer` (write decrypted packets), `Status` (up/down events). `PlatformTun::create(name)` returns `(Vec<Reader>, Writer, Status)`.
- **`Udp`** (`udp.rs`) — `UdpReader` (read datagrams + endpoint), `UdpWriter` (write to endpoint). `PlatformUdp::bind(port)` returns `(Vec<Reader>, Writer, Owner)`.
- **`Endpoint`** (`endpoint.rs`) — `from_address` / `to_address` / `clear_src`. Carried through the stack to track peer addresses.
- **`PlatformCapabilities`** (`capabilities.rs`) — runtime-detected I/O capabilities (sendmmsg, GSO/GRO, multi-queue TUN) used by the pipeline to select optimal code paths.

- **`NetworkManager`** (`network_manager.rs`) -- trait for OS-level network configuration: address assignment, route installation, masquerade NAT, and post_up/post_down hook execution. Implementations in `macos/`, `linux/`, and `dummy/`.

Implementations: `macos/` (real utun + UDP sockets + pfctl NAT), `linux/` (TUN + iptables NAT), `dummy/` (in-memory for testing), `quic.rs` (QUIC transport behind `quic` feature).

The dummy backend enables full-stack protocol testing without root or real sockets.

### WireGuard Core (`ironguard-core`)

Generic over `T: Tun` and `B: Udp` -- zero OS dependencies.

#### Device and Workers

**`WireGuard<T, B>`** (`device.rs`) -- top-level device. Owns:
- `router::DeviceHandle` -- crypto-key routing with `treebitmap` LPM tables (IPv4 + IPv6)
- Per-peer state via `PeerInner` (timers, stats, session bookkeeping)

**Two async worker loops** (`workers.rs`):
- `tun_worker` -- TUN read -> pad -> router encrypt -> UDP send
- `udp_worker` -- UDP read -> dispatch: transport packets to router decrypt

#### Router (`router/`)

`device.rs` (device-level routing table), `peer.rs` (per-peer KeyWheel with next/current/previous keypair + AntiReplay bitmap), `send.rs` / `receive.rs` (encrypt/decrypt paths), `route.rs` (IP routing table wrapper), `messages_v2.rs` (v2 frame format -- 16-byte header with batch support).

#### v2 Pipeline (`pipeline/`) -- NEW

High-throughput packet processing pipeline. See `docs/superpowers/specs/` for the full design spec.

- **`pool.rs`** -- Two-tier pre-allocated buffer pool (8192 small 2KB buffers + 128 large 64KB buffers). Lock-free `ArrayQueue` free lists. `PacketRef` is an 8-byte handle (pool index + offset + length) for cheap copies. RAII `PacketGuard` returns buffers on drop.
- **`batch.rs`** -- `BatchAccumulator` that collects `PacketRef` values and flushes when count (64), bytes (64KB), or timeout (50us) thresholds are reached. Amortizes channel send and syscall overhead.
- **`io.rs`** -- `TransportIo` trait abstracting batch send/receive. UDP and QUIC implement it differently; the pipeline treats them uniformly.
- **`reorder.rs`** -- Per-peer reorder buffer (BTreeMap, window size 256) that restores packet ordering after parallel crypto workers complete out of order. Supports `DropMarker` for auth failures.

#### v2 Session Management (`session/`)

Manages session lifecycle via QUIC-based key exchange.

- **`keys.rs`** -- HKDF-SHA256-based key derivation. `derive_initial_keys(prk, role)` for the first epoch; `derive_epoch_keys(prk, role, epoch, entropy)` for rekeying. Keys are directional (client-to-server vs server-to-client labels).
- **`state.rs`** -- `SessionState` machine with states: `Idle`, `Stable`, `Rekeying`, `Migrating`. Handles `RekeyInit`/`RekeyAck` and `MigrationProbe`/`MigrationAck` messages with constant-time challenge verification.
- **`quic.rs`** (behind `quic` feature) -- QUIC-based session setup. `DataPlaneInit`/`DataPlaneAck` messages exchanged as QUIC datagrams after TLS handshake. `QuicSessionConfig` for cert/key paths and SNI.
- **`manager.rs`** (behind `quic` feature) -- `SessionManager` orchestrates per-peer QUIC sessions. Drives handshake, data-plane key exchange, and epoch-based rekeying.

#### v2 Frame Format (`router/messages_v2.rs`)

16-byte `FrameHeader`: Type(8) | Flags(8) | Reserved(16) | ReceiverID(32) | Counter(64). Types start at 0x04 to coexist with legacy WireGuard handshake types (1-3). Supports `TYPE_DATA` (0x04), `TYPE_KEEPALIVE` (0x05), `TYPE_CONTROL` (0x06), `TYPE_BATCH` (0x07 -- 20-byte header with packet count).

#### Other Core Modules

- **Callbacks pattern** (`router/types.rs`) -- `Callbacks` trait decouples the router from timer/stats logic.
- **Timer model** (`timers.rs`) -- 5 `Option<Instant>` deadlines per peer, checked every 100ms.

### Key Design Patterns

- **Type-generic IO**: Swapping `dummy::*` for `macos::*` tests the full stack without sockets
- **Zero-copy outbound**: TUN reads leave `SIZE_MESSAGE_PREFIX` (64 bytes) free; router writes transport header in-place
- **Lock strategy**: `spin::RwLock`/`spin::Mutex` on hot paths (peer lookups, key state); `parking_lot` where blocking is acceptable
- **Key zeroization**: `zeroize` derive on `StaticSecret`, `Key`; `subtle::ConstantTimeEq` for shared secret comparison
- **Buffer pooling**: Pre-allocated two-tier pool eliminates per-packet allocation on the hot path
- **Batch I/O**: `BatchAccumulator` + `TransportIo` trait amortize syscall overhead across multiple packets
- **Startup flow** (`main.rs`): Load config -> validate -> load keys -> create TUN -> create WireGuard device -> configure peers -> bind UDP -> attach readers -> bring up -> timer task -> wait for Ctrl+C

### Configuration (`ironguard-config`)

- `types.rs` -- `Config` struct: `HashMap<String, InterfaceConfig>` with serde. QUIC-only transport. Supports `masquerade`, `acl`, `post_up`/`post_down`, `post_quantum: false|true|strict`, per-peer `pq_public_key`.
- `keys.rs` -- loads private keys from file (`private_key_file`) or env var (`private_key_env`), accepts hex or base64.
- `conf.rs` -- bidirectional import/export between standard WireGuard `.conf` and `wg.json`.
- `validate.rs` -- semantic validation (missing keys, port conflicts, allowed-IP overlaps, QUIC config).

### CLI Commands

`up`, `down`, `status`, `genkey`, `pubkey`, `genpsk`, `gen-quic-cert`, `validate`, `import`, `export`. With `pq` feature: `pq-genkey`, `pq-pubkey`.
