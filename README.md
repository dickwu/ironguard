# IronGuard

A modern, cross-platform WireGuard implementation in pure Rust.

IronGuard is a from-scratch WireGuard implementation built on Rust 2024 edition with async Tokio, modern cryptography, and first-class JSON configuration. It features a v2 high-performance pipeline with AES-256-GCM, batch I/O, and buffer pooling, plus optional QUIC transport for restricted networks, automatic NAT traversal, and post-quantum key exchange for future-proof security.

## Features

- **Full WireGuard Protocol** - Noise_IKpsk2 handshake, crypto-key routing, anti-replay (RFC 6479), per-peer timers, MAC1/MAC2 DoS mitigation
- **v2 High-Performance Pipeline** - AES-256-GCM AEAD (2.5-3.6x faster than ChaCha20-Poly1305 on AES-NI hardware), two-tier buffer pool, batch accumulator with count/size/timeout flush, per-peer reorder buffer, and v2 frame format with 16-byte headers
- **Async Tokio Architecture** - Non-blocking I/O with work-stealing runtime, batch-aware TUN and UDP workers, Darwin `sendmsg_x`/`recvmsg_x` and Linux `sendmmsg`/`recvmmsg` for syscall amortization
- **NAT Traversal** (`ironguard-connect`) - STUN-based NAT detection, coordinated UDP hole punching, birthday paradox spray for symmetric NAT, UPnP port mapping, mDNS LAN auto-discovery, and QUIC-based relay fallback
- **Cross-Platform** - macOS (utun) and Linux support with platform-specific optimizations (GSO/GRO on Linux, kernel buffer tuning on macOS)
- **JSON Configuration** - `wg.json` format with secrets separation, multi-interface, DNS hostname endpoints, inline comments (JSONC)
- **Standard Config Interop** - Import/export standard WireGuard `.conf` files
- **QUIC Transport** (feature-gated) - RFC 9298 MASQUE encapsulation via quinn for traversing firewalls that block UDP, with automatic datagram/stream fallback and session management
- **Post-Quantum Ready** (feature-gated) - Hybrid ML-KEM-768 + X25519 key exchange via the WireGuard PSK slot (FIPS 203)
- **Zero-Copy Data Path** - In-place transport header construction, `ring` seal_in_place, and pre-allocated buffer pooling for minimal allocation on the hot path
- **274 Tests** - Unit, integration, protocol-level, and benchmark tests across all modules

## Architecture

```
ironguard/
  crates/
    ironguard-core/       # Pure WireGuard protocol — generic over platform traits
      handshake/          #   Noise_IKpsk2 via snow, MAC/cookie DoS, rate limiter
      router/             #   Crypto-key routing, AES-256-GCM AEAD, KeyWheel, AntiReplay
      pipeline/           #   v2 buffer pool, batch accumulator, reorder buffer, TransportIO
      session/            #   Epoch-based key derivation, rekey/migration state machines
      timers.rs           #   5 per-peer WireGuard timers
      device.rs           #   Top-level device orchestration
      workers.rs          #   Batch-aware async tun/udp/handshake workers

    ironguard-platform/   # Platform abstractions
      tun.rs / udp.rs     #   Async IO traits + PlatformCapabilities
      macos/              #   macOS utun + sendmsg_x/recvmsg_x batch I/O
      linux/              #   Linux TUN + sendmmsg/recvmmsg + GSO/GRO
      dummy/              #   In-memory backends for testing

    ironguard-connect/    # NAT traversal & connectivity
      stun.rs             #   STUN binding requests for NAT detection
      holepunch.rs        #   Coordinated UDP hole punching
      birthday.rs         #   Birthday paradox spray for symmetric NAT
      portmap.rs          #   UPnP port mapping (igd-next)
      discovery/          #   mDNS LAN auto-discovery
      relay/              #   QUIC-based relay server and client
      manager.rs          #   ConnectionManager orchestrating all strategies

    ironguard-config/     # Configuration layer
      json.rs / conf.rs   #   wg.json + .conf parsing
      keys.rs             #   Key file/env loading (hex + base64)
      validate.rs         #   Config validation

    ironguard-cli/        # CLI binary
      main.rs             #   clap-based CLI with all commands
```

## Installation

### Homebrew (macOS)

```bash
brew tap dickwu/tap
brew install ironguard
```

### Download Binary

Pre-built binaries for macOS and Linux are available on the [releases page](https://github.com/dickwu/ironguard/releases):

| Platform | Binary |
|----------|--------|
| macOS Apple Silicon | `ironguard-macos-aarch64.tar.gz` |
| macOS Intel | `ironguard-macos-x86_64.tar.gz` |
| Linux x86_64 | `ironguard-linux-x86_64.tar.gz` |
| Linux ARM64 | `ironguard-linux-aarch64.tar.gz` |

```bash
# Example: download and install on macOS Apple Silicon
curl -sL https://github.com/dickwu/ironguard/releases/latest/download/ironguard-macos-aarch64.tar.gz | tar xz
sudo mv ironguard /usr/local/bin/
```

### Build from Source

```bash
cargo build --release

# With QUIC transport
cargo build --release --features quic

# With post-quantum crypto
cargo build --release --features pq

# With everything
cargo build --release --features "quic,pq"
```

### Generate Keys

```bash
# Generate a private key
ironguard genkey > private.key

# Derive the public key
ironguard pubkey < private.key > public.key

# Generate a pre-shared key
ironguard genpsk > preshared.key

# Generate post-quantum keys (requires --features pq)
ironguard pq-genkey > pq-private.key
ironguard pq-pubkey < pq-private.key > pq-public.key
```

### Configure

Create a `wg.json` configuration file:

```jsonc
{
  // IronGuard configuration
  "$schema": "ironguard/v1",
  "interfaces": {
    "utun9": {
      "private_key_file": "./private.key",
      "listen_port": 51820,
      "address": ["10.0.0.1/24"],
      "mtu": 1420,
      "transport": "udp",
      "peers": [
        {
          "public_key": "abc123...",
          "endpoint": "vpn.example.com:51820",
          "allowed_ips": ["10.0.0.2/32"],
          "persistent_keepalive": 25,
          "_comment": "Peer B"
        }
      ]
    }
  }
}
```

### Run

```bash
# Start the tunnel (requires root for TUN device creation on macOS)
sudo ironguard up utun9 --config wg.json --foreground

# Validate config without running
ironguard validate wg.json

# Show configured interfaces
ironguard status
```

### Import/Export Standard Config

```bash
# Import from standard WireGuard .conf
ironguard import --conf /etc/wireguard/wg0.conf --output wg.json

# Export back to .conf format
ironguard export --json wg.json --interface utun9 --output wg0.conf
```

## Configuration Reference

### `wg.json` Schema

| Field | Type | Description |
|-------|------|-------------|
| `$schema` | string | Schema identifier (`"ironguard/v1"`) |
| `interfaces` | map | Map of interface name to config |

### Interface Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `private_key_file` | string | - | Path to private key file |
| `private_key_env` | string | - | Environment variable containing private key |
| `listen_port` | u16 | random | UDP listen port |
| `address` | string[] | [] | Interface addresses (CIDR) |
| `dns` | string[] | [] | DNS servers |
| `mtu` | u16 | 1420 | Tunnel MTU |
| `fwmark` | u32 | 0 | Firewall mark |
| `transport` | string | `"udp"` | Transport mode: `"udp"` or `"quic"` |
| `quic.port` | u16 | 443 | QUIC listen port (when transport=quic) |
| `quic.sni` | string | - | TLS SNI for QUIC |
| `post_quantum` | bool/string | `false` | PQ mode: `false`, `true`, or `"strict"` |
| `peers` | array | [] | Peer configurations |

### Peer Fields

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string | Peer's public key (hex or base64) |
| `preshared_key_file` | string | Path to pre-shared key file |
| `endpoint` | string | Peer endpoint (`host:port`, DNS supported) |
| `allowed_ips` | string[] | Allowed IP ranges (CIDR) |
| `persistent_keepalive` | u64 | Keepalive interval in seconds |
| `pq_public_key` | string | ML-KEM-768 public key (hex, requires `pq` feature) |
| `_comment` | string | Inline comment (preserved in round-trips) |

## Cryptography

| Component | Implementation | Notes |
|-----------|---------------|-------|
| Noise Handshake | `snow 0.10` (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) | Audited library, feature-gated (`legacy-wireguard`) |
| AEAD (v2) | `ring 0.17` (AES-256-GCM) | Hardware-accelerated AES-NI, 2.5-3.6x faster than ChaCha20-Poly1305 |
| AEAD (legacy) | `ring 0.17` (ChaCha20-Poly1305) | BoringSSL assembly for legacy WireGuard compat |
| Key Exchange | `x25519-dalek 2` | Curve25519 DH |
| Key Derivation (v2) | HKDF-SHA256 | Epoch-based rekeying with directional key labels |
| Hashing | `blake2s_simd 1` | AVX2 SIMD-accelerated BLAKE2s |
| Key Zeroization | `zeroize 1` | Secure memory clearing on drop |
| Post-Quantum | `ml-kem 0.2` (FIPS 203 ML-KEM-768) | Feature-gated, hybrid with X25519 |
| QUIC | `quinn 0.11` + `rustls 0.23` | Feature-gated, TLS 1.3, session management |
| Anti-Replay | Custom RFC 6479 | 2048-bit sliding window bitmap |
| DoS Mitigation | Custom MAC1/MAC2/cookie | Per-IP rate limiting (20 pkt/s) |

## QUIC Transport

When `transport: "quic"` is set, IronGuard encapsulates WireGuard packets inside QUIC connections on port 443. This makes VPN traffic indistinguishable from normal HTTPS/HTTP3 traffic, enabling connectivity on networks that block UDP on non-standard ports.

- Prefers QUIC unreliable datagrams (RFC 9221) for minimum overhead
- Falls back to length-prefixed QUIC streams if datagrams are unavailable
- Self-signed certificates (WireGuard's Noise handshake provides authentication)
- Automatic reconnection with session resumption

```jsonc
{
  "interfaces": {
    "utun9": {
      "transport": "quic",
      "quic": {
        "port": 443,
        "sni": "cdn.example.com"
      }
    }
  }
}
```

## Post-Quantum Cryptography

IronGuard supports hybrid ML-KEM-768 + X25519 key exchange for protection against quantum computers. The ML-KEM shared secret is injected into the WireGuard PSK slot — no protocol changes needed.

Three modes:
- `"post_quantum": false` - Disabled (standard WireGuard)
- `"post_quantum": true` - Enabled with graceful downgrade (log warning if peer lacks PQ key)
- `"post_quantum": "strict"` - Refuse peers without PQ key exchange

## Development

```bash
# Run all tests
cargo test --workspace

# Run with all features
cargo test --workspace --features "quic,pq"

# Clippy
cargo clippy --workspace --features "quic,pq"

# Build release
cargo build --release --features "quic,pq"
```

### Test Coverage

274 tests passing across all crates:

| Module | Tests | Coverage |
|--------|-------|----------|
| Handshake (noise, macs, ratelimiter) | 17 | Handshake completion, key symmetry, DoS mitigation, cookie flow |
| Router (routing, AEAD, replay, v2 frames) | 17 | LPM routing, bidirectional crypto, anti-replay, key rotation, v2 frame encoding |
| Pipeline (pool, batch, reorder) | 20+ | Buffer pool alloc/free, batch flush thresholds, reorder window, TransportIO |
| Session (keys, state, QUIC) | 15+ | Key derivation, epoch rekeying, migration state machine, QUIC handshake |
| Timers | 19 | All 5 timer types, scheduling, cancellation |
| Device + Workers | 6 | Full tunnel test (dummy TUN/UDP), worker lifecycle |
| Config | 143 | JSON round-trip, .conf import/export, key loading, validation |
| Platform | 16 | UDP binding, TUN creation, batch I/O, capabilities detection |
| Connect | 20 | STUN, hole punching, mDNS, relay protocol, connection manager |
| QUIC | 2 | Loopback datagram + stream fallback |
| Post-Quantum | 8 | KEM roundtrip, key serialization, handshake integration |

## License

GPL-3.0-or-later
