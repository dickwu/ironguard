# IronGuard

A modern, cross-platform WireGuard implementation in pure Rust.

IronGuard is a from-scratch WireGuard implementation built on Rust 2024 edition with async Tokio, modern cryptography, and first-class JSON configuration. It supports optional QUIC transport for restricted networks and post-quantum key exchange for future-proof security.

## Features

- **Full WireGuard Protocol** - Noise_IKpsk2 handshake, ChaCha20-Poly1305 AEAD, crypto-key routing, anti-replay (RFC 6479), per-peer timers, MAC1/MAC2 DoS mitigation
- **Async Tokio Architecture** - Non-blocking I/O with work-stealing runtime, dedicated crypto thread pool for high-throughput encryption
- **Cross-Platform** - macOS (utun) support built-in, Linux support planned
- **JSON Configuration** - `wg.json` format with secrets separation, multi-interface, DNS hostname endpoints, inline comments (JSONC)
- **Standard Config Interop** - Import/export standard WireGuard `.conf` files
- **QUIC Transport** (feature-gated) - RFC 9298 MASQUE encapsulation via quinn for traversing firewalls that block UDP, with automatic datagram/stream fallback
- **Post-Quantum Ready** (feature-gated) - Hybrid ML-KEM-768 + X25519 key exchange via the WireGuard PSK slot (FIPS 203)
- **Zero-Copy Data Path** - In-place transport header construction and `ring` seal_in_place for minimal memory copies
- **105 Tests** - Unit, integration, and protocol-level tests across all modules

## Architecture

```
ironguard/
  crates/
    ironguard-core/       # Pure WireGuard protocol (9400+ lines)
      handshake/          #   Noise_IKpsk2 via snow, MAC/cookie DoS, rate limiter
      router/             #   Crypto-key routing, AEAD, KeyWheel, AntiReplay
      timers.rs           #   5 per-peer WireGuard timers
      device.rs           #   Top-level device orchestration
      workers.rs          #   Async tun/udp/handshake worker tasks

    ironguard-platform/   # Platform abstractions
      tun.rs / udp.rs     #   Async IO traits
      macos/              #   macOS utun + UDP via tun-rs + tokio
      dummy/              #   In-memory backends for testing

    ironguard-config/     # Configuration layer
      json.rs / conf.rs   #   wg.json + .conf parsing
      keys.rs             #   Key file/env loading (hex + base64)
      validate.rs         #   Config validation

    ironguard-cli/        # CLI binary
      main.rs             #   clap-based CLI with all commands
```

## Quick Start

### Build

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
| Noise Handshake | `snow 0.10` (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) | Audited library |
| AEAD | `ring 0.17` (ChaCha20-Poly1305) | BoringSSL assembly, hardware-accelerated |
| Key Exchange | `x25519-dalek 2` | Curve25519 DH |
| Hashing | `blake2s_simd 1` | AVX2 SIMD-accelerated BLAKE2s |
| Key Zeroization | `zeroize 1` | Secure memory clearing on drop |
| Post-Quantum | `ml-kem 0.2` (FIPS 203 ML-KEM-768) | Feature-gated, hybrid with X25519 |
| QUIC | `quinn 0.11` + `rustls 0.23` | Feature-gated, TLS 1.3 |
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

| Module | Tests | Coverage |
|--------|-------|----------|
| Handshake (noise, macs, ratelimiter) | 17 | Handshake completion, key symmetry, DoS mitigation, cookie flow |
| Router (routing, AEAD, replay) | 17 | LPM routing, bidirectional crypto, anti-replay, key rotation |
| Timers | 19 | All 5 timer types, scheduling, cancellation |
| Device + Workers | 6 | Full tunnel test (dummy TUN/UDP), worker lifecycle |
| Config | 22 | JSON round-trip, .conf import/export, key loading, validation |
| Platform | 3 | UDP binding, TUN creation (ignored without sudo) |
| QUIC | 2 | Loopback datagram + stream fallback |
| Post-Quantum | 8 | KEM roundtrip, key serialization, handshake integration |

## License

GPL-3.0-or-later
