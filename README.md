# IronGuard

A modern, cross-platform WireGuard implementation in pure Rust.

IronGuard is a from-scratch WireGuard implementation built on Rust 2024 edition with async Tokio, modern cryptography, and first-class JSON configuration. It features a high-performance pipeline with AES-256-GCM, batch I/O, and buffer pooling, QUIC-based session management for key exchange, automatic NAT traversal, and cross-platform support.

## Features

- **Full WireGuard Protocol** - Crypto-key routing, anti-replay (RFC 6479), per-peer timers, QUIC-based session management
- **v2 High-Performance Pipeline** - AES-256-GCM AEAD (2.5-3.6x faster than ChaCha20-Poly1305 on AES-NI hardware), two-tier buffer pool, batch accumulator with count/size/timeout flush, per-peer reorder buffer, and v2 frame format with 16-byte headers
- **Async Tokio Architecture** - Non-blocking I/O with work-stealing runtime, batch-aware TUN and UDP workers, Darwin `sendmsg_x`/`recvmsg_x` and Linux `sendmmsg`/`recvmmsg` for syscall amortization
- **NAT Traversal** (`ironguard-connect`) - STUN-based NAT detection, coordinated UDP hole punching, birthday paradox spray for symmetric NAT, UPnP port mapping, mDNS LAN auto-discovery, and QUIC-based relay fallback
- **Cross-Platform** - macOS (utun) and Linux support with platform-specific optimizations (GSO/GRO on Linux, kernel buffer tuning on macOS)
- **JSON Configuration** - `wg.json` format with secrets separation, multi-interface, DNS hostname endpoints, inline comments (JSONC)
- **Standard Config Interop** - Import/export standard WireGuard `.conf` files
- **QUIC Transport** (feature-gated) - RFC 9298 MASQUE encapsulation via quinn for traversing firewalls that block UDP, with automatic datagram/stream fallback and session management
- **Zero-Copy Data Path** - In-place transport header construction, `ring` seal_in_place, and pre-allocated buffer pooling for minimal allocation on the hot path
- **274 Tests** - Unit, integration, protocol-level, and benchmark tests across all modules

## Architecture

```
ironguard/
  crates/
    ironguard-core/       # Pure WireGuard protocol — generic over platform traits
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

### Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/dickwu/ironguard/main/scripts/install.sh | sudo bash
```

Detects your OS and architecture, downloads the latest release, installs both `ironguard` and `ironguard-tui` to `/usr/local/bin/`. Supports `--version=v0.3.0` and `--dir=/custom/path`.

### Homebrew (macOS)

```bash
brew tap dickwu/tap
brew install ironguard    # installs both ironguard and ironguard-tui
```

### Download Binary

Pre-built binaries for macOS and Linux are available on the [releases page](https://github.com/dickwu/ironguard/releases). Each archive contains both `ironguard` (tunnel) and `ironguard-tui` (manager).

| Platform | Binary |
|----------|--------|
| macOS Apple Silicon | `ironguard-macos-aarch64.tar.gz` |
| macOS Intel | `ironguard-macos-x86_64.tar.gz` |
| Linux x86_64 | `ironguard-linux-x86_64.tar.gz` |
| Linux ARM64 | `ironguard-linux-aarch64.tar.gz` |

```bash
# Download and install both binaries
curl -sL https://github.com/dickwu/ironguard/releases/latest/download/ironguard-macos-aarch64.tar.gz | tar xz
sudo mv ironguard ironguard-tui /usr/local/bin/
```

### Build from Source

```bash
# Build everything (tunnel + TUI manager)
cargo build --workspace --release

# Install the TUI manager to ~/.cargo/bin/
cargo install --path crates/ironguard-tui

# Or install just the tunnel
cargo install --path crates/ironguard-cli
```

### Generate Keys

```bash
# Generate a private key
ironguard genkey > private.key

# Derive the public key
ironguard pubkey < private.key > public.key

# Generate a pre-shared key
ironguard genpsk > preshared.key
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
| `peers` | array | [] | Peer configurations |

### Peer Fields

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string | Peer's public key (hex or base64) |
| `preshared_key_file` | string | Path to pre-shared key file |
| `endpoint` | string | Peer endpoint (`host:port`, DNS supported) |
| `allowed_ips` | string[] | Allowed IP ranges (CIDR) |
| `persistent_keepalive` | u64 | Keepalive interval in seconds |
| `_comment` | string | Inline comment (preserved in round-trips) |

## Cryptography

| Component | Implementation | Notes |
|-----------|---------------|-------|
| AEAD | `ring 0.17` (AES-256-GCM) | Hardware-accelerated AES-NI |
| Key Exchange | `x25519-dalek 2` | Curve25519 DH |
| Key Derivation | HKDF-SHA256 | Epoch-based rekeying with directional key labels |
| Session Management | QUIC (`quinn 0.11` + `rustls 0.23`) | TLS 1.3, DataPlaneInit/Ack key exchange |
| Key Zeroization | `zeroize 1` | Secure memory clearing on drop |
| Anti-Replay | Custom RFC 6479 | 2048-bit sliding window bitmap |

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

## Quick Start

`ironguard-tui` is a Rust TUI manager for IronGuard. Run it with no arguments for an interactive dashboard, or use subcommands for scripting.

### Interactive (TUI)

```bash
# Launch the dashboard — shows status, peers, logs, and keybindings
sudo ironguard-tui
```

```
+-IronGuard---------------------------------------------------+
| Status: RUNNING    Interface: wg0    Port: 51820/udp        |
| Key: a1b2c3d4e5f6...                                        |
+-Peers (2)---------------------------------------------------+
| Name          IP            Public Key            Keepalive  |
| laptop        10.0.0.2      f7e8d9c0...           25s       |
| phone         10.0.0.3      b1a2c3d4...           25s       |
+-Log---------------------------------------------------------+
| [10:30:22] Server started                                    |
+--------------------------------------------------------------+
| [s]etup [c]lient [p]eers [r]estart [l]ogs [?]help [q]uit   |
+--------------------------------------------------------------+
```

### CLI (non-interactive)

```bash
# 1. Set up the server
sudo ironguard-tui setup

# 2. Create clients (auto-generates keys, assigns IP, adds peer to server)
sudo ironguard-tui client create laptop --endpoint=vpn.example.com:51820
sudo ironguard-tui client create phone  --endpoint=vpn.example.com:51820

# 3. Start the server
sudo ironguard-tui start

# 4. Copy client folder to device and connect
scp -r /etc/ironguard/clients/laptop/ user@laptop:~/ironguard/
# On the client:
cd ~/ironguard && sudo ironguard up utun10 -c wg.json -f
```

### Server Commands

```bash
ironguard-tui start              # start the server
ironguard-tui stop               # stop the server
ironguard-tui restart            # restart (picks up config changes)
ironguard-tui status             # show running state + peer count
ironguard-tui logs               # tail server logs
ironguard-tui peers              # list all configured peers
ironguard-tui server-key         # print server public key
```

### Client Commands

```bash
ironguard-tui client create <name>   # generate keys + config, add to server
ironguard-tui client list            # list all clients with IPs
ironguard-tui client show <name>     # show client details + config
ironguard-tui client remove <name>   # remove client + peer from server
```

Each `client create` generates keys, picks the next available IP (10.0.0.2, .3, .4...), writes a ready-to-use `wg.json`, and adds the peer to the server config. After adding or removing clients, run `restart` to apply.

### Setup Options

```bash
# Custom interface, port, IP
sudo ironguard-tui setup --interface=wg0 --port=51820 --ip=10.0.0.1

# Build the TUI itself
cargo build -p ironguard-tui --release
```

Setup auto-detects Linux vs macOS and:
- Generates server keys in `/etc/ironguard/keys/`
- Creates `/etc/ironguard/wg.json` with empty peer list
- Registers a system service (systemd on Linux, launchd on macOS)
- Configures firewall rules and IP forwarding


## Project Map

```
ironguard/
  Cargo.toml                    # Workspace root (6 crates)
  crates/
    ironguard-core/             # Pure WireGuard protocol (generic over platform traits)
      src/
        device.rs               #   WireGuard<T,B> top-level device orchestration
        workers.rs              #   Async tun/udp worker loops
        timers.rs               #   5 per-peer WireGuard deadline timers
        peer.rs                 #   Per-peer state, stats, handshake bookkeeping
        queue.rs                #   Bounded parallel work queue
        types.rs                #   StaticSecret, PublicKey, KeyPair wrappers
        constants.rs            #   Protocol constants (sizes, timeouts)
        router/
          device.rs             #     DeviceHandle: treebitmap IPv4+IPv6 LPM tables
          peer.rs               #     KeyWheel (next/current/previous) + AntiReplay
          send.rs               #     Outbound: TUN -> AES-256-GCM encrypt -> UDP
          receive.rs            #     Inbound: UDP -> decrypt -> TUN
          route.rs              #     IP routing table wrapper
          anti_replay.rs        #     RFC 6479 2048-bit sliding window
          messages_v2.rs        #     v2 16-byte FrameHeader (types 0x04-0x07)
          messages.rs           #     Legacy transport message structs
          queue.rs              #     Staged packet queue per peer
          types.rs              #     Callbacks trait (decouples router from timers)
          tests.rs              #     Router unit tests
        pipeline/
          pool.rs               #     Two-tier buffer pool (8192x2KB + 128x64KB)
          batch.rs              #     BatchAccumulator (count/size/timeout flush)
          io.rs                 #     TransportIo trait (batch send/receive)
          reorder.rs            #     Per-peer reorder buffer (BTreeMap, window=256)
        session/
          keys.rs               #     HKDF-SHA256 epoch-based key derivation
          state.rs              #     SessionState machine (Idle/Stable/Rekeying/Migrating)
          quic.rs               #     QUIC-based session setup (quic feature)
          manager.rs            #     SessionManager per-peer QUIC sessions (quic feature)
          tasks.rs              #     Async session tasks (rekey, migration)
      benches/
        pipeline.rs             #   Criterion benchmarks

    ironguard-platform/         # OS I/O abstractions
      src/
        tun.rs                  #   Tun trait (Reader, Writer, Status)
        udp.rs                  #   Udp trait (UdpReader, UdpWriter)
        endpoint.rs             #   Endpoint trait
        capabilities.rs         #   PlatformCapabilities (sendmmsg, GSO, multi-queue)
        quic.rs                 #   QUIC transport backend (quic feature)
        macos/
          tun.rs                #     macOS utun via tun-rs
          udp.rs                #     macOS UDP with sendmsg_x/recvmsg_x
          darwin_batch.rs       #     Darwin batch I/O FFI syscalls
          endpoint.rs           #     MacosEndpoint
        linux/
          tun.rs                #     Linux TUN via tun-rs
          udp.rs                #     Linux UDP with sendmmsg/recvmmsg + GSO/GRO
          endpoint.rs           #     LinuxEndpoint
        dummy/
          tun.rs                #     In-memory TUN for testing
          udp.rs                #     In-memory UDP for testing

    ironguard-connect/          # NAT traversal & connectivity
      src/
        stun.rs                 #   STUN binding requests (NAT detection)
        holepunch.rs            #   Coordinated UDP hole punching
        birthday.rs             #   Birthday paradox spray (symmetric NAT)
        portmap.rs              #   UPnP port mapping (igd-next)
        netcheck.rs             #   Network type detection
        candidate.rs            #   Ranked connection candidates
        manager.rs              #   ConnectionManager orchestrating all strategies
        discovery/
          mdns.rs               #     mDNS LAN auto-discovery
          local.rs              #     Local network scanning
          subnet.rs             #     Subnet-based peer search
        relay/
          server.rs             #     QUIC-based relay server
          client.rs             #     QUIC-based relay client
          protocol.rs           #     Relay wire protocol messages

    ironguard-config/           # Configuration layer
      src/
        types.rs                #   Config, InterfaceConfig, PeerConfig structs
        keys.rs                 #   Key loading from file/env (hex + base64)
        conf.rs                 #   WireGuard .conf <-> wg.json conversion
        validate.rs             #   Semantic config validation
      tests/
        config_to_core.rs       #   JSON round-trip + import/export tests

    ironguard-cli/              # CLI binary
      src/
        main.rs                 #   clap CLI: up/down/status/genkey/pubkey/import/export

    ironguard-tui/              # TUI manager (ratatui + crossterm)
      src/
        main.rs                 #   Dual-mode: interactive TUI or CLI subcommands
        app.rs                  #   App state machine (screens, data, transitions)
        tui.rs                  #   Terminal setup/teardown, main render loop
        event.rs                #   Key event handling + action dispatch
        ui/
          dashboard.rs          #     Main dashboard: status + peers + log + keybindings
          setup.rs              #     Step-by-step setup wizard with progress bar
          clients.rs            #     Client create form + client list table
          logs.rs               #     Scrollable log viewer
          help.rs               #     Keybinding reference
        actions/
          server.rs             #     Start/stop/restart (systemd or launchd)
          config.rs             #     Config CRUD: peers, clients, server settings
          keys.rs               #     X25519 key generation + derivation
          system.rs             #     OS detection, service install, firewall, IP forwarding
          setup.rs              #     Non-interactive setup flow

  configs/                      # Example configurations
    server-wg.json              #   Server config (utun9, port 51820)
    client-wg.json              #   Client config (utun10, port 51830)

  scripts/
    install.sh                  # curl-pipe-bash installer (Linux + macOS)
    deploy-ai.sh                # Remote deploy + test script
    ironguard-ctl               # Bash fallback (same commands as ironguard-tui)

  .github/workflows/
    ci.yml                      # CI: build + test + clippy + fmt (Linux + macOS)
    release.yml                 # Release: 4-platform builds + GitHub release + Homebrew
```

## Development

```bash
# Run all tests
cargo test --workspace

# Clippy
cargo clippy --workspace -- -D warnings

# Build release
cargo build --workspace --release
```

### Test Coverage

Tests passing across all crates:

| Module | Tests | Coverage |
|--------|-------|----------|
| Router (routing, AEAD, replay, v2 frames) | 17 | LPM routing, bidirectional crypto, anti-replay, key rotation, v2 frame encoding |
| Pipeline (pool, batch, reorder) | 20+ | Buffer pool alloc/free, batch flush thresholds, reorder window, TransportIO |
| Session (keys, state, QUIC) | 15+ | Key derivation, epoch rekeying, migration state machine, QUIC handshake |
| Timers | 19 | All 5 timer types, scheduling, cancellation |
| Device + Workers | 6 | Full tunnel test (dummy TUN/UDP), worker lifecycle |
| Config | 143 | JSON round-trip, .conf import/export, key loading, validation |
| Platform | 16 | UDP binding, TUN creation, batch I/O, capabilities detection |
| Connect | 20 | STUN, hole punching, mDNS, relay protocol, connection manager |
| QUIC | 2 | Loopback datagram + stream fallback |

## License

GPL-3.0-or-later
