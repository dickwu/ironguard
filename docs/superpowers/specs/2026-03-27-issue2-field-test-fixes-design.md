# IronGuard v0.3.2 — Issue #2 Field Test Fixes

**Date**: 2026-03-27
**Issue**: dickwu/ironguard#2
**Scope**: 3 P0 bugs, 3 P1 features, documentation fixes
**Approach**: Layered bottom-up (config → platform → core → CLI → docs)
**Platforms**: macOS + Linux

---

## Summary

Field testing v0.3.1 in a 3-client topology (2 macOS + 1 Linux) revealed that
the TUN interface never gets an IP address, UDP transport is broken, and
multi-peer QUIC sessions all route to peer 0. This spec fixes all three bugs
and adds masquerade, per-peer ACL, and PostUp/PostDown hooks.

---

## Layer 1: Config Schema (`ironguard-config`)

All new fields added in one pass to avoid repeated schema migrations.

### InterfaceConfig Additions

```rust
pub struct InterfaceConfig {
    // ... existing fields ...

    /// NAT outbound tunnel traffic.
    /// `false` or absent = disabled.
    /// `true` = masquerade on all non-tunnel interfaces.
    /// `["en0", "eth0"]` = masquerade only on listed interfaces.
    #[serde(default, skip_serializing_if = "Masquerade::is_disabled")]
    pub masquerade: Masquerade,

    /// Shell commands to run after interface is up. %i = interface name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_up: Vec<String>,

    /// Shell commands to run before interface is torn down. %i = interface name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_down: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Masquerade {
    #[default]
    Disabled,                // false or absent
    All(bool),               // true
    Interfaces(Vec<String>), // ["en0", "eth0"]
}

impl Masquerade {
    pub fn is_disabled(&self) -> bool {
        matches!(self, Masquerade::Disabled | Masquerade::All(false))
    }
}
```

### PeerConfig Additions

```rust
pub struct PeerConfig {
    // ... existing fields ...

    /// Destination ACL — restrict which IPs this peer can reach.
    /// If absent, peer can reach any routable destination (current behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<PeerAcl>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAcl {
    /// CIDRs this peer is allowed to send traffic TO.
    pub allow_destinations: Vec<String>,
}
```

### QuicConfig Fix

```rust
pub struct QuicConfig {
    /// QUIC port. Defaults to listen_port + 1 if omitted.
    #[serde(default)]
    pub port: Option<u16>,
    // ... rest unchanged ...
}
```

At runtime, resolve `None` to `listen_port + 1`.

### Validation Updates (`validate.rs`)

- `quic` block required only when `transport == "quic"`
- `masquerade: true` requires at least one peer with `allowed_ips` containing a non-tunnel subnet (warn, not error)
- `acl.allow_destinations` CIDRs must parse correctly
- `post_up`/`post_down` commands without `%i` emit a warning (non-blocking)

---

## Layer 2: Platform Layer (`ironguard-platform`)

New `NetworkManager` trait abstracting OS-specific network configuration.

### Trait Definition (`net_manager.rs`)

```rust
use std::net::IpAddr;

pub trait NetworkManager: Send + Sync {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;
    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;
    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;
    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;
    fn add_masquerade(&self, tun_iface: &str, tun_subnet: &str, out_ifaces: &[String]) -> Result<()>;
    fn remove_masquerade(&self, tun_iface: &str) -> Result<()>;
    /// Run a shell command with %i replaced by the interface name.
    /// Timeout: 30 seconds. Runs via tokio::task::spawn_blocking to avoid
    /// stalling the async runtime.
    fn run_hook(&self, command: &str, iface: &str) -> Result<()>;
}
```

All methods are idempotent. Calling `add` twice or `remove` on non-existent state is a no-op.
Each method logs the underlying command at `debug!` level before execution.

### macOS Implementation (`macos/net_manager.rs`)

| Method | Command |
|--------|---------|
| `add_address` (IPv4) | `ifconfig {iface} inet {addr}/{prefix} {addr}` |
| `add_address` (IPv6) | `ifconfig {iface} inet6 {addr} prefixlen {prefix}` |
| `remove_address` | `ifconfig {iface} delete {addr}` |
| `add_route` | `route -n add -net {dest}/{prefix} -interface {iface}` |
| `remove_route` | `route -n delete -net {dest}/{prefix} -interface {iface}` |
| `add_masquerade` | Load PF anchor: `nat on {out_iface} from {subnet} to any -> ({out_iface})` |
| `remove_masquerade` | Flush PF anchor for this tunnel |
| `run_hook` | `sh -c "{command with %i replaced}"` |

All via `std::process::Command`.

### Linux Implementation (`linux/net_manager.rs`)

| Method | Command |
|--------|---------|
| `add_address` | `ip addr add {addr}/{prefix} dev {iface}` |
| `remove_address` | `ip addr del {addr}/{prefix} dev {iface}` |
| `add_route` | `ip route add {dest}/{prefix} dev {iface}` |
| `remove_route` | `ip route del {dest}/{prefix} dev {iface}` |
| `add_masquerade` | `nft add table ip ironguard-{iface}` + nat chain with masquerade rule |
| `remove_masquerade` | `nft delete table ip ironguard-{iface}` (atomic) |
| `run_hook` | `sh -c "{command with %i replaced}"` |

### Dummy Implementation (`dummy/net_manager.rs`)

Records all calls into `Vec<NetManagerOp>` for test assertions. No real syscalls.

---

## Layer 3: Core Fixes (`ironguard-core`)

### 3a. Multi-Peer QUIC Routing (Bug #3)

**Root cause**: `PeerLookup::lookup_by_addr` in `session/tasks.rs` has a wildcard
fallback `wildcards.first().copied()` that always returns peer 0 when IP lookup
fails.

**Fix**: Three changes:

**Prerequisite — Enable mutual TLS (mTLS).** The current QUIC setup uses
`with_no_client_auth()` (in `session/quic.rs` and hardcoded in `cmd_up` via
`make_test_server_config()`). The server never requests client certificates,
so `peer_identity()` always returns `None`. This must change:

- **New function `make_mtls_server_config()`** in `session/quic.rs`: configures
  `rustls::ServerConfig` with `with_client_cert_verifier(...)` requiring a client
  cert signed by a known CA or self-signed by a known peer. Accept certs whose CN
  matches any configured peer's WireGuard public key (base64-encoded).
- **New CLI command `ironguard gen-quic-cert`**: generates a self-signed X.509
  certificate with the WireGuard public key embedded in the Subject CN field as
  base64. Outputs cert + key PEM files. The existing `ironguard genkey` generates
  raw X25519 keys only — it does NOT generate TLS certs (correcting a previous
  incorrect assumption).
- **Config additions to `QuicConfig`**: `cert_file` and `key_file` fields for the
  node's own TLS identity, `peer_ca_file` or `peer_certs` for trusted peer certs.
- **`cmd_up` changes**: Replace `make_test_server_config()` with
  `make_mtls_server_config()` on both macOS (~line 425) and Linux (~line 698).
  Client-side: use `make_mtls_client_config()` with the client's own cert.

1. **Extract peer identity from QUIC TLS.** After mTLS is enabled, the client
   presents a certificate during the QUIC handshake. Read the peer's WireGuard
   public key from the certificate CN via `quinn::Connection::peer_identity()`.

```rust
// session/quic.rs — new helper
fn extract_peer_identity(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let certs = conn.peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer>>().ok()?;
    let cert = certs.first()?;
    extract_wg_pubkey_from_cert(cert) // x509-parser: read CN, base64-decode to [u8; 32]
}

// session/tasks.rs — quic_accept_loop
let peer_pk = match extract_peer_identity(&quic_connection) {
    Some(pk) if known_peer_pks.contains(&pk) => pk,
    _ => {
        // Fall back to IP-based lookup (known-endpoint case)
        match known_peers.lookup_by_addr(&remote_addr) {
            Some(pk) => pk,
            None => { warn!("unknown peer from {remote_addr}"); return; }
        }
    }
};
```

2. **Remove the wildcard fallback entirely** from `lookup_by_addr`. If neither
   identity extraction nor IP lookup matches, reject the connection.

3. **New dependency**: `x509-parser` crate in `ironguard-core/Cargo.toml` for
   certificate CN extraction.

### 3b. Userspace Per-Peer ACL (Feature #5)

Destination filter in **both directions** using the existing `treebitmap` LPM
table type (`RoutingTable<()>` from `router/route.rs`).

```rust
// router/peer.rs
pub struct PeerInner<C: Callbacks, T: Tun, B: Udp> {
    // ... existing fields ...
    /// Destination CIDRs this peer is allowed to reach. None = unrestricted.
    pub acl_destinations: Option<RoutingTable<()>>,
}
```

**Outbound check** (TUN → encrypt → UDP): filters packets being SENT TO this peer.

```rust
// router/send.rs — after peer is resolved, before encryption
if let Some(ref acl) = peer.acl_destinations {
    let dst_ip = extract_dst_ip(packet);
    if acl.longest_match(dst_ip).is_none() {
        return; // destination not in this peer's ACL — drop
    }
}
```

**Inbound check** (UDP → decrypt → TUN): filters packets RECEIVED FROM this peer.
Without this, a malicious peer can send packets to disallowed destinations that
bypass the outbound ACL after decryption.

```rust
// router/receive.rs — in sequential_work(), after decryption, before TUN write
// The existing check_route validates SOURCE IP matches peer's allowed_ips.
// Add a second check: DESTINATION IP must be in peer's ACL (if configured).
if let Some(ref acl) = peer.acl_destinations {
    let dst_ip = extract_dst_ip(decrypted_packet);
    if acl.longest_match(dst_ip).is_none() {
        return; // peer not allowed to reach this destination — drop
    }
}
```

**Performance**: One `RoutingTable` LPM lookup (~50ns estimate, pending benchmark)
per packet per direction. Negligible vs ChaCha20 encryption (~200ns for 1400B).
No connection tracking needed — this is stateless destination filtering.

**Configuration**: `set_acl_destinations(Some(table))` when peer is configured.
`None` = unrestricted (current behavior, zero overhead — the `if let` short-circuits).

### 3c. Transport Branching Support (Bug #2)

The core crate needs to support running without a `SessionManager`:

```rust
// device.rs
pub session_manager: Option<SessionManager>,
```

**Critical: the UDP path requires wiring the legacy Noise handshake.** The
current `cmd_up` is QUIC-only — there is no code that starts the Noise handshake
workers or triggers initial handshakes. For `transport == "udp"` to produce a
working tunnel, `cmd_up` must:

1. Create the `handshake::Device` with the local static key and all peer public
   keys + PSKs (this already exists behind `#[cfg(feature = "legacy-wireguard")]`).
2. Spawn `handshake_worker` threads (from `workers.rs`) to process the handshake
   queue — these produce keypairs that get installed into the router.
3. For each peer with a configured `endpoint`, trigger an initial handshake by
   calling `wg.begin_handshake(peer_handle)` (or equivalent) so that the client
   actively connects to the server.
4. Bind UDP sockets via `PlatformUdp::bind(listen_port)` and spawn `udp_worker`
   threads to receive handshake + transport packets.

The `#[cfg(feature = "legacy-wireguard")]` guards in the core crate already
support this — the handshake module, worker functions, and keypair installation
callbacks all exist. The gap is purely in `cmd_up` which never calls them.

**Requires `legacy-wireguard` feature**: If built with `--no-default-features`
(which disables the legacy handshake), `transport: "udp"` must emit a clear
error: "UDP transport requires the legacy-wireguard feature".

---

## Layer 4: CLI Integration (`ironguard-cli`)

### 4a. Transport Branching in `cmd_up` (Bug #2)

Both macOS (~line 255) and Linux (~line 534) code paths:

```rust
// BEFORE: unconditionally requires QUIC
let quic_cfg = iface_cfg.quic.as_ref()
    .ok_or_else(|| anyhow!("up requires a [quic] config section"))?;

// AFTER: branch on transport
let transport = iface_cfg.transport.as_str();
let session_manager = if transport == "quic" {
    let quic_cfg = iface_cfg.quic.as_ref()
        .ok_or_else(|| anyhow!("transport \"quic\" requires a [quic] config section"))?;
    // Resolve QUIC port: explicit > listen_port + 1 > error
    let quic_port = quic_cfg.port.or_else(|| iface_cfg.listen_port.map(|p| p + 1))
        .ok_or_else(|| anyhow!("QUIC transport requires quic.port or listen_port"))?;
    // ... existing QUIC setup using quic_port ...
    Some(manager)
} else {
    // UDP: wire legacy Noise handshake (requires legacy-wireguard feature)
    #[cfg(not(feature = "legacy-wireguard"))]
    return Err(anyhow!("UDP transport requires the legacy-wireguard feature"));

    // 1. Create handshake device with local key + peer keys
    // 2. Spawn handshake_worker threads
    // 3. Bind UDP sockets, spawn udp_worker threads
    // 4. Trigger initial handshakes for peers with configured endpoints
    None
};
```

### 4b. Address Assignment + Routes in `cmd_up` (Bug #1)

After TUN creation, before starting workers:

```rust
let net_mgr = platform::create_net_manager();

// Assign addresses
for addr_str in &iface_cfg.address {
    let (ip, prefix_len) = parse_cidr(addr_str)?;
    net_mgr.add_address(&iface_name, ip, prefix_len)?;
    info!("assigned {addr_str} to {iface_name}");
}

// Add routes for each peer's allowed_ips
// SAFETY: skip 0.0.0.0/0 and ::/0 — these require policy routing (fwmark)
// to avoid routing loops. Log a warning if encountered.
for peer_cfg in &iface_cfg.peers {
    for allowed_ip in &peer_cfg.allowed_ips {
        let (dest, prefix_len) = parse_cidr(allowed_ip)?;
        if prefix_len == 0 {
            warn!("skipping default route {allowed_ip} — use PostUp for catch-all routing");
            continue;
        }
        net_mgr.add_route(&iface_name, dest, prefix_len)?;
        info!("route {allowed_ip} via {iface_name}");
    }
}

// Enable masquerade if configured
let tun_subnet = iface_cfg.address.first()
    .ok_or_else(|| anyhow!("masquerade requires at least one interface address"))?;
match &iface_cfg.masquerade {
    Masquerade::All(true) => {
        net_mgr.add_masquerade(&iface_name, tun_subnet, &[])?;
    }
    Masquerade::Interfaces(ifaces) => {
        net_mgr.add_masquerade(&iface_name, tun_subnet, ifaces)?;
    }
    _ => {}
}

// Run PostUp hooks (30s timeout per hook, via spawn_blocking)
for cmd in &iface_cfg.post_up {
    net_mgr.run_hook(cmd, &iface_name)?;
}
```

### 4c. Per-Peer ACL Wiring

When configuring peers:

```rust
if let Some(acl) = &peer_cfg.acl {
    let mut acl_table = AllowedIps::new();
    for cidr in &acl.allow_destinations {
        let (ip, prefix_len) = parse_cidr(cidr)?;
        acl_table.insert(ip, prefix_len, ());
    }
    peer_handle.set_acl_destinations(Some(acl_table));
}
```

### 4d. QUIC Multi-Peer Wiring (Bug #3)

Pass known peer public keys to the accept loop:

```rust
let known_peer_pks: HashSet<[u8; 32]> = iface_cfg.peers.iter()
    .map(|p| decode_key(&p.public_key))
    .collect::<Result<_>>()?;

tokio::spawn(quic_accept_loop(
    quic_endpoint,
    key_installer,
    known_peer_pks,
    known_peers,
));
```

### 4e. Cleanup on `cmd_down` and Ctrl+C

Reverse order of setup. Errors logged but don't prevent further cleanup.

```rust
// 1. PostDown hooks (may depend on routes/addresses)
for cmd in &iface_cfg.post_down {
    let _ = net_mgr.run_hook(cmd, &iface_name).map_err(|e| warn!("post_down: {e}"));
}
// 2. Remove masquerade
let _ = net_mgr.remove_masquerade(&iface_name);
// 3. Remove routes (each peer's allowed_ips)
for peer_cfg in &iface_cfg.peers {
    for allowed_ip in &peer_cfg.allowed_ips {
        if let Ok((dest, prefix_len)) = parse_cidr(allowed_ip) {
            let _ = net_mgr.remove_route(&iface_name, dest, prefix_len);
        }
    }
}
// 4. Remove addresses
for addr_str in &iface_cfg.address {
    if let Ok((ip, prefix_len)) = parse_cidr(addr_str) {
        let _ = net_mgr.remove_address(&iface_name, ip, prefix_len);
    }
}
// 5. TUN device dropped automatically
```

The Ctrl+C signal handler calls the same cleanup path. The `cmd_up` function
stores `Arc<NetworkManager>`, `iface_name`, and `iface_cfg` (cloned) in the
signal handler closure so cleanup can proceed even if the main task panics.

**Crash recovery**: If the process is killed (SIGKILL) or panics before the
signal handler runs, routes/addresses/masquerade rules are orphaned. On the
next `cmd_up` for the same interface, perform idempotent cleanup first:
call `remove_masquerade`, `remove_route`, and `remove_address` for the
configured values before starting setup. This is safe because all
`NetworkManager` methods are idempotent — removing non-existent state is a
no-op.

---

## Layer 5: Documentation

### README Fixes (Issue #7)

| Current Claim | Fix |
|---|---|
| `transport` defaults to `"udp"` | Keep — now accurate since bug #2 is fixed |
| `quic.port` defaults to `443` | Change to: "Defaults to `listen_port + 1` if omitted" |
| JSONC comments supported | Remove claim. State: config must be valid JSON |
| `configs/` directory with examples | Create directory with working examples |

Add undocumented peer fields to the Peer Fields table: `pq_public_key`, `role`,
`relay_for`.

Fix the README example config to work out of the box (either UDP without `quic`
block, or QUIC with a proper `quic` block).

### QUIC Port Convention (Issue #8)

New section under Configuration:

> When using `"transport": "quic"`, the QUIC session handshake uses a separate
> port. Set `quic.port` in config, or omit to default to `listen_port + 1`.
> The client connects to the server's endpoint port + 1 for the QUIC handshake.
> Both ports must be reachable.

### New Config Fields Documentation

Document `masquerade`, `acl`, `post_up`, `post_down` with examples in the
Configuration Reference table and a dedicated "Network Setup" section.

### Example Configs (Issue #9)

Create `configs/` directory:

- `configs/simple-client-server.json` — Single client, UDP transport, minimal
- `configs/multi-client-quic-server.json` — 3 peers, QUIC, masquerade, ACLs
- `configs/lan-routing-server.json` — Server with LAN routing + PostUp/PostDown
- `configs/systemd/ironguard@.service` — systemd unit template
- `configs/launchd/net.ironguard.plist` — launchd plist template

### CLAUDE.md Updates

Add: `NetworkManager` trait, new config fields, transport branching, `configs/` directory.

---

## Testing Strategy

### Unit Tests (`cargo test`)

| Area | Tests |
|---|---|
| Config schema | Deserialize all new fields (masquerade variants, acl, post_up/post_down). Round-trip serde. Validation rejects bad CIDRs. `QuicConfig.port` defaults to `None`. |
| ACL filter | `RoutingTable<()>` ACL: matching IPs pass, non-matching drop. `None` = unrestricted. IPv4 + IPv6. Test BOTH send and receive directions. |
| PeerLookup | Correct peer for known IP. `None` for unknown IP. No wildcard fallback. Test with multiple wildcard peers — must return `None`, not first. |
| Masquerade enum | Serde parses `false`, `true`, `["en0"]`, absent field correctly. Verify `null` is rejected. |
| mTLS cert | Generate cert with WG pubkey in CN. Round-trip: generate → parse → extract → matches original key. |
| QuicConfig.port | `None` when omitted. Resolves to `listen_port + 1`. Error when both absent with QUIC transport. |

### Integration Tests (dummy platform)

| Test | Description |
|---|---|
| Address assignment | Dummy `NetworkManager` — verify `add_address` + `add_route` called correctly |
| Cleanup ordering | `cmd_down` calls in reverse: post_down → masquerade → routes → addresses |
| UDP transport | Config with `transport: "udp"`, no `quic` block → starts without error |
| QUIC transport | Config with `transport: "quic"` + `quic` block → `SessionManager` created |
| ACL enforcement (outbound) | Restricted peer sends to disallowed dest via TUN→encrypt path → dropped |
| ACL enforcement (inbound) | Restricted peer's decrypted packet to disallowed dest → dropped before TUN write |
| Multi-peer QUIC | Two mTLS connections with different cert CNs → keypairs to correct peers |
| Crash recovery | Simulate stale routes/addresses from previous run → `cmd_up` cleans before setup |
| Default route guard | Config with `0.0.0.0/0` in allowed_ips → route skipped with warning |

### Field Test via `/tunnel-perf`

Build → sync to server → test on the real 3-client topology:

| Step | Verifies | Pass criteria |
|---|---|---|
| Build | Code compiles | `cargo build --workspace` clean |
| Sync | Binary deployed | rsync succeeds |
| UDP transport start | Bug #2 fixed | `ironguard up` with `transport: "udp"` exits 0 |
| Address assigned | Bug #1 fixed | `ifconfig`/`ip addr` shows tunnel IP |
| Routes installed | Bug #1 extension | Routing table has peer allowed_ips |
| Ping peers | Connectivity | `ping -c3 10.10.10.x` succeeds |
| QUIC multi-peer | Bug #3 fixed | Server logs show distinct peer PKs |
| iperf3 throughput | No regression | Within 10% of baseline |
| PostUp/PostDown | Feature #6 works | Hook side-effect verified |
| Cleanup (down) | Teardown | No addresses, routes, or firewall rules remain |
| Cleanup (Ctrl+C) | Signal handler | Same as above |

ACL enforcement and masquerade field-tested later on the office Mac with LAN access.

---

## Files Changed

| Crate | Files | Nature |
|---|---|---|
| `ironguard-config` | `types.rs`, `validate.rs`, `Cargo.toml` | New fields, new validation |
| `ironguard-platform` | `net_manager.rs` (new), `macos/net_manager.rs` (new), `linux/net_manager.rs` (new), `dummy/net_manager.rs` (new), `macos/mod.rs`, `linux/mod.rs`, `dummy/mod.rs` | New trait + 3 implementations |
| `ironguard-core` | `session/tasks.rs`, `session/quic.rs`, `router/peer.rs`, `router/send.rs`, `router/receive.rs`, `device.rs`, `Cargo.toml` | Bug fixes, mTLS, ACL filter (both directions) |
| `ironguard-cli` | `main.rs` | Transport branching, Noise handshake wiring, address/route/masquerade/hook wiring, cleanup, crash recovery |
| root | `README.md`, `CLAUDE.md` | Doc fixes |
| root | `configs/` (new directory, 5 files) | Example configs + service files |

### New Dependencies

| Crate | Dependency | Purpose |
|---|---|---|
| `ironguard-core` | `x509-parser` | Extract WG pubkey from QUIC client cert CN |
