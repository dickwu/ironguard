# Issue #2 Field Test Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix TUN address assignment (Bug #1), multi-peer QUIC routing (Bug #3), add masquerade/ACL/PostUp-PostDown features, deprecate UDP transport, update all docs.

**Architecture:** Layered bottom-up: config schema -> platform NetworkManager trait -> core ACL+mTLS -> CLI wiring -> docs. Each layer is independently testable. QUIC is the only transport; legacy WireGuard is not supported.

**Tech Stack:** Rust 2024, serde (custom deserializer), quinn/rustls (mTLS), rcgen (cert gen), x509-parser (cert parsing), treebitmap (ACL), std::process::Command (platform syscalls)

**Spec:** `docs/superpowers/specs/2026-03-27-issue2-field-test-fixes-design.md`

---

## File Map

### New Files
| File | Responsibility |
|------|---------------|
| `crates/ironguard-platform/src/net_manager.rs` | `NetworkManager` trait definition |
| `crates/ironguard-platform/src/macos/net_manager.rs` | macOS impl (ifconfig, route, pfctl) |
| `crates/ironguard-platform/src/linux/net_manager.rs` | Linux impl (ip, nft) |
| `crates/ironguard-platform/src/dummy/net_manager.rs` | Test impl (records ops) |
| `configs/simple-client-server.json` | Example: single client QUIC |
| `configs/multi-client-quic-server.json` | Example: 3 peers, masquerade, ACLs |
| `configs/lan-routing-server.json` | Example: LAN routing + hooks |
| `configs/systemd/ironguard@.service` | systemd unit template |
| `configs/launchd/net.ironguard.plist` | launchd plist template |

### Modified Files
| File | Changes |
|------|---------|
| `crates/ironguard-config/src/types.rs` | Add Masquerade, PeerAcl, post_up/down, QuicConfig cert fields, deprecate transport |
| `crates/ironguard-config/src/validate.rs` | New validation rules for all new fields |
| `crates/ironguard-platform/src/lib.rs` | Export `net_manager` module |
| `crates/ironguard-platform/src/macos/mod.rs` | Export `net_manager` |
| `crates/ironguard-platform/src/linux/mod.rs` | Export `net_manager` |
| `crates/ironguard-platform/src/dummy/mod.rs` | Export `net_manager` |
| `crates/ironguard-core/Cargo.toml` | Add `x509-parser` dep |
| `crates/ironguard-core/src/session/quic.rs` | Add `extract_wg_pubkey_from_cert`, `generate_wg_cert` |
| `crates/ironguard-core/src/session/tasks.rs` | Remove wildcard fallback, add mTLS identity extraction |
| `crates/ironguard-core/src/router/peer.rs` | Add `acl_destinations` field to PeerInner |
| `crates/ironguard-core/src/router/device.rs` | Add outbound ACL check in `send()` |
| `crates/ironguard-core/src/router/receive.rs` | Add inbound ACL check in `sequential_work()` |
| `crates/ironguard-cli/src/main.rs` | Transport deprecation, gen-quic-cert cmd, NetworkManager wiring, cleanup handlers |
| `README.md` | Already partially done; finish remaining fixes |
| `CLAUDE.md` | Already partially done; finish remaining fixes |

---

## Task 1: Config Schema — Masquerade Type + Custom Deserializer

**Files:**
- Modify: `crates/ironguard-config/src/types.rs:12-37`
- Test: `crates/ironguard-config/tests/config_to_core.rs` (append)

- [ ] **Step 1: Write failing tests for Masquerade deserialization**

Append to `crates/ironguard-config/tests/config_to_core.rs`:

```rust
#[test]
fn masquerade_deserialize_false() {
    let json = r#"{"masquerade": false}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper { masquerade: ironguard_config::types::Masquerade }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert!(w.masquerade.is_disabled());
}

#[test]
fn masquerade_deserialize_true() {
    let json = r#"{"masquerade": true}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper { masquerade: ironguard_config::types::Masquerade }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert!(matches!(w.masquerade, ironguard_config::types::Masquerade::All));
}

#[test]
fn masquerade_deserialize_interfaces() {
    let json = r#"{"masquerade": ["en0", "eth0"]}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper { masquerade: ironguard_config::types::Masquerade }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    match w.masquerade {
        ironguard_config::types::Masquerade::Interfaces(v) => assert_eq!(v, vec!["en0", "eth0"]),
        other => panic!("expected Interfaces, got {:?}", other),
    }
}

#[test]
fn masquerade_deserialize_absent() {
    let json = r#"{}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        masquerade: ironguard_config::types::Masquerade,
    }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert!(w.masquerade.is_disabled());
}

#[test]
fn masquerade_deserialize_null_rejected() {
    let json = r#"{"masquerade": null}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper { masquerade: ironguard_config::types::Masquerade }
    assert!(serde_json::from_str::<Wrapper>(json).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ironguard-config masquerade_deserialize`
Expected: compile error — `Masquerade` type does not exist

- [ ] **Step 3: Implement Masquerade type with custom deserializer**

In `crates/ironguard-config/src/types.rs`, after the existing imports, add:

```rust
use serde::de::{self, Deserializer, Visitor};

#[derive(Clone, Debug, Default)]
pub enum Masquerade {
    #[default]
    Disabled,
    All,
    Interfaces(Vec<String>),
}

impl Masquerade {
    pub fn is_disabled(&self) -> bool {
        matches!(self, Masquerade::Disabled)
    }
}

impl serde::Serialize for Masquerade {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Masquerade::Disabled => serializer.serialize_bool(false),
            Masquerade::All => serializer.serialize_bool(true),
            Masquerade::Interfaces(v) => v.serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Masquerade {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MasqueradeVisitor;
        impl<'de> Visitor<'de> for MasqueradeVisitor {
            type Value = Masquerade;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("false, true, or array of interface names")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Masquerade, E> {
                Ok(if v { Masquerade::All } else { Masquerade::Disabled })
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Masquerade, A::Error> {
                let mut ifaces = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    ifaces.push(s);
                }
                Ok(Masquerade::Interfaces(ifaces))
            }
        }
        deserializer.deserialize_any(MasqueradeVisitor)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ironguard-config masquerade_deserialize`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-config/src/types.rs crates/ironguard-config/tests/config_to_core.rs
git commit -m "feat(config): add Masquerade type with custom deserializer"
```

---

## Task 2: Config Schema — PeerAcl, PostUp/PostDown, QuicConfig Changes

**Files:**
- Modify: `crates/ironguard-config/src/types.rs:12-37` (InterfaceConfig), `types.ts:40-59` (QuicConfig), `types.ts:97-123` (PeerConfig)
- Test: `crates/ironguard-config/tests/config_to_core.rs` (append)

- [ ] **Step 1: Write failing tests for new config fields**

Append to `crates/ironguard-config/tests/config_to_core.rs`:

```rust
#[test]
fn peer_acl_deserialize() {
    let json = r#"{"acl": {"allow_destinations": ["10.0.0.0/24", "192.168.1.0/24"]}}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper { acl: Option<ironguard_config::types::PeerAcl> }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    let acl = w.acl.unwrap();
    assert_eq!(acl.allow_destinations, vec!["10.0.0.0/24", "192.168.1.0/24"]);
}

#[test]
fn peer_acl_absent() {
    let json = r#"{}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        acl: Option<ironguard_config::types::PeerAcl>,
    }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert!(w.acl.is_none());
}

#[test]
fn post_up_down_deserialize() {
    let json = r#"{"post_up": ["echo up %i"], "post_down": ["echo down %i"]}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        post_up: Vec<String>,
        #[serde(default)]
        post_down: Vec<String>,
    }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert_eq!(w.post_up, vec!["echo up %i"]);
    assert_eq!(w.post_down, vec!["echo down %i"]);
}

#[test]
fn quic_config_port_optional() {
    let json = r#"{"sni": "test.com"}"#;
    let qc: ironguard_config::types::QuicConfig = serde_json::from_str(json).unwrap();
    assert!(qc.port.is_none());
}

#[test]
fn quic_config_cert_fields() {
    let json = r#"{"port": 51821, "cert_file": "a.crt", "key_file": "a.key", "peer_certs": ["b.crt"]}"#;
    let qc: ironguard_config::types::QuicConfig = serde_json::from_str(json).unwrap();
    assert_eq!(qc.cert_file.as_deref(), Some("a.crt"));
    assert_eq!(qc.key_file.as_deref(), Some("a.key"));
    assert_eq!(qc.peer_certs, vec!["b.crt"]);
}

#[test]
fn transport_field_deprecated() {
    let json = r#"{"transport": "quic"}"#;
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        transport: Option<String>,
    }
    let w: Wrapper = serde_json::from_str(json).unwrap();
    assert_eq!(w.transport.as_deref(), Some("quic"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ironguard-config peer_acl_deserialize quic_config_port_optional`
Expected: compile error — `PeerAcl` does not exist, `QuicConfig.port` is `u16` not `Option<u16>`

- [ ] **Step 3: Add PeerAcl struct and update InterfaceConfig/PeerConfig/QuicConfig**

In `crates/ironguard-config/src/types.rs`:

After the `Masquerade` impl, add:
```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAcl {
    pub allow_destinations: Vec<String>,
}
```

Add to `InterfaceConfig` struct (after `peers` field at L36):
```rust
    #[serde(default, skip_serializing_if = "Masquerade::is_disabled")]
    pub masquerade: Masquerade,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_up: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_down: Vec<String>,
```

Change `transport` field (L28) from `String` with default to:
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
```
Remove the `default_transport()` function if it exists.

Add to `PeerConfig` struct (after `relay_for` at L122):
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<PeerAcl>,
```

Change `QuicConfig.port` (L41) from `pub port: u16` to:
```rust
    #[serde(default)]
    pub port: Option<u16>,
```

Add to `QuicConfig` struct (after existing fields):
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_certs: Vec<String>,
```

Fix all compile errors from `QuicConfig.port` type change: search for `quic_cfg.port` in `main.rs` and change to `quic_cfg.port.unwrap_or(0)` temporarily (we fix this properly in Task 8).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ironguard-config`
Expected: all new tests PASS, existing tests still PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-config/src/types.rs crates/ironguard-config/tests/config_to_core.rs
git commit -m "feat(config): add PeerAcl, PostUp/PostDown, QuicConfig cert fields, deprecate transport"
```

---

## Task 3: Config Validation Updates

**Files:**
- Modify: `crates/ironguard-config/src/validate.rs:15-83`
- Test: `crates/ironguard-config/tests/config_to_core.rs` (append)

- [ ] **Step 1: Write failing tests for new validation rules**

```rust
#[test]
fn validate_transport_udp_rejected() {
    let config = make_config_with_transport(Some("udp".into()));
    let result = ironguard_config::validate::validate(&config);
    assert!(result.is_err() || result.unwrap().iter().any(|w| w.contains("UDP")));
}

#[test]
fn validate_transport_quic_warns() {
    let config = make_config_with_transport(Some("quic".into()));
    let result = ironguard_config::validate::validate(&config).unwrap();
    assert!(result.iter().any(|w| w.contains("deprecated")));
}

#[test]
fn validate_acl_bad_cidr_rejected() {
    let config = make_config_with_acl(vec!["not-a-cidr".into()]);
    let result = ironguard_config::validate::validate(&config);
    assert!(result.is_err() || result.unwrap().iter().any(|w| w.contains("CIDR")));
}

#[test]
fn validate_quic_port_overflow() {
    let config = make_config_with_listen_port(65535, None);
    let result = ironguard_config::validate::validate(&config);
    assert!(result.is_err() || result.unwrap().iter().any(|w| w.contains("65535")));
}

#[test]
fn validate_cert_file_without_key_file() {
    let config = make_config_with_quic_certs(Some("a.crt".into()), None);
    let result = ironguard_config::validate::validate(&config);
    assert!(result.is_err() || result.unwrap().iter().any(|w| w.contains("cert_file")));
}
```

Note: `make_config_with_*` are test helpers that build a minimal `Config` struct with the specific field set. Implement them as needed — each returns `Config` with one interface containing the test values.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ironguard-config validate_`
Expected: FAIL — validation rules don't exist yet

- [ ] **Step 3: Implement validation rules**

In `crates/ironguard-config/src/validate.rs`, add to the `validate` function body (after existing checks):

```rust
// Transport deprecation
if let Some(transport) = &iface_cfg.transport {
    if transport == "udp" {
        return Err(anyhow::anyhow!(
            "UDP transport is not supported. IronGuard uses QUIC-based \
             session management. Remove the transport field or set it to \"quic\"."
        ));
    }
    warnings.push(format!(
        "{}: transport field is deprecated — IronGuard uses QUIC exclusively",
        iface_name
    ));
}

// QUIC config required
if iface_cfg.quic.is_none() {
    warnings.push(format!(
        "{}: missing [quic] config section — required for IronGuard",
        iface_name
    ));
}

// QUIC port overflow guard
if let Some(quic_cfg) = &iface_cfg.quic {
    if quic_cfg.port.is_none() {
        if let Some(lp) = iface_cfg.listen_port {
            if lp >= 65535 {
                warnings.push(format!(
                    "{}: listen_port {} too high for QUIC auto-assignment (needs < 65535), set quic.port explicitly",
                    iface_name, lp
                ));
            }
        }
    }
    // cert_file and key_file must both be set or both absent
    match (&quic_cfg.cert_file, &quic_cfg.key_file) {
        (Some(_), None) | (None, Some(_)) => {
            warnings.push(format!(
                "{}: quic.cert_file and quic.key_file must both be set",
                iface_name
            ));
        }
        _ => {}
    }
}

// ACL validation
for (i, peer) in iface_cfg.peers.iter().enumerate() {
    if let Some(acl) = &peer.acl {
        for cidr in &acl.allow_destinations {
            if !is_valid_cidr(cidr) {
                warnings.push(format!(
                    "{}: peer[{}].acl.allow_destinations: invalid CIDR \"{}\"",
                    iface_name, i, cidr
                ));
            }
        }
    }
}

// Masquerade requires address
if !iface_cfg.masquerade.is_disabled() && iface_cfg.address.is_empty() {
    warnings.push(format!(
        "{}: masquerade requires at least one interface address",
        iface_name
    ));
}

// PostUp/PostDown %i warning
for cmd in &iface_cfg.post_up {
    if !cmd.contains("%i") {
        warnings.push(format!("{}: post_up command has no %i placeholder: {}", iface_name, cmd));
    }
}
for cmd in &iface_cfg.post_down {
    if !cmd.contains("%i") {
        warnings.push(format!("{}: post_down command has no %i placeholder: {}", iface_name, cmd));
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ironguard-config validate_`
Expected: all PASS

- [ ] **Step 5: Run full config test suite**

Run: `cargo test -p ironguard-config`
Expected: all tests PASS (including existing ones)

- [ ] **Step 6: Commit**

```bash
git add crates/ironguard-config/src/validate.rs crates/ironguard-config/tests/config_to_core.rs
git commit -m "feat(config): add validation for transport deprecation, ACL CIDRs, QUIC port, masquerade"
```

---

## Task 4: Platform — NetworkManager Trait + Dummy Implementation

**Files:**
- Create: `crates/ironguard-platform/src/net_manager.rs`
- Create: `crates/ironguard-platform/src/dummy/net_manager.rs`
- Modify: `crates/ironguard-platform/src/lib.rs:1-16`
- Modify: `crates/ironguard-platform/src/dummy/mod.rs:1-2`

- [ ] **Step 1: Write failing test for dummy NetworkManager**

Create `crates/ironguard-platform/src/dummy/net_manager.rs`:

```rust
use crate::net_manager::{NetworkManager, NetManagerOp};
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Mutex;

pub struct DummyNetManager {
    pub ops: Mutex<Vec<NetManagerOp>>,
}

impl DummyNetManager {
    pub fn new() -> Self {
        Self { ops: Mutex::new(Vec::new()) }
    }

    pub fn get_ops(&self) -> Vec<NetManagerOp> {
        self.ops.lock().unwrap().clone()
    }
}

impl NetworkManager for DummyNetManager {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::AddAddress {
            iface: iface.to_string(), addr, prefix_len,
        });
        Ok(())
    }
    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::RemoveAddress {
            iface: iface.to_string(), addr, prefix_len,
        });
        Ok(())
    }
    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::AddRoute {
            iface: iface.to_string(), dest, prefix_len,
        });
        Ok(())
    }
    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::RemoveRoute {
            iface: iface.to_string(), dest, prefix_len,
        });
        Ok(())
    }
    fn add_masquerade(&self, tun_iface: &str, tun_subnet: &str, out_ifaces: &[String]) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::AddMasquerade {
            tun_iface: tun_iface.to_string(),
            tun_subnet: tun_subnet.to_string(),
            out_ifaces: out_ifaces.to_vec(),
        });
        Ok(())
    }
    fn remove_masquerade(&self, tun_iface: &str) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::RemoveMasquerade {
            tun_iface: tun_iface.to_string(),
        });
        Ok(())
    }
    fn run_hook(&self, command: &str, iface: &str) -> Result<()> {
        self.ops.lock().unwrap().push(NetManagerOp::RunHook {
            command: command.to_string(), iface: iface.to_string(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_records_ops() {
        let mgr = DummyNetManager::new();
        mgr.add_address("utun9", "10.0.0.1".parse().unwrap(), 24).unwrap();
        mgr.add_route("utun9", "10.0.0.0".parse().unwrap(), 24).unwrap();
        let ops = mgr.get_ops();
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], NetManagerOp::AddAddress { iface, .. } if iface == "utun9"));
        assert!(matches!(&ops[1], NetManagerOp::AddRoute { iface, .. } if iface == "utun9"));
    }
}
```

- [ ] **Step 2: Create the trait definition**

Create `crates/ironguard-platform/src/net_manager.rs`:

```rust
use anyhow::Result;
use std::net::IpAddr;

pub trait NetworkManager: Send + Sync {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;
    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;
    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;
    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;
    fn add_masquerade(&self, tun_iface: &str, tun_subnet: &str, out_ifaces: &[String]) -> Result<()>;
    fn remove_masquerade(&self, tun_iface: &str) -> Result<()>;
    fn run_hook(&self, command: &str, iface: &str) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum NetManagerOp {
    AddAddress { iface: String, addr: IpAddr, prefix_len: u8 },
    RemoveAddress { iface: String, addr: IpAddr, prefix_len: u8 },
    AddRoute { iface: String, dest: IpAddr, prefix_len: u8 },
    RemoveRoute { iface: String, dest: IpAddr, prefix_len: u8 },
    AddMasquerade { tun_iface: String, tun_subnet: String, out_ifaces: Vec<String> },
    RemoveMasquerade { tun_iface: String },
    RunHook { command: String, iface: String },
}
```

- [ ] **Step 3: Wire modules into lib.rs and dummy/mod.rs**

Add to `crates/ironguard-platform/src/lib.rs`:
```rust
pub mod net_manager;
```

Add to `crates/ironguard-platform/src/dummy/mod.rs`:
```rust
pub mod net_manager;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ironguard-platform dummy_records_ops`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-platform/src/net_manager.rs crates/ironguard-platform/src/dummy/net_manager.rs crates/ironguard-platform/src/lib.rs crates/ironguard-platform/src/dummy/mod.rs
git commit -m "feat(platform): add NetworkManager trait and dummy implementation"
```

---

## Task 5: Platform — macOS NetworkManager Implementation

**Files:**
- Create: `crates/ironguard-platform/src/macos/net_manager.rs`
- Modify: `crates/ironguard-platform/src/macos/mod.rs`

- [ ] **Step 1: Create macOS implementation**

Create `crates/ironguard-platform/src/macos/net_manager.rs`:

```rust
use crate::net_manager::NetworkManager;
use anyhow::{Context, Result};
use std::net::IpAddr;
use std::process::Command;
use tracing::debug;

pub struct MacosNetManager;

impl MacosNetManager {
    pub fn new() -> Self { Self }

    fn run_cmd(args: &[&str]) -> Result<()> {
        debug!("exec: {}", args.join(" "));
        let output = Command::new(args[0])
            .args(&args[1..])
            .output()
            .with_context(|| format!("failed to run {}", args[0]))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Idempotent: ignore "already exists" / "not found" errors
            if stderr.contains("File exists")
                || stderr.contains("not in table")
                || stderr.contains("Can't assign requested address")
            {
                debug!("idempotent skip: {}", stderr.trim());
                return Ok(());
            }
            anyhow::bail!("{}: {}", args.join(" "), stderr.trim());
        }
        Ok(())
    }

    fn shell_escape(s: &str) -> String {
        s.replace('\'', "'\\''")
    }
}

impl NetworkManager for MacosNetManager {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        match addr {
            IpAddr::V4(v4) => {
                Self::run_cmd(&["ifconfig", iface, "inet", &format!("{}/{}", v4, prefix_len), &v4.to_string()])
            }
            IpAddr::V6(v6) => {
                Self::run_cmd(&["ifconfig", iface, "inet6", &v6.to_string(), "prefixlen", &prefix_len.to_string()])
            }
        }
    }

    fn remove_address(&self, iface: &str, addr: IpAddr, _prefix_len: u8) -> Result<()> {
        Self::run_cmd(&["ifconfig", iface, "delete", &addr.to_string()])
    }

    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        Self::run_cmd(&["route", "-n", "add", "-net", &format!("{}/{}", dest, prefix_len), "-interface", iface])
    }

    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        Self::run_cmd(&["route", "-n", "delete", "-net", &format!("{}/{}", dest, prefix_len), "-interface", iface])
    }

    fn add_masquerade(&self, tun_iface: &str, tun_subnet: &str, out_ifaces: &[String]) -> Result<()> {
        let anchor = format!("com.ironguard.{}", tun_iface);
        let ifaces = if out_ifaces.is_empty() { vec!["en0".to_string()] } else { out_ifaces.to_vec() };
        let mut rules = String::new();
        for iface in &ifaces {
            rules.push_str(&format!("nat on {} from {} to any -> ({})\n", iface, tun_subnet, iface));
        }
        let tmp = format!("/tmp/ironguard-{}.pf", tun_iface);
        std::fs::write(&tmp, &rules)?;
        Self::run_cmd(&["pfctl", "-a", &anchor, "-f", &tmp])?;
        Self::run_cmd(&["pfctl", "-e"])?;
        std::fs::remove_file(&tmp).ok();
        Ok(())
    }

    fn remove_masquerade(&self, tun_iface: &str) -> Result<()> {
        let anchor = format!("com.ironguard.{}", tun_iface);
        Self::run_cmd(&["pfctl", "-a", &anchor, "-F", "all"])
    }

    fn run_hook(&self, command: &str, iface: &str) -> Result<()> {
        let escaped_iface = Self::shell_escape(iface);
        let expanded = command.replace("%i", &escaped_iface);
        debug!("hook: {}", expanded);
        let output = Command::new("sh")
            .arg("-c")
            .arg(&expanded)
            .output()
            .context("failed to run hook")?;
        if !output.status.success() {
            anyhow::bail!("hook failed: {}", String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(())
    }
}
```

- [ ] **Step 2: Export from macos/mod.rs**

Add to `crates/ironguard-platform/src/macos/mod.rs`:
```rust
pub mod net_manager;
```

- [ ] **Step 3: Build to verify compilation**

Run: `cargo build -p ironguard-platform`
Expected: compiles clean

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-platform/src/macos/net_manager.rs crates/ironguard-platform/src/macos/mod.rs
git commit -m "feat(platform): add macOS NetworkManager (ifconfig, route, pfctl)"
```

---

## Task 6: Platform — Linux NetworkManager Implementation

**Files:**
- Create: `crates/ironguard-platform/src/linux/net_manager.rs`
- Modify: `crates/ironguard-platform/src/linux/mod.rs`

- [ ] **Step 1: Create Linux implementation**

Create `crates/ironguard-platform/src/linux/net_manager.rs` — same structure as macOS but using `ip` and `nft` commands. Follow the same `run_cmd` + idempotent error handling pattern. See spec Layer 2 for exact commands.

- [ ] **Step 2: Export from linux/mod.rs**

Add `pub mod net_manager;` to `crates/ironguard-platform/src/linux/mod.rs`.

- [ ] **Step 3: Build to verify**

Run: `cargo build -p ironguard-platform`
Expected: compiles clean

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-platform/src/linux/net_manager.rs crates/ironguard-platform/src/linux/mod.rs
git commit -m "feat(platform): add Linux NetworkManager (ip, nft)"
```

---

## Task 7: Core — ACL Filter on PeerInner + Router

**Files:**
- Modify: `crates/ironguard-core/src/router/peer.rs:36-45` (PeerInner struct)
- Modify: `crates/ironguard-core/src/router/peer.rs:195-218` (new_peer)
- Modify: `crates/ironguard-core/src/router/device.rs:199-215` (send method)
- Modify: `crates/ironguard-core/src/router/receive.rs:186-225` (sequential_work TUN write)
- Test: `crates/ironguard-core/src/router/tests.rs` (append)

- [ ] **Step 1: Write failing test for ACL filtering**

Append to `crates/ironguard-core/src/router/tests.rs`:

```rust
#[test]
fn acl_blocks_disallowed_destination() {
    // Build a RoutingTable ACL that only allows 10.0.0.0/24
    let mut acl = RoutingTable::new();
    acl.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24, ());

    // 10.0.0.5 should match
    let allowed_pkt = make_ipv4_packet(
        Ipv4Addr::new(192, 168, 1, 1), // src
        Ipv4Addr::new(10, 0, 0, 5),    // dst — in ACL
    );
    assert!(acl.get_route(&allowed_pkt).is_some());

    // 192.168.2.1 should NOT match
    let blocked_pkt = make_ipv4_packet(
        Ipv4Addr::new(192, 168, 1, 1), // src
        Ipv4Addr::new(192, 168, 2, 1), // dst — NOT in ACL
    );
    assert!(acl.get_route(&blocked_pkt).is_none());
}
```

Note: `make_ipv4_packet` is a test helper that constructs a minimal IPv4 header with src/dst addresses. If it doesn't already exist, add it.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p ironguard-core acl_blocks`
Expected: compile error or test failure

- [ ] **Step 3: Add `acl_destinations` field to PeerInner**

In `crates/ironguard-core/src/router/peer.rs`, add to `PeerInner` struct (after `endpoint` at L44):
```rust
    pub acl_destinations: spin::RwLock<Option<RoutingTable<()>>>,
```

Add import at top:
```rust
use crate::router::route::RoutingTable;
```

In `new_peer()` (L195-218), add to the PeerInner initialization:
```rust
    acl_destinations: spin::RwLock::new(None),
```

Add setter method after `new_peer()`:
```rust
impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> PeerHandle<E, C, T, B> {
    pub fn set_acl_destinations(&self, acl: Option<RoutingTable<()>>) {
        *self.peer.inner.acl_destinations.write() = acl;
    }
}
```

- [ ] **Step 4: Add outbound ACL check in device.rs send()**

In `crates/ironguard-core/src/router/device.rs`, in the `send()` method (L199-215), after the route lookup returns a peer (L206-210) and before `peer.send(msg, true)` (L213), insert:

```rust
    // ACL check: if peer has destination restrictions, verify the packet's dst IP is allowed
    if let Some(ref acl) = *peer.inner.acl_destinations.read() {
        if acl.get_route(packet).is_none() {
            return Err(RouterError::NoCryptoKeyRoute); // destination not in peer's ACL
        }
    }
```

- [ ] **Step 5: Add inbound ACL check in receive.rs sequential_work()**

In `crates/ironguard-core/src/router/receive.rs`, in `sequential_work()`, before the TUN write at L220-223 (after `inner_length` check at L189), insert:

```rust
    // Inbound ACL: check if the decrypted packet's destination is allowed for this peer
    if let Some(ref acl) = *peer.inner.acl_destinations.read() {
        let ip_data = &msg.1[HEADER_SIZE..HEADER_SIZE + inner];
        if acl.get_route(ip_data).is_none() {
            return; // peer not allowed to reach this destination
        }
    }
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p ironguard-core`
Expected: all tests PASS including the new ACL test

- [ ] **Step 7: Commit**

```bash
git add crates/ironguard-core/src/router/peer.rs crates/ironguard-core/src/router/device.rs crates/ironguard-core/src/router/receive.rs crates/ironguard-core/src/router/tests.rs
git commit -m "feat(core): add per-peer ACL filter in both send and receive paths"
```

---

## Task 8: Core — mTLS Cert Generation + Peer Identity Extraction

**Files:**
- Modify: `crates/ironguard-core/Cargo.toml` (add x509-parser)
- Modify: `crates/ironguard-core/src/session/quic.rs:132-176`

- [ ] **Step 1: Add x509-parser dependency**

In `crates/ironguard-core/Cargo.toml`, add under `[dependencies]`:
```toml
x509-parser = { version = "0.16", optional = true }
base64 = { version = "0.22", optional = true }
```

Add to `quic` feature:
```toml
quic = ["dep:quinn", "dep:rustls", "dep:rcgen", "dep:serde", "dep:serde_json", "dep:x509-parser", "dep:base64"]
```

- [ ] **Step 2: Write failing test for cert generation + pubkey extraction**

In `crates/ironguard-core/src/session/quic.rs`, add at bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wg_cert_roundtrip() {
        let wg_pk = [42u8; 32]; // dummy WG public key
        let (cert_der, _key_der) = generate_wg_cert(&wg_pk).unwrap();
        let extracted = extract_wg_pubkey_from_cert(&cert_der).unwrap();
        assert_eq!(extracted, wg_pk);
    }

    #[test]
    fn generate_wg_cert_has_ca_flag() {
        let wg_pk = [1u8; 32];
        let (cert_der, _) = generate_wg_cert(&wg_pk).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p ironguard-core generate_wg_cert`
Expected: compile error — functions don't exist

- [ ] **Step 4: Implement generate_wg_cert and extract_wg_pubkey_from_cert**

In `crates/ironguard-core/src/session/quic.rs`, add:

```rust
#[cfg(feature = "quic")]
use base64::Engine;

/// Generate a self-signed X.509 cert with the WireGuard public key in the CN field.
/// Sets is_ca=true so WebPkiClientVerifier accepts it as a trust anchor.
#[cfg(feature = "quic")]
pub fn generate_wg_cert(
    wg_pubkey: &[u8; 32],
) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
), SessionError> {
    let cn = base64::engine::general_purpose::STANDARD.encode(wg_pubkey);
    let mut params = rcgen::CertificateParams::new(vec!["ironguard".to_string()])
        .map_err(|e| SessionError::CertGeneration(e.to_string()))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| SessionError::CertGeneration(e.to_string()))?;
    let cert = params.self_signed(&key_pair)
        .map_err(|e| SessionError::CertGeneration(e.to_string()))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| SessionError::CertGeneration(e.to_string()))?;

    Ok((cert_der, key_der))
}

/// Extract the WireGuard public key from a certificate's CN field.
#[cfg(feature = "quic")]
pub fn extract_wg_pubkey_from_cert(
    cert_der: &rustls::pki_types::CertificateDer,
) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let cn = cert.subject().iter_common_name().next()?;
    let cn_str = cn.as_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(cn_str).ok()?;
    if decoded.len() != 32 { return None; }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&decoded);
    Some(pk)
}

/// Extract peer identity from a QUIC connection's client certificate.
#[cfg(feature = "quic")]
pub fn extract_peer_identity(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let certs = conn.peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()?;
    let cert = certs.first()?;
    extract_wg_pubkey_from_cert(cert)
}
```

Add `CertGeneration(String)` variant to `SessionError` if it doesn't exist.

- [ ] **Step 5: Run tests**

Run: `cargo test -p ironguard-core generate_wg_cert`
Expected: both tests PASS

- [ ] **Step 6: Commit**

```bash
git add crates/ironguard-core/Cargo.toml crates/ironguard-core/src/session/quic.rs
git commit -m "feat(core): mTLS cert generation with WG pubkey in CN + extraction"
```

---

## Task 9: Core — Fix PeerLookup Wildcard Fallback

**Files:**
- Modify: `crates/ironguard-core/src/session/tasks.rs:274-287`

- [ ] **Step 1: Write failing test**

In `crates/ironguard-core/src/session/tasks.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_addr_no_wildcard_fallback() {
        let lookup = PeerLookup::new();
        lookup.add_wildcard([1u8; 32]);
        lookup.add_wildcard([2u8; 32]);

        let unknown_addr = "203.0.113.1:12345".parse().unwrap();
        // Must return None, NOT the first wildcard
        assert!(lookup.lookup_by_addr(&unknown_addr).is_none());
    }

    #[test]
    fn lookup_by_addr_ip_match() {
        let lookup = PeerLookup::new();
        let addr = "10.0.0.1:51820".parse().unwrap();
        lookup.add(addr, [3u8; 32]);

        let query = "10.0.0.1:9999".parse().unwrap(); // different port, same IP
        assert_eq!(lookup.lookup_by_addr(&query), Some([3u8; 32]));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p ironguard-core lookup_by_addr_no_wildcard`
Expected: FAIL — wildcard fallback returns `Some([1u8; 32])`

- [ ] **Step 3: Remove the wildcard fallback**

In `crates/ironguard-core/src/session/tasks.rs`, change `lookup_by_addr` (L274-287):

```rust
pub fn lookup_by_addr(&self, addr: &std::net::SocketAddr) -> Option<[u8; 32]> {
    let entries = self.entries.read();
    for (entry_addr, pk) in entries.iter() {
        if entry_addr.ip() == addr.ip() {
            return Some(*pk);
        }
    }
    // No wildcard fallback — unknown peers must be identified via mTLS
    None
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ironguard-core lookup_by_addr`
Expected: both tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/ironguard-core/src/session/tasks.rs
git commit -m "fix(core): remove wildcard fallback from PeerLookup — fixes multi-peer routing"
```

---

## Task 10: Core — mTLS Identity in Accept Loop

**Files:**
- Modify: `crates/ironguard-core/src/session/tasks.rs:54-148` (quic_accept_loop)

- [ ] **Step 1: Add `known_peer_pks` parameter and mTLS identity extraction**

Change `quic_accept_loop` signature to accept a `HashSet<[u8; 32]>`:

```rust
pub async fn quic_accept_loop<K: KeyInstaller>(
    endpoint: quinn::Endpoint,
    session_mgr: Arc<SessionManager>,
    key_installer: Arc<K>,
    known_peers: Arc<PeerLookup>,
    known_peer_pks: std::collections::HashSet<[u8; 32]>,  // NEW
    data_port: u16,
    stop: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
)
```

Inside the connection handler (where `known_peers.lookup_by_addr(&remote_addr)` is called), replace with:

```rust
let peer_pk = match crate::session::quic::extract_peer_identity(&connection) {
    Some(pk) if known_peer_pks.contains(&pk) => pk,
    _ => {
        // Fall back to IP-based lookup (single-peer or known-endpoint case)
        match known_peers.lookup_by_addr(&remote_addr) {
            Some(pk) => pk,
            None => {
                tracing::warn!("unknown peer from {remote_addr}, no mTLS identity");
                return;
            }
        }
    }
};
```

- [ ] **Step 2: Fix all call sites of quic_accept_loop**

Search for `quic_accept_loop(` in `main.rs` and add the new `known_peer_pks` parameter. Use `std::collections::HashSet::new()` for now — wired properly in Task 12.

- [ ] **Step 3: Build to verify**

Run: `cargo build --workspace`
Expected: compiles clean

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-core/src/session/tasks.rs crates/ironguard-cli/src/main.rs
git commit -m "feat(core): add mTLS peer identity extraction to QUIC accept loop"
```

---

## Task 11: CLI — gen-quic-cert Command

**Files:**
- Modify: `crates/ironguard-cli/src/main.rs:65-125` (Commands enum)

- [ ] **Step 1: Add GenQuicCert variant to Commands enum**

In `crates/ironguard-cli/src/main.rs`, add to `Commands` enum (after `Genpsk`):

```rust
    /// Generate a QUIC mTLS certificate with WireGuard public key in CN
    GenQuicCert {
        /// Path to WireGuard private key file
        #[clap(long)]
        key: String,
        /// Output certificate file path
        #[clap(long, default_value = "quic.crt")]
        out_cert: String,
        /// Output TLS private key file path
        #[clap(long, default_value = "quic.key")]
        out_key: String,
    },
```

- [ ] **Step 2: Implement the command handler**

Add function:

```rust
fn cmd_gen_quic_cert(key_path: &str, out_cert: &str, out_key: &str) -> Result<()> {
    let key_data = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read key file: {key_path}"))?;
    let private_key = ironguard_config::keys::decode_private_key(&key_data)?;
    let public_key = x25519_dalek::PublicKey::from(
        &x25519_dalek::StaticSecret::from(private_key)
    );
    let wg_pk: [u8; 32] = public_key.to_bytes();

    let (cert_der, key_der) = ironguard_core::session::quic::generate_wg_cert(&wg_pk)?;

    // Write PEM files
    let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.as_ref()));
    std::fs::write(out_cert, &cert_pem)
        .with_context(|| format!("failed to write cert: {out_cert}"))?;

    let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key_der.secret_der()));
    std::fs::write(out_key, &key_pem)
        .with_context(|| format!("failed to write key: {out_key}"))?;

    eprintln!("Generated mTLS certificate:");
    eprintln!("  cert: {out_cert}");
    eprintln!("  key:  {out_key}");
    eprintln!("  WG pubkey in CN: {}", base64::engine::general_purpose::STANDARD.encode(wg_pk));
    Ok(())
}
```

Wire in the match arm:
```rust
Commands::GenQuicCert { key, out_cert, out_key } => cmd_gen_quic_cert(&key, &out_cert, &out_key)?,
```

Add `pem` and `base64` to `ironguard-cli/Cargo.toml` if not already present.

- [ ] **Step 3: Build and test manually**

Run: `cargo build -p ironguard-cli`
Expected: compiles clean

- [ ] **Step 4: Commit**

```bash
git add crates/ironguard-cli/src/main.rs crates/ironguard-cli/Cargo.toml
git commit -m "feat(cli): add gen-quic-cert command for mTLS certificate generation"
```

---

## Task 12: CLI — Address Assignment, Routes, Masquerade, Hooks, Cleanup

**Files:**
- Modify: `crates/ironguard-cli/src/main.rs:197-472` (macOS cmd_up), `main.rs:476+` (Linux cmd_up)

This is the largest task — it wires all platform layer calls into `cmd_up` and `cmd_down`.

- [ ] **Step 1: Add NetworkManager creation and address assignment to macOS cmd_up**

After TUN creation (~L210) and before QUIC setup (~L255), insert the network setup block from spec Section 4b. Use `MacosNetManager::new()`. Include:
- Address assignment loop
- Route installation loop (with `prefix_len == 0` guard)
- Masquerade setup
- PostUp hooks

- [ ] **Step 2: Add transport deprecation handling**

Replace L255-259 (the `iface_cfg.quic.as_ref()` line) with the transport validation from spec Section 4a. Handle deprecated `transport` field, resolve QUIC port with overflow guard, and set up mTLS config based on cert_file/key_file presence.

- [ ] **Step 3: Wire known_peer_pks into quic_accept_loop**

Before the `tokio::spawn(quic_accept_loop(...))` call, build the HashSet:
```rust
let known_peer_pks: std::collections::HashSet<[u8; 32]> = iface_cfg.peers.iter()
    .filter_map(|p| ironguard_config::keys::decode_public_key(&p.public_key).ok())
    .collect();
```
Pass it to `quic_accept_loop`.

- [ ] **Step 4: Wire ACL into peer configuration**

In the peer setup loop, after `wg.new_peer(...)`, add the ACL wiring from spec Section 4c using `RoutingTable::new()` + `insert()` + `set_acl_destinations()`.

- [ ] **Step 5: Add SIGINT + SIGTERM cleanup handler**

Replace the existing Ctrl+C handler (~L461-471) with:
```rust
let cleanup_mgr = Arc::new(net_mgr);
let cleanup_cfg = iface_cfg.clone();
let cleanup_iface = interface.to_string();

tokio::select! {
    _ = tokio::signal::ctrl_c() => {},
    _ = async {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).unwrap();
        sigterm.recv().await;
    } => {},
}

// Cleanup
stop.store(true, std::sync::atomic::Ordering::Relaxed);
shutdown.notify_waiters();

// PostDown hooks
for cmd in &cleanup_cfg.post_down {
    let _ = cleanup_mgr.run_hook(cmd, &cleanup_iface);
}
// Remove masquerade
let _ = cleanup_mgr.remove_masquerade(&cleanup_iface);
// Remove routes
for peer_cfg in &cleanup_cfg.peers {
    for allowed_ip in &peer_cfg.allowed_ips {
        if let Ok((dest, prefix_len)) = parse_cidr(allowed_ip) {
            let _ = cleanup_mgr.remove_route(&cleanup_iface, dest, prefix_len);
        }
    }
}
// Remove addresses
for addr_str in &cleanup_cfg.address {
    if let Ok((ip, prefix_len)) = parse_cidr(addr_str) {
        let _ = cleanup_mgr.remove_address(&cleanup_iface, ip, prefix_len);
    }
}

wg.down();
remove_pid_file(&cleanup_iface);
```

- [ ] **Step 6: Add crash recovery — idempotent cleanup at start of cmd_up**

Before address assignment, add:
```rust
// Crash recovery: clean stale state from previous run
for addr_str in &iface_cfg.address {
    if let Ok((ip, prefix_len)) = parse_cidr(addr_str) {
        let _ = net_mgr.remove_address(&iface_name, ip, prefix_len);
    }
}
let _ = net_mgr.remove_masquerade(&iface_name);
```

- [ ] **Step 7: Repeat steps 1-6 for Linux cmd_up**

Apply the same changes to the Linux `cmd_up` (~L476+) using `LinuxNetManager::new()` instead of `MacosNetManager::new()`.

- [ ] **Step 8: Build and verify**

Run: `cargo build --workspace`
Expected: compiles clean on the current platform

- [ ] **Step 9: Commit**

```bash
git add crates/ironguard-cli/src/main.rs
git commit -m "feat(cli): wire NetworkManager for address/route/masquerade/hooks + cleanup handlers"
```

---

## Task 13: Documentation — README, CLAUDE.md, Example Configs

**Files:**
- Modify: `README.md` (finish remaining fixes from spec Layer 5)
- Modify: `CLAUDE.md` (finish remaining fixes)
- Create: `configs/simple-client-server.json`
- Create: `configs/multi-client-quic-server.json`
- Create: `configs/lan-routing-server.json`
- Create: `configs/systemd/ironguard@.service`
- Create: `configs/launchd/net.ironguard.plist`

- [ ] **Step 1: Update README Interface Fields table**

Add rows for `masquerade`, `post_up`, `post_down`, `quic.cert_file`, `quic.key_file`, `quic.peer_certs`. Add `acl` to Peer Fields table. Remove `transport` row. Add `gen-quic-cert` to CLI commands section.

- [ ] **Step 2: Add QUIC Port Convention section**

Add under Configuration Reference:
```markdown
### QUIC Port Convention

IronGuard's QUIC session handshake uses a separate port from the data plane.
Set `quic.port` in config, or omit to default to `listen_port + 1`. The client
connects to the server's endpoint port + 1 for the handshake. Both ports must
be reachable from the client.
```

- [ ] **Step 3: Create example configs**

Create `configs/simple-client-server.json`, `configs/multi-client-quic-server.json`, `configs/lan-routing-server.json` with valid JSON (no comments) that exercises the new features.

- [ ] **Step 4: Create service files**

Create `configs/systemd/ironguard@.service` and `configs/launchd/net.ironguard.plist` per spec.

- [ ] **Step 5: Update CLAUDE.md**

Finish any remaining stale references. Verify feature flags table matches `Cargo.toml`. Add `NetworkManager`, `gen-quic-cert`, new config fields.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md configs/
git commit -m "docs: update README/CLAUDE.md, add example configs and service files"
```

---

## Task 14: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests PASS

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Run format check**

Run: `cargo fmt --all -- --check`
Expected: no formatting issues

- [ ] **Step 4: Validate example configs**

Run: `cargo run -p ironguard-cli -- validate configs/simple-client-server.json`
Run: `cargo run -p ironguard-cli -- validate configs/multi-client-quic-server.json`
Expected: both validate successfully (or with expected warnings)

- [ ] **Step 5: Commit any fixes**

If any issues found in steps 1-4, fix and commit.

- [ ] **Step 6: Version bump**

Update version in workspace `Cargo.toml` to `0.3.2`.

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.3.2"
```
