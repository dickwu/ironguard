use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::keys::{base64_encode, load_private_key};
use crate::types::{Config, InterfaceConfig, Masquerade, PeerConfig, PostQuantumMode};

/// Parse a standard WireGuard `.conf` file and return an IronGuard `Config`.
///
/// The private key is extracted and saved to `<conf_dir>/<interface>.key`,
/// referenced via `private_key_file` in the resulting config.
pub fn import_conf(path: &str) -> Result<Config> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read conf file: {path}"))?;

    let conf_path = Path::new(path);
    let interface_name = conf_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wg0")
        .to_string();

    let conf_dir = conf_path.parent().unwrap_or_else(|| Path::new("."));

    let (iface_cfg, key_data) = parse_conf_content(&content, &interface_name, conf_dir)?;

    // Save extracted private key to file if present
    if let (Some(key_bytes), Some(key_path)) = (&key_data, &iface_cfg.private_key_file) {
        let key_dir = Path::new(key_path).parent();
        if let Some(dir) = key_dir {
            fs::create_dir_all(dir).ok();
        }
        fs::write(key_path, hex::encode(key_bytes))
            .with_context(|| format!("failed to write key file: {key_path}"))?;
    }

    let mut interfaces = HashMap::new();
    interfaces.insert(interface_name, iface_cfg);

    Ok(Config {
        schema: Some("ironguard/v1".to_string()),
        interfaces,
    })
}

/// Parse a `.conf` file's text content into an `InterfaceConfig`.
/// Returns the config and optionally the raw private key bytes (for saving to a file).
fn parse_conf_content(
    content: &str,
    interface_name: &str,
    conf_dir: &Path,
) -> Result<(InterfaceConfig, Option<[u8; 32]>)> {
    let mut listen_port = None;
    let mut address = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = None;
    let mut fwmark = None;
    let mut private_key_raw: Option<[u8; 32]> = None;
    let mut peers = Vec::new();

    let mut current_section = Section::None;
    let mut current_peer: Option<PeerBuilder> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section headers
        if line.eq_ignore_ascii_case("[interface]") {
            // Flush any pending peer
            if let Some(peer) = current_peer.take() {
                peers.push(peer.build()?);
            }
            current_section = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[peer]") {
            // Flush any pending peer
            if let Some(peer) = current_peer.take() {
                peers.push(peer.build()?);
            }
            current_section = Section::Peer;
            current_peer = Some(PeerBuilder::default());
            continue;
        }

        // Key = Value
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        match current_section {
            Section::Interface => match key.to_lowercase().as_str() {
                "privatekey" => {
                    private_key_raw = Some(decode_wg_key(value)?);
                }
                "listenport" => {
                    listen_port = Some(
                        value
                            .parse::<u16>()
                            .with_context(|| format!("invalid listen port: {value}"))?,
                    );
                }
                "address" => {
                    for addr in value.split(',') {
                        let addr = addr.trim();
                        if !addr.is_empty() {
                            address.push(addr.to_string());
                        }
                    }
                }
                "dns" => {
                    for d in value.split(',') {
                        let d = d.trim();
                        if !d.is_empty() {
                            dns.push(d.to_string());
                        }
                    }
                }
                "mtu" => {
                    mtu = Some(
                        value
                            .parse::<u16>()
                            .with_context(|| format!("invalid mtu: {value}"))?,
                    );
                }
                "fwmark" => {
                    fwmark = Some(
                        value
                            .parse::<u32>()
                            .with_context(|| format!("invalid fwmark: {value}"))?,
                    );
                }
                _ => {} // Ignore unknown keys
            },
            Section::Peer => {
                if let Some(ref mut peer) = current_peer {
                    match key.to_lowercase().as_str() {
                        "publickey" => {
                            let key_bytes = decode_wg_key(value)?;
                            peer.public_key = Some(hex::encode(key_bytes));
                        }
                        "presharedkey" => {
                            let key_bytes = decode_wg_key(value)?;
                            // Save preshared key to a file
                            let psk_path = conf_dir
                                .join(format!("{interface_name}.psk.{}", peers.len()))
                                .to_str()
                                .unwrap_or("psk.key")
                                .to_string();
                            fs::create_dir_all(conf_dir).ok();
                            fs::write(&psk_path, hex::encode(key_bytes)).with_context(|| {
                                format!("failed to write preshared key file: {psk_path}")
                            })?;
                            peer.preshared_key_file = Some(psk_path);
                        }
                        "allowedips" => {
                            for ip in value.split(',') {
                                let ip = ip.trim();
                                if !ip.is_empty() {
                                    peer.allowed_ips.push(ip.to_string());
                                }
                            }
                        }
                        "endpoint" => {
                            peer.endpoint = Some(value.to_string());
                        }
                        "persistentkeepalive" => {
                            peer.persistent_keepalive =
                                Some(value.parse::<u64>().with_context(|| {
                                    format!("invalid persistent keepalive: {value}")
                                })?);
                        }
                        _ => {}
                    }
                }
            }
            Section::None => {}
        }
    }

    // Flush last peer
    if let Some(peer) = current_peer.take() {
        peers.push(peer.build()?);
    }

    let key_file_path = conf_dir
        .join(format!("{interface_name}.key"))
        .to_str()
        .unwrap_or("wg0.key")
        .to_string();

    let iface = InterfaceConfig {
        private_key_file: if private_key_raw.is_some() {
            Some(key_file_path)
        } else {
            None
        },
        private_key_env: None,
        listen_port,
        address,
        dns,
        mtu,
        fwmark,
        transport: Some("udp".to_string()),
        masquerade: Masquerade::default(),
        post_up: Vec::new(),
        post_down: Vec::new(),
        quic: None,
        post_quantum: PostQuantumMode::default(),
        mesh: None,
        peers,
    };

    Ok((iface, private_key_raw))
}

/// Export a wg.json Config interface to standard WireGuard `.conf` format.
///
/// IronGuard-specific fields (transport, quic, post_quantum) are dropped.
/// The private key is read from the configured key source and embedded inline.
pub fn export_conf(config: &Config, interface: &str) -> Result<String> {
    let iface = config
        .interfaces
        .get(interface)
        .ok_or_else(|| anyhow::anyhow!("interface {interface} not found in config"))?;

    let mut out = String::new();
    out.push_str("[Interface]\n");

    // Try to load and embed the private key
    match load_private_key(iface) {
        Ok(key_bytes) => {
            out.push_str(&format!("PrivateKey = {}\n", base64_encode(&key_bytes)));
        }
        Err(_) => {
            out.push_str("# PrivateKey = <not available>\n");
        }
    }

    if let Some(port) = iface.listen_port {
        out.push_str(&format!("ListenPort = {port}\n"));
    }

    if !iface.address.is_empty() {
        out.push_str(&format!("Address = {}\n", iface.address.join(", ")));
    }

    if !iface.dns.is_empty() {
        out.push_str(&format!("DNS = {}\n", iface.dns.join(", ")));
    }

    if let Some(mtu) = iface.mtu {
        out.push_str(&format!("MTU = {mtu}\n"));
    }

    if let Some(fwmark) = iface.fwmark {
        out.push_str(&format!("FwMark = {fwmark}\n"));
    }

    for peer in &iface.peers {
        out.push('\n');
        out.push_str("[Peer]\n");

        // Decode hex public key and re-encode as base64 for .conf format
        match hex::decode(&peer.public_key) {
            Ok(pk_bytes) if pk_bytes.len() == 32 => {
                out.push_str(&format!("PublicKey = {}\n", base64_encode(&pk_bytes)));
            }
            _ => {
                // Already base64 or unknown format — pass through
                out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            }
        }

        if let Some(psk_path) = &peer.preshared_key_file {
            if let Ok(content) = fs::read_to_string(psk_path) {
                if let Ok(psk_bytes) = hex::decode(content.trim()) {
                    if psk_bytes.len() == 32 {
                        out.push_str(&format!("PresharedKey = {}\n", base64_encode(&psk_bytes)));
                    }
                }
            }
        }

        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
        }

        if let Some(ep) = &peer.endpoint {
            out.push_str(&format!("Endpoint = {ep}\n"));
        }

        if let Some(ka) = peer.persistent_keepalive {
            out.push_str(&format!("PersistentKeepalive = {ka}\n"));
        }
    }

    Ok(out)
}

/// Decode a WireGuard key (always base64 in .conf files).
fn decode_wg_key(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    let decoded = crate::keys::base64_decode_raw(trimmed)?;
    if decoded.len() != 32 {
        bail!(
            "key has wrong length: expected 32 bytes, got {} bytes",
            decoded.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[derive(Debug, Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Debug, Default)]
struct PeerBuilder {
    public_key: Option<String>,
    preshared_key_file: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u64>,
}

impl PeerBuilder {
    fn build(self) -> Result<PeerConfig> {
        let public_key = self
            .public_key
            .ok_or_else(|| anyhow::anyhow!("peer missing PublicKey"))?;

        Ok(PeerConfig {
            public_key,
            preshared_key_file: self.preshared_key_file,
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips,
            persistent_keepalive: self.persistent_keepalive,
            comment: None,
            pq_public_key: None,
            quic_port: None,
            role: None,
            relay_for: Vec::new(),
            acl: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_conf() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("wg0.conf");

        // Generate a test private key and encode as base64
        let sk_bytes = [0x42u8; 32];
        let sk_b64 = base64_encode(&sk_bytes);

        let pk_bytes = [0xABu8; 32];
        let pk_b64 = base64_encode(&pk_bytes);

        let conf_content = format!(
            "[Interface]\n\
             PrivateKey = {sk_b64}\n\
             ListenPort = 51820\n\
             Address = 10.0.0.1/24\n\
             \n\
             [Peer]\n\
             PublicKey = {pk_b64}\n\
             AllowedIPs = 10.0.0.2/32\n\
             Endpoint = 192.168.1.100:51820\n\
             PersistentKeepalive = 25\n"
        );

        fs::write(&conf_path, &conf_content).unwrap();

        let config = import_conf(conf_path.to_str().unwrap()).unwrap();
        let iface = config.interfaces.get("wg0").unwrap();

        assert_eq!(iface.listen_port, Some(51820));
        assert_eq!(iface.address, vec!["10.0.0.1/24"]);
        assert_eq!(iface.peers.len(), 1);
        assert_eq!(iface.peers[0].allowed_ips, vec!["10.0.0.2/32"]);
        assert_eq!(
            iface.peers[0].endpoint.as_deref(),
            Some("192.168.1.100:51820")
        );
        assert_eq!(iface.peers[0].persistent_keepalive, Some(25));

        // Verify key was saved
        let key_path = iface.private_key_file.as_ref().unwrap();
        let saved_key = fs::read_to_string(key_path).unwrap();
        assert_eq!(hex::decode(saved_key.trim()).unwrap(), sk_bytes);
    }

    #[test]
    fn test_import_export_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("wg0.conf");

        let sk_bytes = [0x42u8; 32];
        let sk_b64 = base64_encode(&sk_bytes);

        let pk_bytes = [0xABu8; 32];
        let pk_b64 = base64_encode(&pk_bytes);

        let original_conf = format!(
            "[Interface]\n\
             PrivateKey = {sk_b64}\n\
             ListenPort = 51820\n\
             Address = 10.0.0.1/24\n\
             \n\
             [Peer]\n\
             PublicKey = {pk_b64}\n\
             AllowedIPs = 10.0.0.2/32\n\
             Endpoint = 192.168.1.100:51820\n\
             PersistentKeepalive = 25\n"
        );

        fs::write(&conf_path, &original_conf).unwrap();

        // Import
        let config = import_conf(conf_path.to_str().unwrap()).unwrap();

        // Export
        let exported = export_conf(&config, "wg0").unwrap();

        // Re-import from exported
        let conf_path2 = dir.path().join("wg0_exported.conf");
        fs::write(&conf_path2, &exported).unwrap();
        let config2 = import_conf(conf_path2.to_str().unwrap()).unwrap();

        let iface1 = config.interfaces.get("wg0").unwrap();
        let iface2 = config2.interfaces.get("wg0_exported").unwrap();

        assert_eq!(iface1.listen_port, iface2.listen_port);
        assert_eq!(iface1.address, iface2.address);
        assert_eq!(iface1.peers.len(), iface2.peers.len());
        assert_eq!(iface1.peers[0].allowed_ips, iface2.peers[0].allowed_ips);
        assert_eq!(iface1.peers[0].endpoint, iface2.peers[0].endpoint);
        assert_eq!(
            iface1.peers[0].persistent_keepalive,
            iface2.peers[0].persistent_keepalive
        );

        // Verify the public keys represent the same key bytes
        let pk1 = hex::decode(&iface1.peers[0].public_key).unwrap();
        let pk2 = hex::decode(&iface2.peers[0].public_key).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_export_conf_interface_not_found() {
        let config = Config {
            schema: None,
            interfaces: HashMap::new(),
        };
        assert!(export_conf(&config, "wg0").is_err());
    }
}
