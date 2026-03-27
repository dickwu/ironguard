use anyhow::{Result, anyhow};
use std::path::Path;

use crate::types::Config;

/// Validate a Config and return a list of warnings.
///
/// Checks:
/// - All referenced key files exist
/// - All public keys are valid length (64 hex chars = 32 bytes)
/// - All allowed_ips parse as valid CIDR notation
/// - Transport deprecation (UDP rejected, QUIC deprecated)
/// - QUIC config presence and port overflow
/// - QUIC cert_file / key_file pairing
/// - ACL CIDR validation
/// - Masquerade requires interface address
/// - PostUp / PostDown `%i` placeholder usage
///
/// Returns warnings for non-critical issues. Returns an error only for
/// structural problems that prevent validation from completing.
pub fn validate(config: &Config) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    for (name, iface) in &config.interfaces {
        // Check private key source
        match (&iface.private_key_file, &iface.private_key_env) {
            (None, None) => {
                warnings.push(format!(
                    "interface {name}: no private key source configured"
                ));
            }
            (Some(path), _) => {
                if !Path::new(path).exists() {
                    warnings.push(format!(
                        "interface {name}: private key file does not exist: {path}"
                    ));
                }
            }
            (None, Some(env_var)) => {
                if std::env::var(env_var).is_err() {
                    warnings.push(format!(
                        "interface {name}: private key env var not set: {env_var}"
                    ));
                }
            }
        }

        // --- Transport deprecation ---
        if let Some(transport) = &iface.transport {
            match transport.as_str() {
                "udp" => {
                    return Err(anyhow!(
                        "interface {name}: UDP transport is not supported; \
                         IronGuard uses QUIC for session management"
                    ));
                }
                "quic" => {
                    warnings.push(format!(
                        "interface {name}: the 'transport' field is deprecated; \
                         QUIC is now the default and only transport"
                    ));
                }
                _ => {}
            }
        }

        // --- QUIC config required ---
        if iface.quic.is_none() {
            warnings.push(format!(
                "interface {name}: no 'quic' config section; \
                 QUIC defaults will be used"
            ));
        }

        // --- QUIC port overflow ---
        if let Some(listen_port) = iface.listen_port {
            if let Some(quic) = &iface.quic {
                if quic.port.is_none() && listen_port == 65535 {
                    warnings.push(format!(
                        "interface {name}: listen_port is {listen_port} and quic.port \
                         is not set; the default QUIC port (listen_port + 1) would overflow"
                    ));
                }
            }
        }

        // --- QUIC cert_file / key_file pairing ---
        if let Some(quic) = &iface.quic {
            let has_cert = quic.cert_file.is_some();
            let has_key = quic.key_file.is_some();
            if has_cert != has_key {
                let missing = if has_cert { "key_file" } else { "cert_file" };
                warnings.push(format!(
                    "interface {name}: quic.{missing} is not set but its \
                     counterpart is; both cert_file and key_file must be provided together"
                ));
            }
        }

        // --- Masquerade requires address ---
        if !iface.masquerade.is_disabled() && iface.address.is_empty() {
            warnings.push(format!(
                "interface {name}: masquerade is enabled but no 'address' is set; \
                 masquerade requires at least one interface address"
            ));
        }

        // --- PostUp / PostDown %i warning ---
        for cmd in &iface.post_up {
            if !cmd.contains("%i") {
                warnings.push(format!(
                    "interface {name}: post_up command does not contain '%i' \
                     interface placeholder: {cmd}"
                ));
            }
        }
        for cmd in &iface.post_down {
            if !cmd.contains("%i") {
                warnings.push(format!(
                    "interface {name}: post_down command does not contain '%i' \
                     interface placeholder: {cmd}"
                ));
            }
        }

        for (i, peer) in iface.peers.iter().enumerate() {
            let peer_label = format!("interface {name}, peer {i}");

            // Check public key length
            let pk = &peer.public_key;
            match hex::decode(pk) {
                Ok(bytes) if bytes.len() == 32 => {} // valid hex key
                Ok(bytes) => {
                    warnings.push(format!(
                        "{peer_label}: public key has wrong length ({} bytes, expected 32)",
                        bytes.len()
                    ));
                }
                Err(_) => {
                    // Maybe it's base64? Check length heuristically
                    if pk.len() != 44 && pk.len() != 43 {
                        warnings.push(format!(
                            "{peer_label}: public key is not valid hex or base64"
                        ));
                    }
                }
            }

            // Check preshared key file
            if let Some(psk_path) = &peer.preshared_key_file {
                if !Path::new(psk_path).exists() {
                    warnings.push(format!(
                        "{peer_label}: preshared key file does not exist: {psk_path}"
                    ));
                }
            }

            // Check allowed_ips are valid CIDR
            for ip in &peer.allowed_ips {
                if !is_valid_cidr(ip) {
                    warnings.push(format!("{peer_label}: invalid CIDR notation: {ip}"));
                }
            }

            // --- ACL CIDR validation ---
            if let Some(acl) = &peer.acl {
                for dest in &acl.allow_destinations {
                    if !is_valid_cidr(dest) {
                        warnings.push(format!(
                            "{peer_label}: ACL allow_destinations contains \
                             invalid CIDR: {dest}"
                        ));
                    }
                }
            }
        }
    }

    Ok(warnings)
}

/// Check if a string is valid CIDR notation (e.g. "10.0.0.0/24" or "fd00::/64").
fn is_valid_cidr(s: &str) -> bool {
    let Some((addr_str, prefix_str)) = s.split_once('/') else {
        return false;
    };

    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };

    if let Ok(_addr) = addr_str.parse::<std::net::Ipv4Addr>() {
        return prefix_len <= 32;
    }

    if let Ok(_addr) = addr_str.parse::<std::net::Ipv6Addr>() {
        return prefix_len <= 128;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        InterfaceConfig, Masquerade, PeerAcl, PeerConfig, PostQuantumMode, QuicConfig,
    };
    use std::collections::HashMap;

    /// Build a minimal Config for testing.
    ///
    /// `transport` is `None` (the new default -- no deprecated field) and
    /// a stub `QuicConfig` is included so the "no quic config" warning
    /// does not fire unless the test explicitly wants it to.
    fn make_config(
        key_file: Option<&str>,
        peer_pk: &str,
        allowed_ips: Vec<&str>,
        psk_file: Option<&str>,
    ) -> Config {
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "wg0".to_string(),
            InterfaceConfig {
                private_key_file: key_file.map(|s| s.to_string()),
                private_key_env: None,
                listen_port: Some(51820),
                address: vec!["10.0.0.1/24".to_string()],
                dns: vec![],
                mtu: None,
                fwmark: None,
                transport: None,
                quic: Some(default_quic()),
                post_quantum: PostQuantumMode::default(),
                mesh: None,
                peers: vec![PeerConfig {
                    public_key: peer_pk.to_string(),
                    preshared_key_file: psk_file.map(|s| s.to_string()),
                    endpoint: None,
                    allowed_ips: allowed_ips.into_iter().map(|s| s.to_string()).collect(),
                    persistent_keepalive: None,
                    comment: None,
                    pq_public_key: None,
                    quic_port: None,
                    role: None,
                    relay_for: Vec::new(),
                    acl: None,
                }],
                masquerade: Masquerade::default(),
                post_up: Vec::new(),
                post_down: Vec::new(),
            },
        );

        Config {
            schema: Some("ironguard/v1".to_string()),
            interfaces,
        }
    }

    /// Minimal QuicConfig with no cert_file/key_file (avoids pairing warning).
    fn default_quic() -> QuicConfig {
        QuicConfig {
            port: None,
            sni: None,
            alpn: None,
            cert_path: None,
            key_path: None,
            mode: Default::default(),
            datagram_only: false,
            cert_file: None,
            key_file: None,
            peer_certs: Vec::new(),
        }
    }

    // ---- existing tests (updated for new defaults) ----

    #[test]
    fn test_validate_missing_key_file() {
        let config = make_config(
            Some("/nonexistent/key.file"),
            &hex::encode([0xABu8; 32]),
            vec!["10.0.0.0/24"],
            None,
        );

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("does not exist")),
            "should warn about missing key file: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_no_key_source() {
        let config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("no private key source")),
            "should warn about missing key source: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_bad_public_key() {
        let config = make_config(None, "not-a-valid-key", vec!["10.0.0.0/24"], None);

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("public key")),
            "should warn about invalid public key: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_bad_cidr() {
        let config = make_config(None, &hex::encode([0xABu8; 32]), vec!["not-a-cidr"], None);

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("invalid CIDR")),
            "should warn about invalid CIDR: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("wg0.key");
        std::fs::write(&key_path, hex::encode([0xABu8; 32])).unwrap();

        let config = make_config(
            Some(key_path.to_str().unwrap()),
            &hex::encode([0xCDu8; 32]),
            vec!["10.0.0.0/24", "fd00::/64"],
            None,
        );

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.is_empty(),
            "valid config should produce no warnings: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_missing_psk_file() {
        let config = make_config(
            None,
            &hex::encode([0xABu8; 32]),
            vec!["10.0.0.0/24"],
            Some("/nonexistent/psk.key"),
        );

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("preshared key file does not exist")),
            "should warn about missing psk file: {warnings:?}"
        );
    }

    #[test]
    fn test_is_valid_cidr() {
        assert!(is_valid_cidr("10.0.0.0/24"));
        assert!(is_valid_cidr("10.0.0.1/32"));
        assert!(is_valid_cidr("0.0.0.0/0"));
        assert!(is_valid_cidr("fd00::/64"));
        assert!(is_valid_cidr("::1/128"));
        assert!(!is_valid_cidr("10.0.0.0"));
        assert!(!is_valid_cidr("10.0.0.0/33"));
        assert!(!is_valid_cidr("not-an-ip/24"));
    }

    // ---- new tests for Task 3 validation rules ----

    #[test]
    fn test_validate_udp_transport_rejected() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().transport = Some("udp".to_string());

        let result = validate(&config);
        assert!(result.is_err(), "UDP transport must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("UDP transport is not supported"),
            "error should mention UDP not supported: {msg}"
        );
    }

    #[test]
    fn test_validate_quic_transport_deprecated_warning() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().transport = Some("quic".to_string());

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("deprecated")),
            "should warn about transport field deprecation: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_missing_quic_config_warning() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().quic = None;

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("no 'quic' config")),
            "should warn about missing quic config: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_quic_port_overflow() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        let iface = config.interfaces.get_mut("wg0").unwrap();
        iface.listen_port = Some(65535);
        // quic.port is None so the default (listen_port + 1) would overflow
        iface.quic = Some(default_quic());

        let warnings = validate(&config).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("overflow")),
            "should warn about QUIC port overflow: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_quic_cert_file_without_key_file() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        let quic = config
            .interfaces
            .get_mut("wg0")
            .unwrap()
            .quic
            .as_mut()
            .unwrap();
        quic.cert_file = Some("/path/to/cert.pem".to_string());
        // key_file intentionally left None

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("key_file") && w.contains("not set")),
            "should warn about missing key_file: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_quic_key_file_without_cert_file() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        let quic = config
            .interfaces
            .get_mut("wg0")
            .unwrap()
            .quic
            .as_mut()
            .unwrap();
        quic.key_file = Some("/path/to/key.pem".to_string());
        // cert_file intentionally left None

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("cert_file") && w.contains("not set")),
            "should warn about missing cert_file: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_acl_bad_cidr() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().peers[0].acl = Some(PeerAcl {
            allow_destinations: vec!["10.0.0.0/24".to_string(), "not-a-cidr".to_string()],
        });

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("ACL") && w.contains("not-a-cidr")),
            "should warn about invalid ACL CIDR: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_acl_valid_cidrs() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().peers[0].acl = Some(PeerAcl {
            allow_destinations: vec!["10.0.0.0/24".to_string(), "fd00::/64".to_string()],
        });

        let warnings = validate(&config).unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("ACL")),
            "valid ACL CIDRs should not produce warnings: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_masquerade_requires_address() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        let iface = config.interfaces.get_mut("wg0").unwrap();
        iface.masquerade = Masquerade::All;
        iface.address = vec![]; // empty address

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("masquerade") && w.contains("address")),
            "should warn about masquerade without address: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_post_up_missing_percent_i() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().post_up =
            vec!["iptables -A FORWARD -i wg0 -j ACCEPT".to_string()];

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("post_up") && w.contains("%i")),
            "should warn about missing %i in post_up: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_post_down_missing_percent_i() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().post_down =
            vec!["iptables -D FORWARD -i wg0 -j ACCEPT".to_string()];

        let warnings = validate(&config).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("post_down") && w.contains("%i")),
            "should warn about missing %i in post_down: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_post_up_with_percent_i_no_warning() {
        let mut config = make_config(None, &hex::encode([0xABu8; 32]), vec!["10.0.0.0/24"], None);
        config.interfaces.get_mut("wg0").unwrap().post_up =
            vec!["iptables -A FORWARD -i %i -j ACCEPT".to_string()];

        let warnings = validate(&config).unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("post_up")),
            "post_up with %i should not produce a warning: {warnings:?}"
        );
    }
}
