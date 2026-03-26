use anyhow::Result;
use std::path::Path;

use crate::types::Config;

/// Validate a Config and return a list of warnings.
///
/// Checks:
/// - All referenced key files exist
/// - All public keys are valid length (64 hex chars = 32 bytes)
/// - All allowed_ips parse as valid CIDR notation
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
    use crate::types::{InterfaceConfig, PeerConfig, PostQuantumMode};
    use std::collections::HashMap;

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
                transport: "udp".to_string(),
                quic: None,
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
                }],
            },
        );

        Config {
            schema: Some("ironguard/v1".to_string()),
            interfaces,
        }
    }

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
}
