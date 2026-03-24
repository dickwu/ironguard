use anyhow::{Context, Result, bail};
use std::fs;

use crate::types::{InterfaceConfig, PeerConfig};

/// Decode a key string that may be hex-encoded (64 chars) or base64-encoded (44 chars).
/// Returns exactly 32 bytes.
pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();

    // Try hex first (64 hex chars = 32 bytes)
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(trimmed).context("invalid hex key")?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Try base64 (44 chars with padding, or 43 without)
    let decoded = base64_decode(trimmed)?;
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

/// Minimal base64 decoder (standard alphabet, optional padding).
/// We avoid pulling in a full base64 crate for this single use.
pub(crate) fn base64_decode_raw(input: &str) -> Result<Vec<u8>> {
    base64_decode(input)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u8> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => bail!("invalid base64 character: {}", c as char),
        }
    }

    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();

    let chunks = bytes.len() / 4;
    for i in 0..chunks {
        let a = val(bytes[i * 4])?;
        let b = val(bytes[i * 4 + 1])?;
        let c = val(bytes[i * 4 + 2])?;
        let d = val(bytes[i * 4 + 3])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }

    let rem = bytes.len() % 4;
    let start = chunks * 4;
    if rem == 2 {
        let a = val(bytes[start])?;
        let b = val(bytes[start + 1])?;
        out.push((a << 2) | (b >> 4));
    } else if rem == 3 {
        let a = val(bytes[start])?;
        let b = val(bytes[start + 1])?;
        let c = val(bytes[start + 2])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
    }

    Ok(out)
}

/// Minimal base64 encoder (standard alphabet, with padding).
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.len() / 3;

    for i in 0..chunks {
        let b0 = data[i * 3] as usize;
        let b1 = data[i * 3 + 1] as usize;
        let b2 = data[i * 3 + 2] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        out.push(TABLE[b2 & 0x3F] as char);
    }

    let rem = data.len() % 3;
    let start = chunks * 3;
    if rem == 1 {
        let b0 = data[start] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[(b0 & 0x03) << 4] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = data[start] as usize;
        let b1 = data[start + 1] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(TABLE[(b1 & 0x0F) << 2] as char);
        out.push('=');
    }

    out
}

/// Load a private key from the interface config.
///
/// Checks `private_key_file` first, then `private_key_env`.
/// Keys in files may be hex-encoded (64 chars) or base64-encoded (44 chars).
pub fn load_private_key(config: &InterfaceConfig) -> Result<[u8; 32]> {
    if let Some(path) = &config.private_key_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read private key file: {path}"))?;
        return decode_key(&content)
            .with_context(|| format!("failed to decode private key from file: {path}"));
    }

    if let Some(env_var) = &config.private_key_env {
        let value = std::env::var(env_var)
            .with_context(|| format!("environment variable not set: {env_var}"))?;
        return decode_key(&value)
            .with_context(|| format!("failed to decode private key from env: {env_var}"));
    }

    bail!("no private key source configured (set private_key_file or private_key_env)")
}

/// Load an optional preshared key from a peer config.
///
/// Returns `None` if `preshared_key_file` is not set.
/// Keys in files may be hex-encoded or base64-encoded.
pub fn load_preshared_key(peer: &PeerConfig) -> Result<Option<[u8; 32]>> {
    match &peer.preshared_key_file {
        None => Ok(None),
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read preshared key file: {path}"))?;
            let key = decode_key(&content)
                .with_context(|| format!("failed to decode preshared key from file: {path}"))?;
            Ok(Some(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_key() {
        let hex_str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let key = decode_key(hex_str).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0xa1);
        assert_eq!(key[1], 0xb2);
    }

    #[test]
    fn test_decode_base64_key() {
        // 32 bytes of zeros in base64
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = decode_key(b64).unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = [42u8; 32];
        let encoded = base64_encode(&original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &original);
    }

    #[test]
    fn test_load_private_key_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let key_bytes = [0xABu8; 32];
        let hex_key = hex::encode(key_bytes);
        fs::write(&key_path, &hex_key).unwrap();

        let config = InterfaceConfig {
            private_key_file: Some(key_path.to_str().unwrap().to_string()),
            private_key_env: None,
            listen_port: None,
            address: vec![],
            dns: vec![],
            mtu: None,
            fwmark: None,
            transport: "udp".to_string(),
            quic: None,
            post_quantum: Default::default(),
            peers: vec![],
        };

        let loaded = load_private_key(&config).unwrap();
        assert_eq!(loaded, key_bytes);
    }

    #[test]
    fn test_load_private_key_from_env() {
        let key_bytes = [0xCDu8; 32];
        let hex_key = hex::encode(key_bytes);
        // SAFETY: test-only, single-threaded access to this env var
        unsafe { std::env::set_var("IRONGUARD_TEST_KEY_12345", &hex_key) };

        let config = InterfaceConfig {
            private_key_file: None,
            private_key_env: Some("IRONGUARD_TEST_KEY_12345".to_string()),
            listen_port: None,
            address: vec![],
            dns: vec![],
            mtu: None,
            fwmark: None,
            transport: "udp".to_string(),
            quic: None,
            post_quantum: Default::default(),
            peers: vec![],
        };

        let loaded = load_private_key(&config).unwrap();
        assert_eq!(loaded, key_bytes);

        // SAFETY: test-only, single-threaded access to this env var
        unsafe { std::env::remove_var("IRONGUARD_TEST_KEY_12345") };
    }

    #[test]
    fn test_load_private_key_missing() {
        let config = InterfaceConfig {
            private_key_file: None,
            private_key_env: None,
            listen_port: None,
            address: vec![],
            dns: vec![],
            mtu: None,
            fwmark: None,
            transport: "udp".to_string(),
            quic: None,
            post_quantum: Default::default(),
            peers: vec![],
        };

        assert!(load_private_key(&config).is_err());
    }

    #[test]
    fn test_load_preshared_key_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("psk.key");
        let key_bytes = [0xEFu8; 32];
        fs::write(&key_path, hex::encode(key_bytes)).unwrap();

        let peer = PeerConfig {
            public_key: "deadbeef".to_string(),
            preshared_key_file: Some(key_path.to_str().unwrap().to_string()),
            endpoint: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
            comment: None,
            pq_public_key: None,
            quic_port: None,
        };

        let loaded = load_preshared_key(&peer).unwrap();
        assert_eq!(loaded, Some(key_bytes));
    }

    #[test]
    fn test_load_preshared_key_none() {
        let peer = PeerConfig {
            public_key: "deadbeef".to_string(),
            preshared_key_file: None,
            endpoint: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
            comment: None,
            pq_public_key: None,
            quic_port: None,
        };

        assert_eq!(load_preshared_key(&peer).unwrap(), None);
    }

    #[test]
    fn test_load_base64_key_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("b64.key");
        let key_bytes = [0x42u8; 32];
        let b64_key = base64_encode(&key_bytes);
        fs::write(&key_path, &b64_key).unwrap();

        let config = InterfaceConfig {
            private_key_file: Some(key_path.to_str().unwrap().to_string()),
            private_key_env: None,
            listen_port: None,
            address: vec![],
            dns: vec![],
            mtu: None,
            fwmark: None,
            transport: "udp".to_string(),
            quic: None,
            post_quantum: Default::default(),
            peers: vec![],
        };

        let loaded = load_private_key(&config).unwrap();
        assert_eq!(loaded, key_bytes);
    }
}
