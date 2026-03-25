use anyhow::{Result, anyhow};
use x25519_dalek::PublicKey;

use super::system::System;

/// Generate a new X25519 private key, returned as hex string.
pub fn generate_private_key() -> String {
    let mut key_bytes = [0u8; 32];
    rand::fill(&mut key_bytes);
    // Clamp for X25519
    key_bytes[0] &= 248;
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;
    hex::encode(key_bytes)
}

/// Derive public key from a hex-encoded private key.
pub fn derive_public_key(private_hex: &str) -> Result<String> {
    let bytes = hex::decode(private_hex.trim())?;
    if bytes.len() != 32 {
        return Err(anyhow!("private key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let secret = x25519_dalek::StaticSecret::from(key);
    let public = PublicKey::from(&secret);
    Ok(hex::encode(public.as_bytes()))
}

/// Ensure server keys exist. Returns public key hex.
pub fn ensure_server_keys() -> Result<String> {
    let sys = System::detect();
    let key_dir = sys.key_dir();
    let key_path = format!("{key_dir}/server.key");

    std::fs::create_dir_all(&key_dir)?;

    if !std::path::Path::new(&key_path).exists() {
        let private_key = generate_private_key();
        std::fs::write(&key_path, &private_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    let private_hex = std::fs::read_to_string(&key_path)?;
    derive_public_key(&private_hex)
}

/// Read server public key from existing key file.
pub fn server_public_key() -> Result<String> {
    let sys = System::detect();
    let key_path = format!("{}/server.key", sys.key_dir());
    if !std::path::Path::new(&key_path).exists() {
        return Err(anyhow!("No server key. Run setup first."));
    }
    let private_hex = std::fs::read_to_string(&key_path)?;
    derive_public_key(&private_hex)
}

/// Generate a client keypair. Returns (private_hex, public_hex).
pub fn generate_client_keys() -> (String, String) {
    let private_hex = generate_private_key();
    let public_hex = derive_public_key(&private_hex).expect("freshly generated key is valid");
    (private_hex, public_hex)
}
