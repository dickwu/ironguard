use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

const LABEL_CLIENT_TO_SERVER: &[u8] = b"ironguard-client-to-server";
const LABEL_SERVER_TO_CLIENT: &[u8] = b"ironguard-server-to-client";
const LABEL_EPOCH_PREFIX: &[u8] = b"ironguard-epoch";

/// Custom KeyType for HKDF-Expand output lengths.
struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPlaneKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

/// Derive a directional key pair from a PRK using the standard labels.
/// Returns (client_to_server_key, server_to_client_key).
fn derive_directional_keys(prk: &Prk) -> ([u8; 32], [u8; 32]) {
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];

    prk.expand(&[LABEL_CLIENT_TO_SERVER], OkmLen(32))
        .expect("HKDF-Expand for client-to-server key")
        .fill(&mut c2s)
        .expect("fill client-to-server key");

    prk.expand(&[LABEL_SERVER_TO_CLIENT], OkmLen(32))
        .expect("HKDF-Expand for server-to-client key")
        .fill(&mut s2c)
        .expect("fill server-to-client key");

    (c2s, s2c)
}

/// Assign directional keys based on role.
fn keys_for_role(c2s: [u8; 32], s2c: [u8; 32], role: Role) -> DataPlaneKeys {
    match role {
        Role::Client => DataPlaneKeys {
            send_key: c2s,
            recv_key: s2c,
        },
        Role::Server => DataPlaneKeys {
            send_key: s2c,
            recv_key: c2s,
        },
    }
}

/// Derive initial data-plane keys from the TLS exporter secret.
/// Client's send_key = Server's recv_key (and vice versa).
pub fn derive_initial_keys(exporter_secret: &[u8; 64], role: Role) -> DataPlaneKeys {
    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(exporter_secret);

    let (c2s, s2c) = derive_directional_keys(&prk);
    keys_for_role(c2s, s2c, role)
}

/// Derive keys for a specific rekey epoch.
/// Mixes the base exporter with epoch number + fresh entropy from both sides.
pub fn derive_epoch_keys(
    exporter_secret: &[u8; 64],
    epoch: u32,
    initiator_entropy: &[u8; 32],
    responder_entropy: &[u8; 32],
    role: Role,
) -> DataPlaneKeys {
    // Step 1: Extract a base PRK from the exporter secret
    let salt = Salt::new(HKDF_SHA256, &[]);
    let base_prk = salt.extract(exporter_secret);

    // Step 2: Build epoch_info = "ironguard-epoch" || epoch.to_le_bytes() || initiator_entropy || responder_entropy
    let epoch_bytes = epoch.to_le_bytes();
    let epoch_info: &[&[u8]] = &[
        LABEL_EPOCH_PREFIX,
        &epoch_bytes,
        initiator_entropy,
        responder_entropy,
    ];

    // Step 3: Expand base PRK with epoch_info to get a 64-byte epoch_secret
    let mut epoch_secret = [0u8; 64];
    base_prk
        .expand(epoch_info, OkmLen(64))
        .expect("HKDF-Expand for epoch secret")
        .fill(&mut epoch_secret)
        .expect("fill epoch secret");

    // Step 4: Extract a new PRK from the epoch_secret
    let epoch_salt = Salt::new(HKDF_SHA256, &[]);
    let epoch_prk = epoch_salt.extract(&epoch_secret);

    // Step 5: Derive directional keys from the epoch PRK
    let (c2s, s2c) = derive_directional_keys(&epoch_prk);
    keys_for_role(c2s, s2c, role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_keys_are_directional() {
        let exporter = [0x42u8; 64];
        let client_keys = derive_initial_keys(&exporter, Role::Client);
        let server_keys = derive_initial_keys(&exporter, Role::Server);
        assert_eq!(client_keys.send_key, server_keys.recv_key);
        assert_eq!(client_keys.recv_key, server_keys.send_key);
        assert_ne!(client_keys.send_key, client_keys.recv_key);
    }

    #[test]
    fn test_epoch_keys_differ_from_initial() {
        let exporter = [0x42u8; 64];
        let initial = derive_initial_keys(&exporter, Role::Client);
        let epoch = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Client);
        assert_ne!(initial.send_key, epoch.send_key);
        assert_ne!(initial.recv_key, epoch.recv_key);
    }

    #[test]
    fn test_different_entropy_produces_different_keys() {
        let exporter = [0x42u8; 64];
        let keys_a = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Client);
        let keys_b = derive_epoch_keys(&exporter, 1, &[0xCC; 32], &[0xDD; 32], Role::Client);
        assert_ne!(keys_a.send_key, keys_b.send_key);
    }

    #[test]
    fn test_different_epochs_produce_different_keys() {
        let exporter = [0x42u8; 64];
        let keys_1 = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Client);
        let keys_2 = derive_epoch_keys(&exporter, 2, &[0xAA; 32], &[0xBB; 32], Role::Client);
        assert_ne!(keys_1.send_key, keys_2.send_key);
    }

    #[test]
    fn test_epoch_keys_are_directional() {
        let exporter = [0x42u8; 64];
        let client = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Client);
        let server = derive_epoch_keys(&exporter, 1, &[0xAA; 32], &[0xBB; 32], Role::Server);
        assert_eq!(client.send_key, server.recv_key);
        assert_eq!(client.recv_key, server.send_key);
    }

    #[test]
    fn test_deterministic_derivation() {
        let exporter = [0x42u8; 64];
        let keys1 = derive_initial_keys(&exporter, Role::Client);
        let keys2 = derive_initial_keys(&exporter, Role::Client);
        assert_eq!(keys1.send_key, keys2.send_key);
        assert_eq!(keys1.recv_key, keys2.recv_key);
    }
}
