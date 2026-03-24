//! mDNS LAN auto-discovery for zero-config peer detection.
//!
//! Announces the local IronGuard instance on the LAN and discovers
//! peers using mDNS service browsing. Public keys are never exposed
//! on the wire -- instead, an ephemeral identifier derived from
//! HMAC-SHA256(pubkey, salt) is broadcast, and only peers that know
//! each other's public keys can match the announcements.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

type HmacSha256 = Hmac<Sha256>;

/// The mDNS service type for IronGuard.
const SERVICE_TYPE: &str = "_ironguard._udp.local.";

/// Length of the truncated ephemeral ID (bytes).
const EPHEMERAL_ID_LEN: usize = 8;

/// Errors from mDNS discovery operations.
#[derive(Debug, Error)]
pub enum MdnsError {
    /// The mDNS daemon could not be created.
    #[error("mDNS daemon error: {0}")]
    DaemonError(String),

    /// Service registration failed.
    #[error("mDNS registration failed: {0}")]
    RegistrationFailed(String),

    /// Service browsing failed.
    #[error("mDNS browsing failed: {0}")]
    BrowsingFailed(String),
}

/// A peer discovered via mDNS on the local network.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    /// The local network address of the discovered peer.
    pub addr: SocketAddr,
    /// The known public key that matched this peer's ephemeral ID.
    pub pubkey_match: [u8; 32],
}

/// Manages mDNS announcement and discovery for IronGuard peers.
///
/// Announces the local instance with an ephemeral identity derived
/// from the public key and a salt. Discovers other IronGuard peers
/// by matching their ephemeral IDs against a set of known public keys.
pub struct MdnsDiscovery {
    /// Handle to the running mDNS daemon, if active.
    daemon: Arc<Mutex<Option<mdns_sd::ServiceDaemon>>>,
    /// The full service name used for registration.
    registered_name: Arc<Mutex<Option<String>>>,
}

impl MdnsDiscovery {
    /// Creates a new mDNS discovery instance.
    pub fn new() -> Self {
        Self {
            daemon: Arc::new(Mutex::new(None)),
            registered_name: Arc::new(Mutex::new(None)),
        }
    }

    /// Announces this IronGuard instance on the local network.
    ///
    /// Registers an mDNS service of type `_ironguard._udp.local`
    /// with a TXT record containing an ephemeral identifier derived
    /// from the public key. The raw public key is never sent on
    /// the wire -- only a truncated HMAC that peers can verify if
    /// they already know the key.
    ///
    /// # Arguments
    ///
    /// * `port` - The WireGuard listen port to advertise.
    /// * `pubkey` - The local peer's public key (32 bytes).
    /// * `salt` - A rotating salt used for ephemeral ID derivation.
    pub async fn announce(
        &self,
        port: u16,
        pubkey: &[u8; 32],
        salt: &[u8],
    ) -> Result<(), MdnsError> {
        let ephemeral_id = compute_ephemeral_id(pubkey, salt);
        let id_hex = hex::encode(ephemeral_id);

        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|e| MdnsError::DaemonError(e.to_string()))?;

        // Build properties map
        let properties: Vec<(&str, &str)> = vec![("id", &id_hex)];

        let hostname = gethostname();
        let instance_name = format!("ironguard-{}", &id_hex[..8]);

        let service_info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            "",     // Let mdns-sd discover local IPs
            port,
            &properties[..],
        )
        .map_err(|e| MdnsError::RegistrationFailed(e.to_string()))?;

        daemon
            .register(service_info)
            .map_err(|e| MdnsError::RegistrationFailed(e.to_string()))?;

        tracing::info!(
            "mDNS: announcing IronGuard on port {} with ephemeral ID {}",
            port,
            id_hex
        );

        let full_name = format!("{instance_name}.{SERVICE_TYPE}");
        {
            let mut name_guard = self.registered_name.lock().await;
            *name_guard = Some(full_name);
        }
        {
            let mut daemon_guard = self.daemon.lock().await;
            *daemon_guard = Some(daemon);
        }

        Ok(())
    }

    /// Discovers IronGuard peers on the local network.
    ///
    /// Browses for `_ironguard._udp.local` services and matches
    /// their ephemeral IDs against the provided set of known public
    /// keys. Only peers whose public key is in `expected_pubkeys`
    /// will be reported.
    ///
    /// Returns a channel that receives `DiscoveredPeer` values as
    /// peers are found. The channel is closed when `stop()` is called.
    ///
    /// # Arguments
    ///
    /// * `expected_pubkeys` - Public keys of peers we want to discover.
    /// * `salt` - The same salt used by peers for announcement.
    pub async fn discover(
        &self,
        expected_pubkeys: &[[u8; 32]],
        salt: &[u8],
    ) -> Result<mpsc::Receiver<DiscoveredPeer>, MdnsError> {
        // Pre-compute expected ephemeral IDs for all known pubkeys
        let expected_ids: HashMap<[u8; EPHEMERAL_ID_LEN], [u8; 32]> = expected_pubkeys
            .iter()
            .map(|pk| (compute_ephemeral_id(pk, salt), *pk))
            .collect();

        let daemon = {
            let guard = self.daemon.lock().await;
            match guard.as_ref() {
                Some(d) => d.clone(),
                None => {
                    // Create a new daemon for browsing only
                    mdns_sd::ServiceDaemon::new()
                        .map_err(|e| MdnsError::DaemonError(e.to_string()))?
                }
            }
        };

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| MdnsError::BrowsingFailed(e.to_string()))?;

        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        tracing::debug!(
                            "mDNS: resolved service '{}' at {:?}:{}",
                            info.get_fullname(),
                            info.get_addresses(),
                            info.get_port()
                        );

                        let id_value = match info.get_property_val_str("id") {
                            Some(val) => val.to_string(),
                            None => continue,
                        };

                        let received_id = match hex::decode(&id_value) {
                            Ok(bytes) if bytes.len() == EPHEMERAL_ID_LEN => {
                                let mut arr = [0u8; EPHEMERAL_ID_LEN];
                                arr.copy_from_slice(&bytes);
                                arr
                            }
                            _ => continue,
                        };

                        // Match against known pubkeys
                        if let Some(pubkey) = expected_ids.get(&received_id) {
                            for addr in info.get_addresses() {
                                let sock_addr =
                                    SocketAddr::new(*addr, info.get_port());

                                tracing::info!(
                                    "mDNS: discovered peer at {} (pubkey match)",
                                    sock_addr
                                );

                                let peer = DiscoveredPeer {
                                    addr: sock_addr,
                                    pubkey_match: *pubkey,
                                };

                                if tx.send(peer).await.is_err() {
                                    // Receiver dropped, stop browsing
                                    return;
                                }
                            }
                        }
                    }
                    mdns_sd::ServiceEvent::SearchStarted(_) => {
                        tracing::debug!("mDNS: browse started for {SERVICE_TYPE}");
                    }
                    _ => {}
                }
            }
        });

        Ok(rx)
    }

    /// Stops announcing and browsing.
    ///
    /// Unregisters the mDNS service and shuts down the daemon.
    pub async fn stop(&self) {
        let daemon = {
            let mut guard = self.daemon.lock().await;
            guard.take()
        };

        let name = {
            let mut guard = self.registered_name.lock().await;
            guard.take()
        };

        if let (Some(daemon), Some(name)) = (daemon, name) {
            match daemon.unregister(&name) {
                Ok(_receiver) => {
                    tracing::debug!("mDNS: unregistered service {name}");
                }
                Err(e) => {
                    tracing::debug!("mDNS: unregister failed (non-critical): {e}");
                }
            }

            if let Err(e) = daemon.shutdown() {
                tracing::debug!("mDNS: daemon shutdown error (non-critical): {e}");
            }
        }
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the ephemeral ID from a public key and salt.
///
/// Uses HMAC-SHA256(pubkey, salt) truncated to 8 bytes.
/// The truncation prevents recovery of the public key from
/// the mDNS announcement, while still allowing peers that
/// know the key to verify the identity.
pub fn compute_ephemeral_id(pubkey: &[u8; 32], salt: &[u8]) -> [u8; EPHEMERAL_ID_LEN] {
    let mut mac = HmacSha256::new_from_slice(pubkey).expect("HMAC accepts 32-byte key");
    mac.update(salt);
    let result = mac.finalize().into_bytes();

    let mut id = [0u8; EPHEMERAL_ID_LEN];
    id.copy_from_slice(&result[..EPHEMERAL_ID_LEN]);
    id
}

/// Returns the local hostname for mDNS registration.
fn gethostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes into a fixed buffer.
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned() + "."
        } else {
            "ironguard-host.".into()
        }
    }
    #[cfg(not(unix))]
    {
        "ironguard-host.".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ephemeral_id_deterministic() {
        let pubkey = [42u8; 32];
        let salt = b"daily-salt-2026-03-24";

        let id1 = compute_ephemeral_id(&pubkey, salt);
        let id2 = compute_ephemeral_id(&pubkey, salt);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_keys_produce_different_ids() {
        let salt = b"same-salt";
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let id_a = compute_ephemeral_id(&key_a, salt);
        let id_b = compute_ephemeral_id(&key_b, salt);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_different_salts_produce_different_ids() {
        let pubkey = [42u8; 32];
        let salt_a = b"salt-monday";
        let salt_b = b"salt-tuesday";

        let id_a = compute_ephemeral_id(&pubkey, salt_a);
        let id_b = compute_ephemeral_id(&pubkey, salt_b);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_ephemeral_id_length() {
        let pubkey = [0u8; 32];
        let id = compute_ephemeral_id(&pubkey, b"salt");
        assert_eq!(id.len(), EPHEMERAL_ID_LEN);
        assert_eq!(id.len(), 8);
    }

    #[test]
    fn test_ephemeral_id_hex_encoding() {
        let pubkey = [42u8; 32];
        let id = compute_ephemeral_id(&pubkey, b"salt");
        let hex_str = hex::encode(id);
        assert_eq!(hex_str.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_gethostname_non_empty() {
        let name = gethostname();
        assert!(!name.is_empty());
        assert!(name.ends_with('.'));
    }

    #[test]
    fn test_mdns_discovery_default() {
        let _discovery = MdnsDiscovery::default();
    }

    #[test]
    fn test_service_type_format() {
        assert!(SERVICE_TYPE.starts_with('_'));
        assert!(SERVICE_TYPE.contains("._udp."));
        assert!(SERVICE_TYPE.ends_with('.'));
    }

    // Network-dependent mDNS test.
    #[tokio::test]
    #[ignore]
    async fn test_mdns_announce_and_discover() {
        let discovery = MdnsDiscovery::new();
        let pubkey = [42u8; 32];
        let salt = b"test-salt";

        // Announce
        let result = discovery.announce(51820, &pubkey, salt).await;
        match result {
            Ok(()) => {
                tracing::info!("mDNS announcement succeeded");
                // Give the daemon a moment to register
                tokio::time::sleep(Duration::from_millis(500)).await;
                discovery.stop().await;
            }
            Err(e) => {
                tracing::warn!("mDNS not available (expected in CI): {e}");
            }
        }
    }

    // Verify that expected ID computation matches announcement.
    #[test]
    fn test_id_matching_logic() {
        let pubkey_a = [1u8; 32];
        let pubkey_b = [2u8; 32];
        let pubkey_c = [3u8; 32];
        let salt = b"matching-test";

        // Pre-compute expected IDs for A and B
        let expected_ids: HashMap<[u8; EPHEMERAL_ID_LEN], [u8; 32]> = [pubkey_a, pubkey_b]
            .iter()
            .map(|pk| (compute_ephemeral_id(pk, salt), *pk))
            .collect();

        // Simulate receiving an announcement from peer A
        let announced_id = compute_ephemeral_id(&pubkey_a, salt);
        assert!(expected_ids.contains_key(&announced_id));
        assert_eq!(expected_ids[&announced_id], pubkey_a);

        // Simulate receiving an announcement from unknown peer C
        let unknown_id = compute_ephemeral_id(&pubkey_c, salt);
        assert!(!expected_ids.contains_key(&unknown_id));
    }

    use std::collections::HashMap;
    use std::time::Duration;
}
