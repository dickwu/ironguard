//! Background tasks for QUIC session lifecycle management.
//!
//! Two async tasks that run alongside the WireGuard device workers:
//!
//! - **Accept loop** (`quic_accept_loop`) -- listens for inbound QUIC
//!   connections and establishes sessions with connecting peers.
//! - **Rekey timer** (`rekey_timer_task`) -- periodically checks session age
//!   and initiates epoch-based rekeying when `REKEY_AFTER_TIME` is exceeded.
//!
//! Both tasks take `Arc<SessionManager>` and a callback to install derived
//! keypairs into the WireGuard router.
//!
//! Gated behind `feature = "quic"`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::manager::{SessionManager, SessionResult};
use crate::constants::REKEY_AFTER_TIME;

/// How often the rekey timer checks sessions (30 seconds).
const REKEY_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Callback trait for installing keypairs into the WireGuard device.
///
/// Implemented by the CLI layer to bridge the gap between the session
/// manager (which derives keys) and the router (which encrypts/decrypts).
pub trait KeyInstaller: Send + Sync + 'static {
    /// Install a new keypair for the peer identified by `peer_pk`.
    ///
    /// `session` contains the derived keys, epoch, and receiver_id.
    /// `initiator` indicates whether we initiated this session.
    fn install_keypair(&self, peer_pk: &[u8; 32], session: &SessionResult, initiator: bool);
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

/// Run an accept loop on a QUIC server endpoint.
///
/// For each inbound connection:
/// 1. Accepts the QUIC connection from the `quinn::Endpoint`.
/// 2. Calls `session_mgr.accept()` to perform the data-plane key exchange.
/// 3. Calls `key_installer.install_keypair()` to push keys into the router.
///
/// The task runs until `stop` is set to `true` or the endpoint is closed.
///
/// `known_peers` is consulted to map inbound connections to peer public keys.
/// Connections from unknown peers are dropped.
#[allow(clippy::too_many_arguments)]
pub async fn quic_accept_loop<K: KeyInstaller>(
    endpoint: quinn::Endpoint,
    session_mgr: Arc<SessionManager>,
    key_installer: Arc<K>,
    known_peers: Arc<PeerLookup>,
    known_peer_pks: std::collections::HashSet<[u8; 32]>,
    data_port: u16,
    stop: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    let known_peer_pks = Arc::new(known_peer_pks);
    tracing::info!("QUIC accept loop started");

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Wait for an inbound connection or shutdown signal.
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            () = shutdown.notified() => {
                tracing::info!("QUIC accept loop: shutdown signal received");
                break;
            }
        };

        let incoming = match incoming {
            Some(inc) => inc,
            None => {
                tracing::info!("QUIC accept loop: endpoint closed");
                break;
            }
        };

        let session_mgr = session_mgr.clone();
        let key_installer = key_installer.clone();
        let known_peers = known_peers.clone();
        let known_peer_pks = known_peer_pks.clone();
        let stop = stop.clone();

        // Handle each connection in a separate task so the accept loop
        // is not blocked by slow key exchanges.
        tokio::spawn(async move {
            if stop.load(Ordering::Relaxed) {
                return;
            }

            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "QUIC accept: connection failed");
                    return;
                }
            };

            let remote_addr = connection.remote_address();

            // Identify the peer: prefer mTLS certificate identity, fall back
            // to address-based lookup.
            let peer_pk = match crate::session::quic::extract_peer_identity(&connection) {
                Some(pk) if known_peer_pks.contains(&pk) => pk,
                _ => match known_peers.lookup_by_addr(&remote_addr) {
                    Some(pk) => pk,
                    None => {
                        tracing::warn!(
                            remote = %remote_addr,
                            "QUIC accept: unknown peer, dropping connection"
                        );
                        return;
                    }
                },
            };

            let receiver_id: u32 = rand::random();

            match session_mgr
                .accept(peer_pk, connection, None, data_port, receiver_id)
                .await
            {
                Ok(result) => {
                    tracing::info!(
                        remote = %remote_addr,
                        epoch = result.epoch,
                        receiver_id = result.receiver_id,
                        "QUIC session accepted"
                    );
                    key_installer.install_keypair(&peer_pk, &result, false);
                }
                Err(e) => {
                    tracing::warn!(
                        remote = %remote_addr,
                        error = %e,
                        "QUIC accept: key exchange failed"
                    );
                }
            }
        });
    }

    tracing::info!("QUIC accept loop stopped");
}

// ---------------------------------------------------------------------------
// Rekey timer
// ---------------------------------------------------------------------------

/// Periodically check all sessions and rekey those older than `REKEY_AFTER_TIME`.
///
/// For each session that crosses the threshold:
/// 1. Calls `session_mgr.rekey()` to perform the epoch-based rekey.
/// 2. Calls `key_installer.install_keypair()` to push new keys into the router.
///
/// Runs on a `REKEY_CHECK_INTERVAL` (30s) tick until `stop` is set.
pub async fn rekey_timer_task<K: KeyInstaller>(
    session_mgr: Arc<SessionManager>,
    key_installer: Arc<K>,
    stop: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    tracing::info!(
        "rekey timer started (interval={REKEY_CHECK_INTERVAL:?}, threshold={REKEY_AFTER_TIME:?})"
    );

    let mut interval = tokio::time::interval(REKEY_CHECK_INTERVAL);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            () = shutdown.notified() => {
                tracing::info!("rekey timer: shutdown signal received");
                break;
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }

        let peer_keys = session_mgr.peer_keys();
        let now = Instant::now();

        for peer_pk in &peer_keys {
            let needs_rekey = session_mgr
                .session_info(peer_pk)
                .map(|(_, established_at, _)| {
                    now.duration_since(established_at) >= REKEY_AFTER_TIME
                })
                .unwrap_or(false);

            if !needs_rekey {
                continue;
            }

            tracing::info!(
                peer = hex::encode(peer_pk),
                "session exceeded rekey threshold, initiating rekey"
            );

            match session_mgr.rekey(peer_pk).await {
                Ok(result) => {
                    tracing::info!(
                        peer = hex::encode(peer_pk),
                        epoch = result.epoch,
                        "rekey succeeded"
                    );
                    key_installer.install_keypair(peer_pk, &result, true);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = hex::encode(peer_pk),
                        error = %e,
                        "rekey failed"
                    );
                }
            }
        }
    }

    tracing::info!("rekey timer stopped");
}

// ---------------------------------------------------------------------------
// Peer lookup table
// ---------------------------------------------------------------------------

/// Maps remote socket addresses to peer public keys.
///
/// Used by the accept loop to identify which peer is connecting.
/// Populated from the config at startup.
///
/// Peers without configured endpoints are stored as "wildcard" entries
/// and will accept connections from any address.
pub struct PeerLookup {
    /// addr -> peer public key (peers with known endpoints)
    entries: parking_lot::RwLock<Vec<(std::net::SocketAddr, [u8; 32])>>,
    /// Peers without endpoints that accept connections from any address.
    wildcard_peers: parking_lot::RwLock<Vec<[u8; 32]>>,
}

impl PeerLookup {
    pub fn new() -> Self {
        Self {
            entries: parking_lot::RwLock::new(Vec::new()),
            wildcard_peers: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a peer's address and public key.
    pub fn add(&self, addr: std::net::SocketAddr, peer_pk: [u8; 32]) {
        self.entries.write().push((addr, peer_pk));
    }

    /// Register a peer without a known address (server-side peer).
    ///
    /// Wildcard peers accept connections from any IP. When a connection
    /// arrives from an unknown address, the first unclaimed wildcard peer
    /// is returned.
    pub fn add_wildcard(&self, peer_pk: [u8; 32]) {
        self.wildcard_peers.write().push(peer_pk);
    }

    /// Look up a peer public key by remote address.
    ///
    /// Checks address-matched entries (IP only, ignoring port since QUIC
    /// clients use ephemeral source ports). Returns `None` if no entry
    /// matches -- wildcard peers are NOT used as a fallback to avoid
    /// misrouting in multi-peer configurations.
    pub fn lookup_by_addr(&self, addr: &std::net::SocketAddr) -> Option<[u8; 32]> {
        let entries = self.entries.read();
        for (entry_addr, pk) in entries.iter() {
            if entry_addr.ip() == addr.ip() {
                return Some(*pk);
            }
        }
        None
    }
}

impl Default for PeerLookup {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: check if a session needs rekeying
// ---------------------------------------------------------------------------

/// Returns `true` if the session for `peer_pk` has been alive longer than
/// `REKEY_AFTER_TIME`.
pub fn needs_rekey(session_mgr: &SessionManager, peer_pk: &[u8; 32]) -> bool {
    session_mgr
        .session_info(peer_pk)
        .map(|(_, established_at, _)| {
            Instant::now().duration_since(established_at) >= REKEY_AFTER_TIME
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::manager::SessionManager;
    use super::super::quic::{QuicSessionConfig, make_test_server_config};
    use super::*;

    /// A no-op key installer for testing.
    struct NoopInstaller {
        installs: parking_lot::Mutex<Vec<([u8; 32], u32, bool)>>,
    }

    impl NoopInstaller {
        fn new() -> Self {
            Self {
                installs: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn install_count(&self) -> usize {
            self.installs.lock().len()
        }
    }

    impl KeyInstaller for NoopInstaller {
        fn install_keypair(&self, peer_pk: &[u8; 32], session: &SessionResult, initiator: bool) {
            self.installs
                .lock()
                .push((*peer_pk, session.epoch, initiator));
        }
    }

    #[test]
    fn test_peer_lookup_by_ip() {
        let lookup = PeerLookup::new();
        let pk = [0xAA; 32];
        lookup.add("10.0.0.1:51820".parse().unwrap(), pk);

        // Same IP, different port should match.
        let result = lookup.lookup_by_addr(&"10.0.0.1:12345".parse().unwrap());
        assert_eq!(result, Some(pk));

        // Different IP should not match.
        let result = lookup.lookup_by_addr(&"10.0.0.2:51820".parse().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn lookup_by_addr_no_wildcard_fallback() {
        let lookup = PeerLookup::new();
        lookup.add_wildcard([1u8; 32]);
        lookup.add_wildcard([2u8; 32]);
        let unknown: std::net::SocketAddr = "203.0.113.1:12345".parse().unwrap();
        assert!(
            lookup.lookup_by_addr(&unknown).is_none(),
            "wildcard peers must not be used as fallback"
        );
    }

    #[test]
    fn lookup_by_addr_ip_match() {
        let lookup = PeerLookup::new();
        let addr: std::net::SocketAddr = "10.0.0.1:51820".parse().unwrap();
        lookup.add(addr, [3u8; 32]);
        let query: std::net::SocketAddr = "10.0.0.1:9999".parse().unwrap();
        assert_eq!(lookup.lookup_by_addr(&query), Some([3u8; 32]));
    }

    #[test]
    fn test_needs_rekey_no_session() {
        let mgr = SessionManager::new(QuicSessionConfig::default());
        assert!(!needs_rekey(&mgr, &[0u8; 32]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_needs_rekey_fresh_session() {
        // Set up a QUIC session so we have a real PeerSession.
        let server_config = make_test_server_config();
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint");
        let server_port = server_endpoint.local_addr().unwrap().port();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let server_barrier = barrier.clone();

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept");
            let conn = incoming.await.expect("connection");
            let mgr = SessionManager::new(QuicSessionConfig::default());
            let _ = mgr.accept([0xAA; 32], conn, None, 51821, 200).await;
            server_barrier.wait().await;
        });

        let client_mgr = Arc::new(SessionManager::new(QuicSessionConfig::default()));
        let peer_pk = [0xBB; 32];

        client_mgr
            .connect(
                peer_pk,
                format!("127.0.0.1:{server_port}").parse().unwrap(),
                None,
                51820,
                100,
            )
            .await
            .expect("connect");

        // Fresh session should NOT need rekey.
        assert!(!needs_rekey(&client_mgr, &peer_pk));

        barrier.wait().await;
        server_handle.await.expect("server join");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accept_loop_stops_on_shutdown() {
        let server_config = make_test_server_config();
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");

        let session_mgr = Arc::new(SessionManager::new(QuicSessionConfig::default()));
        let installer = Arc::new(NoopInstaller::new());
        let known_peers = Arc::new(PeerLookup::new());
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());

        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(quic_accept_loop(
            endpoint,
            session_mgr,
            installer.clone(),
            known_peers,
            std::collections::HashSet::new(),
            51820,
            stop,
            shutdown_clone,
        ));

        // Signal shutdown after a short delay.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_waiters();

        // The task should complete promptly.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "accept loop should stop on shutdown signal");
        assert_eq!(installer.install_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_rekey_timer_stops_on_shutdown() {
        let session_mgr = Arc::new(SessionManager::new(QuicSessionConfig::default()));
        let installer = Arc::new(NoopInstaller::new());
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());

        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(rekey_timer_task(
            session_mgr,
            installer.clone(),
            stop,
            shutdown_clone,
        ));

        // Signal shutdown after a short delay.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_waiters();

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "rekey timer should stop on shutdown signal");
        assert_eq!(installer.install_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_rekey_timer_stops_on_stop_flag() {
        let session_mgr = Arc::new(SessionManager::new(QuicSessionConfig::default()));
        let installer = Arc::new(NoopInstaller::new());
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());

        let stop_clone = stop.clone();
        let handle = tokio::spawn(rekey_timer_task(
            session_mgr,
            installer,
            stop_clone,
            shutdown,
        ));

        // Set the stop flag.
        stop.store(true, Ordering::Relaxed);

        let result = tokio::time::timeout(Duration::from_secs(35), handle).await;
        assert!(result.is_ok(), "rekey timer should stop on stop flag");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accept_loop_rejects_unknown_peer() {
        let server_config = make_test_server_config();
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");
        let server_port = endpoint.local_addr().unwrap().port();

        let session_mgr = Arc::new(SessionManager::new(QuicSessionConfig::default()));
        let installer = Arc::new(NoopInstaller::new());
        // Empty peer lookup -- no known peers.
        let known_peers = Arc::new(PeerLookup::new());
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());

        let shutdown_clone = shutdown.clone();
        let accept_handle = tokio::spawn(quic_accept_loop(
            endpoint,
            session_mgr,
            installer.clone(),
            known_peers,
            std::collections::HashSet::new(),
            51820,
            stop,
            shutdown_clone,
        ));

        // Connect from a client (unknown peer).
        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
        client_endpoint.set_default_client_config(super::super::quic::make_test_client_config());

        let _conn = client_endpoint
            .connect(
                format!("127.0.0.1:{server_port}").parse().unwrap(),
                "ironguard",
            )
            .expect("connect")
            .await;

        // Give the accept loop time to process.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // No keypair should have been installed.
        assert_eq!(installer.install_count(), 0);

        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), accept_handle).await;
    }
}
