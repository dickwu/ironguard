//! Session manager that orchestrates QUIC-based key exchange per peer.
//!
//! `SessionManager` owns the mapping from peer public keys to active
//! `PeerSession`s. It drives the QUIC handshake, data-plane key exchange, and
//! epoch-based rekeying.
//!
//! Gated behind `feature = "quic"`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;

use super::keys::{DataPlaneKeys, Role, derive_epoch_keys};
use super::quic::{QuicSessionConfig, exchange_data_plane_keys, make_test_client_config};
use super::state::{SessionError, SessionState};

// ---------------------------------------------------------------------------
// Per-peer session
// ---------------------------------------------------------------------------

/// Tracks one active QUIC session with a remote peer.
pub struct PeerSession {
    /// The underlying QUIC connection (kept alive for rekeying).
    pub connection: quinn::Connection,
    /// Current data-plane keys derived from the session.
    pub keys: DataPlaneKeys,
    /// Current epoch (0 = initial keys, 1+ = rekeyed).
    pub epoch: u32,
    /// Our receiver ID advertised to this peer.
    pub receiver_id: u32,
    /// The TLS exporter secret, retained for epoch-based rekeying.
    exporter_secret: [u8; 64],
    /// Our role in the session (client or server).
    role: Role,
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Manages QUIC sessions for all peers on a device.
///
/// Holds configuration, per-peer sessions, and the shared rekey/migration
/// state machine.
pub struct SessionManager {
    config: QuicSessionConfig,
    state: Arc<Mutex<SessionState>>,
    sessions: HashMap<[u8; 32], PeerSession>,
}

impl SessionManager {
    /// Create a new session manager with the given QUIC configuration.
    pub fn new(config: QuicSessionConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(SessionState::new())),
            sessions: HashMap::new(),
        }
    }

    /// Return the bind address from the configuration.
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// Return the number of active peer sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Look up a peer session by public key bytes.
    pub fn get_session(&self, peer_pk: &[u8; 32]) -> Option<&PeerSession> {
        self.sessions.get(peer_pk)
    }

    // ── connect (client role) ────────────────────────────────────────────

    /// Initiate a QUIC connection to `peer_addr`, perform the data-plane key
    /// exchange, and store the resulting `PeerSession`.
    ///
    /// `peer_pk` is the 32-byte public key used to index the session.
    /// `data_port` is the UDP port we will use for the raw data plane.
    /// `receiver_id` is our local receiver ID to advertise.
    pub async fn connect(
        &mut self,
        peer_pk: [u8; 32],
        peer_addr: SocketAddr,
        data_port: u16,
        receiver_id: u32,
    ) -> Result<&PeerSession, SessionError> {
        // Build a client endpoint bound to the configured address.
        let mut endpoint = quinn::Endpoint::client(self.config.bind_addr)
            .map_err(|e| SessionError::QuicDatagram(format!("bind client: {e}")))?;

        endpoint.set_default_client_config(make_test_client_config());

        let sni = "ironguard";

        let connection = endpoint
            .connect(peer_addr, sni)
            .map_err(|e| SessionError::QuicDatagram(format!("connect: {e}")))?
            .await
            .map_err(|e| SessionError::QuicDatagram(format!("handshake: {e}")))?;

        let (keys, _peer_init) =
            exchange_data_plane_keys(&connection, Role::Client, data_port, receiver_id).await?;

        // Extract the TLS exporter secret for future rekeying.
        let mut exporter_secret = [0u8; 64];
        connection
            .export_keying_material(&mut exporter_secret, b"EXPORTER-ironguard-data-plane", &[])
            .map_err(|_| SessionError::InvalidState)?;

        let session = PeerSession {
            connection,
            keys,
            epoch: 0,
            receiver_id,
            exporter_secret,
            role: Role::Client,
        };

        self.sessions.insert(peer_pk, session);
        Ok(self.sessions.get(&peer_pk).unwrap())
    }

    // ── accept (server role) ─────────────────────────────────────────────

    /// Accept an incoming QUIC connection, perform the data-plane key
    /// exchange, and store the resulting `PeerSession`.
    ///
    /// `peer_pk` is the 32-byte public key used to index the session.
    /// `data_port` is the UDP port we will use for the raw data plane.
    /// `receiver_id` is our local receiver ID to advertise.
    pub async fn accept(
        &mut self,
        peer_pk: [u8; 32],
        connection: quinn::Connection,
        data_port: u16,
        receiver_id: u32,
    ) -> Result<&PeerSession, SessionError> {
        let (keys, _peer_init) =
            exchange_data_plane_keys(&connection, Role::Server, data_port, receiver_id).await?;

        // Extract the TLS exporter secret for future rekeying.
        let mut exporter_secret = [0u8; 64];
        connection
            .export_keying_material(&mut exporter_secret, b"EXPORTER-ironguard-data-plane", &[])
            .map_err(|_| SessionError::InvalidState)?;

        let session = PeerSession {
            connection,
            keys,
            epoch: 0,
            receiver_id,
            exporter_secret,
            role: Role::Server,
        };

        self.sessions.insert(peer_pk, session);
        Ok(self.sessions.get(&peer_pk).unwrap())
    }

    // ── rekey ────────────────────────────────────────────────────────────

    /// Perform an epoch-based rekey for the given peer.
    ///
    /// Uses the `SessionState` state machine to drive the rekey protocol:
    /// 1. Initiator generates entropy and sends `RekeyInit` via QUIC datagram.
    /// 2. Responder replies with `RekeyAck` containing its own entropy.
    /// 3. Both sides derive new keys from the TLS exporter + epoch + entropy.
    pub async fn rekey(&mut self, peer_pk: &[u8; 32]) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get(peer_pk)
            .ok_or(SessionError::InvalidState)?;

        let exporter_secret = session.exporter_secret;
        let role = session.role;

        // Drive the state machine.
        let our_entropy: [u8; 32] = rand::random();
        let our_receiver_id: u32 = rand::random();

        let init_msg = {
            let mut state = self.state.lock();
            state.initiate_rekey(our_entropy, our_receiver_id)
        };

        // Serialize and send the rekey init as a QUIC datagram.
        let init_bytes = format!(
            "{{\"epoch\":{},\"fresh_entropy\":\"{}\",\"new_receiver_id\":{}}}",
            init_msg.epoch,
            hex::encode(init_msg.fresh_entropy),
            init_msg.new_receiver_id
        );
        session
            .connection
            .send_datagram(init_bytes.into_bytes().into())
            .map_err(|e| SessionError::QuicDatagram(format!("send rekey init: {e}")))?;

        // Read the responder's ack datagram.
        let ack_bytes = session
            .connection
            .read_datagram()
            .await
            .map_err(|e| SessionError::QuicDatagram(format!("read rekey ack: {e}")))?;

        // Parse minimal fields from the ack.
        let ack_str = std::str::from_utf8(&ack_bytes).map_err(|_| SessionError::InvalidState)?;
        let ack_value: serde_json::Value =
            serde_json::from_str(ack_str).map_err(|_| SessionError::InvalidState)?;

        let responder_epoch = ack_value["epoch"]
            .as_u64()
            .ok_or(SessionError::InvalidState)? as u32;
        let responder_entropy_hex = ack_value["fresh_entropy"]
            .as_str()
            .ok_or(SessionError::InvalidState)?;
        let responder_entropy_vec =
            hex::decode(responder_entropy_hex).map_err(|_| SessionError::InvalidState)?;
        let mut responder_entropy = [0u8; 32];
        if responder_entropy_vec.len() != 32 {
            return Err(SessionError::InvalidState);
        }
        responder_entropy.copy_from_slice(&responder_entropy_vec);

        let new_receiver_id = ack_value["new_receiver_id"]
            .as_u64()
            .ok_or(SessionError::InvalidState)? as u32;

        let ack = super::state::RekeyAck {
            epoch: responder_epoch,
            fresh_entropy: responder_entropy,
            new_receiver_id,
        };

        let (epoch, initiator_entropy, resp_entropy) = {
            let mut state = self.state.lock();
            state.handle_rekey_ack(&ack)?
        };

        // Derive new data-plane keys for this epoch.
        let new_keys = derive_epoch_keys(
            &exporter_secret,
            epoch,
            &initiator_entropy,
            &resp_entropy,
            role,
        );

        // Update the session in place.
        let session = self
            .sessions
            .get_mut(peer_pk)
            .ok_or(SessionError::InvalidState)?;
        session.keys = new_keys;
        session.epoch = epoch;
        session.receiver_id = new_receiver_id;

        Ok(())
    }

    /// Remove a peer session, closing the underlying QUIC connection.
    pub fn remove_session(&mut self, peer_pk: &[u8; 32]) -> Option<PeerSession> {
        self.sessions.remove(peer_pk)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::quic::make_test_server_config;
    use super::*;

    #[test]
    fn test_session_manager_new() {
        let config = QuicSessionConfig::default();
        let mgr = SessionManager::new(config);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_session_manager_get_missing() {
        let config = QuicSessionConfig::default();
        let mgr = SessionManager::new(config);
        assert!(mgr.get_session(&[0u8; 32]).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_session_manager_connect() {
        // Set up a QUIC server on loopback.
        let server_config = make_test_server_config();
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint");
        let server_port = server_endpoint.local_addr().unwrap().port();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let server_barrier = barrier.clone();

        // Server task: accept and perform key exchange as Server role.
        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept");
            let connection = incoming.await.expect("incoming connection");

            let peer_pk = [0xAA; 32];
            let mut server_mgr = SessionManager::new(QuicSessionConfig::default());
            let session = server_mgr
                .accept(peer_pk, connection, 51821, 200)
                .await
                .expect("server accept");

            let keys = session.keys.clone();
            let epoch = session.epoch;
            let receiver_id = session.receiver_id;

            // Keep connection alive until the client is done.
            server_barrier.wait().await;

            (keys, epoch, receiver_id)
        });

        // Client: connect via SessionManager.
        let peer_pk = [0xBB; 32];
        let mut client_mgr = SessionManager::new(QuicSessionConfig::default());

        let session = client_mgr
            .connect(
                peer_pk,
                format!("127.0.0.1:{server_port}").parse().unwrap(),
                51820,
                100,
            )
            .await
            .expect("client connect");

        let client_keys = session.keys.clone();
        let client_epoch = session.epoch;
        let client_receiver_id = session.receiver_id;

        // Signal server can close.
        barrier.wait().await;

        let (server_keys, server_epoch, server_receiver_id) =
            server_handle.await.expect("server join");

        // Verify key symmetry.
        assert_eq!(
            client_keys.send_key, server_keys.recv_key,
            "client send_key must equal server recv_key"
        );
        assert_eq!(
            client_keys.recv_key, server_keys.send_key,
            "client recv_key must equal server send_key"
        );
        assert_ne!(
            client_keys.send_key, client_keys.recv_key,
            "send and recv keys must differ"
        );

        // Both sessions start at epoch 0.
        assert_eq!(client_epoch, 0);
        assert_eq!(server_epoch, 0);

        // Verify receiver IDs were stored.
        assert_eq!(client_receiver_id, 100);
        assert_eq!(server_receiver_id, 200);

        // Verify sessions are tracked.
        assert_eq!(client_mgr.session_count(), 1);
        assert!(client_mgr.get_session(&peer_pk).is_some());
    }
}
