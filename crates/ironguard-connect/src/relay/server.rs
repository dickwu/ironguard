//! IronGuard relay server.
//!
//! A simple QUIC-based relay that forwards encrypted packets between
//! registered peers. The relay never sees plaintext -- it only routes
//! opaque bytes based on ephemeral tokens.
//!
//! ~250 lines. Self-hostable. Designed to be the guaranteed fallback
//! when all direct connection methods fail.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::Endpoint;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use super::protocol::RelayMessage;

/// Maximum concurrent connections the relay will accept.
const MAX_CONNECTIONS: usize = 1024;

/// Idle connection timeout (no messages for this long = disconnect).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Health check interval (server sends ping if no activity).
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Errors from relay server operations.
#[derive(Debug, Error)]
pub enum RelayServerError {
    /// QUIC endpoint creation failed.
    #[error("endpoint error: {0}")]
    EndpointError(String),

    /// TLS configuration error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// Connection handling error.
    #[error("connection error: {0}")]
    ConnectionError(String),

    /// Message handling error.
    #[error("message error: {0}")]
    MessageError(String),
}

/// State for a single registered peer connection.
struct PeerConnection {
    /// The QUIC connection handle for sending messages.
    connection: quinn::Connection,
    /// When the peer last sent a message (for idle detection).
    _last_activity: Instant,
    /// The peer's ephemeral relay token.
    _token: String,
}

/// A simple relay server that forwards encrypted bytes between peers.
///
/// Peers register with ephemeral tokens. When peer A sends a Forward
/// message addressed to peer B's token, the relay wraps it in a
/// Deliver message and sends it to B's QUIC connection.
pub struct RelayServer {
    /// Registered peer connections indexed by their ephemeral token.
    peers: Arc<RwLock<HashMap<String, Arc<Mutex<PeerConnection>>>>>,
}

impl RelayServer {
    /// Creates a new relay server.
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Runs the relay server, accepting QUIC connections on the bind address.
    ///
    /// This method blocks until the server is shut down. Each incoming
    /// connection is handled in a separate tokio task.
    pub async fn run(&self, bind_addr: SocketAddr) -> Result<(), RelayServerError> {
        let endpoint = create_server_endpoint(bind_addr)?;

        tracing::info!("relay server listening on {bind_addr}");

        loop {
            let incoming = match endpoint.accept().await {
                Some(conn) => conn,
                None => {
                    tracing::info!("relay server endpoint closed");
                    break;
                }
            };

            let peer_count = self.peers.read().await.len();
            if peer_count >= MAX_CONNECTIONS {
                tracing::warn!("relay at capacity ({MAX_CONNECTIONS} connections), rejecting");
                incoming.refuse();
                continue;
            }

            let peers = self.peers.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        let remote = connection.remote_address();
                        tracing::debug!("relay: new connection from {remote}");
                        if let Err(e) = handle_connection(connection, peers).await {
                            tracing::debug!("relay: connection from {remote} ended: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::debug!("relay: incoming connection failed: {e}");
                    }
                }
            });
        }

        Ok(())
    }

    /// Returns the number of currently registered peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

impl Default for RelayServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Handles a single QUIC connection lifecycle.
///
/// Reads bidirectional streams from the connection. The first message
/// on each stream must be a Register. Subsequent messages on any
/// stream are Forward messages that get routed to the target peer.
async fn handle_connection(
    connection: quinn::Connection,
    peers: Arc<RwLock<HashMap<String, Arc<Mutex<PeerConnection>>>>>,
) -> Result<(), RelayServerError> {
    let remote = connection.remote_address();
    let mut registered_token: Option<String> = None;

    // Accept streams from this connection
    loop {
        let stream = tokio::select! {
            stream = connection.accept_bi() => {
                match stream {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("relay: connection {remote} stream error: {e}");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(IDLE_TIMEOUT) => {
                tracing::debug!("relay: connection {remote} idle timeout");
                break;
            }
        };

        let (send, recv) = stream;
        let token = registered_token.clone();
        let peers_clone = peers.clone();
        let conn_clone = connection.clone();

        // Handle the stream
        match handle_stream(recv, send, token, peers_clone, conn_clone).await {
            Ok(Some(new_token)) => {
                registered_token = Some(new_token);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("relay: stream error from {remote}: {e}");
            }
        }
    }

    // Unregister on disconnect
    if let Some(token) = &registered_token {
        let mut peers_guard = peers.write().await;
        peers_guard.remove(token);
        tracing::debug!(
            "relay: unregistered peer {remote} (token={}...)",
            &token[..8.min(token.len())]
        );
    }

    Ok(())
}

/// Handles a single bidirectional stream.
///
/// Returns `Some(token)` if the peer registered on this stream.
async fn handle_stream(
    mut recv: quinn::RecvStream,
    mut send: quinn::SendStream,
    current_token: Option<String>,
    peers: Arc<RwLock<HashMap<String, Arc<Mutex<PeerConnection>>>>>,
    connection: quinn::Connection,
) -> Result<Option<String>, RelayServerError> {
    // Read the message
    let data = recv
        .read_to_end(65536)
        .await
        .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;

    let msg = RelayMessage::from_bytes(&data)
        .map_err(|e| RelayServerError::MessageError(e.to_string()))?;

    match msg {
        RelayMessage::Register { token } => {
            let short_token = &token[..8.min(token.len())];
            tracing::debug!(
                "relay: register request from {} (token={}...)",
                connection.remote_address(),
                short_token
            );

            let peer_conn = PeerConnection {
                connection: connection.clone(),
                _last_activity: Instant::now(),
                _token: token.clone(),
            };

            {
                let mut peers_guard = peers.write().await;
                peers_guard.insert(token.clone(), Arc::new(Mutex::new(peer_conn)));
            }

            let response = RelayMessage::Registered {
                ok: true,
                reason: None,
            };
            let response_bytes = response
                .to_bytes()
                .map_err(|e| RelayServerError::MessageError(e.to_string()))?;

            send.write_all(&response_bytes)
                .await
                .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;
            send.finish()
                .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;

            Ok(Some(token))
        }

        RelayMessage::Forward { to_token, data } => {
            let from_token = current_token.unwrap_or_else(|| "anonymous".into());
            let short_from = &from_token[..8.min(from_token.len())];
            let short_to = &to_token[..8.min(to_token.len())];
            tracing::trace!(
                "relay: forward from {}... to {}... ({} bytes)",
                short_from,
                short_to,
                data.len()
            );

            // Look up the target peer
            let target = {
                let peers_guard = peers.read().await;
                peers_guard.get(&to_token).cloned()
            };

            match target {
                Some(peer) => {
                    let deliver = RelayMessage::Deliver {
                        from_token: from_token.clone(),
                        data,
                    };
                    let deliver_bytes = deliver
                        .to_bytes()
                        .map_err(|e| RelayServerError::MessageError(e.to_string()))?;

                    let peer_guard = peer.lock().await;
                    let (mut peer_send, _) = peer_guard
                        .connection
                        .open_bi()
                        .await
                        .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;

                    peer_send
                        .write_all(&deliver_bytes)
                        .await
                        .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;
                    peer_send
                        .finish()
                        .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;
                }
                None => {
                    tracing::debug!("relay: target peer {}... not found", short_to);
                }
            }

            // Acknowledge on the sender's stream
            send.finish()
                .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;

            Ok(None)
        }

        RelayMessage::Ping { seq } => {
            let response = RelayMessage::Pong { seq };
            let response_bytes = response
                .to_bytes()
                .map_err(|e| RelayServerError::MessageError(e.to_string()))?;
            send.write_all(&response_bytes)
                .await
                .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;
            send.finish()
                .map_err(|e| RelayServerError::ConnectionError(e.to_string()))?;
            Ok(None)
        }

        _ => {
            tracing::debug!("relay: unexpected message type from client");
            Ok(None)
        }
    }
}

/// Creates a QUIC server endpoint with a self-signed certificate.
fn create_server_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, RelayServerError> {
    let cert = rcgen::generate_simple_self_signed(vec!["relay.ironguard.local".into()])
        .map_err(|e| RelayServerError::TlsError(e.to_string()))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der.into())
        .map_err(|e| RelayServerError::TlsError(e.to_string()))?;

    // Configure transport
    let transport = Arc::new(quinn::TransportConfig::default());
    server_config.transport_config(transport);

    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| RelayServerError::EndpointError(e.to_string()))?;

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_server_default() {
        let _server = RelayServer::default();
    }

    #[tokio::test]
    async fn test_relay_server_initial_peer_count() {
        let server = RelayServer::new();
        assert_eq!(server.peer_count().await, 0);
    }

    #[test]
    fn test_constants() {
        assert!(MAX_CONNECTIONS >= 100);
        assert!(IDLE_TIMEOUT.as_secs() >= 30);
        assert_eq!(HEALTH_CHECK_INTERVAL.as_secs(), 5);
    }

    #[tokio::test]
    async fn test_create_server_endpoint() {
        // Bind to an ephemeral port (requires tokio runtime for quinn)
        let result = create_server_endpoint("127.0.0.1:0".parse().unwrap());
        assert!(result.is_ok());
    }

    // Integration test: start server and connect a client.
    #[tokio::test]
    #[ignore]
    async fn test_relay_server_client_integration() {
        let server = RelayServer::new();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // This would need a full client implementation to test properly.
        // For now, just verify the server starts and stops cleanly.
        let server_handle = tokio::spawn(async move {
            let _ = server.run(bind_addr).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        server_handle.abort();
    }
}
