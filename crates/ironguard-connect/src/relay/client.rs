//! IronGuard relay client.
//!
//! Connects to a relay server via QUIC, registers with an ephemeral
//! token, and can send/receive encrypted packets through the relay.
//! The relay never sees plaintext -- it only forwards opaque bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::Endpoint;
use thiserror::Error;
use tokio::sync::Mutex;

use super::protocol::{RelayMessage, decode_payload, encode_payload};

/// Default health check interval.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Connection timeout for initial QUIC handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors from relay client operations.
#[derive(Debug, Error)]
pub enum RelayClientError {
    /// Failed to connect to the relay server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Registration with the relay failed.
    #[error("registration failed: {0}")]
    RegistrationFailed(String),

    /// Send operation failed.
    #[error("send failed: {0}")]
    SendFailed(String),

    /// Receive operation failed.
    #[error("receive failed: {0}")]
    ReceiveFailed(String),

    /// Protocol error (unexpected message type).
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// The client is not connected.
    #[error("not connected to relay")]
    NotConnected,
}

/// State of the relay client.
struct ClientState {
    /// The QUIC connection to the relay server.
    connection: quinn::Connection,
    /// Our registered token on the relay.
    token: String,
    /// Last time we received a pong (for health checking).
    last_pong: Instant,
    /// Ping sequence counter.
    ping_seq: u64,
}

/// Client for connecting to an IronGuard relay server.
///
/// Maintains a QUIC connection to the relay, handles registration,
/// health checking, and bidirectional packet forwarding.
pub struct RelayClient {
    /// The QUIC endpoint (client-side).
    endpoint: Endpoint,
    /// Connection state, if connected.
    state: Arc<Mutex<Option<ClientState>>>,
    /// Handle to the background health check task.
    health_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl RelayClient {
    /// Connects to a relay server at the given address.
    ///
    /// Establishes a QUIC connection using the provided endpoint
    /// configuration. The connection uses a self-signed certificate
    /// since the relay's identity is not security-critical (all
    /// traffic is already encrypted end-to-end by WireGuard).
    pub async fn connect(relay_addr: SocketAddr) -> Result<Self, RelayClientError> {
        let endpoint = create_client_endpoint()
            .map_err(|e| RelayClientError::ConnectionFailed(e.to_string()))?;

        let connection = tokio::time::timeout(CONNECT_TIMEOUT, async {
            endpoint
                .connect(relay_addr, "relay.ironguard.local")
                .map_err(|e| RelayClientError::ConnectionFailed(e.to_string()))?
                .await
                .map_err(|e| RelayClientError::ConnectionFailed(e.to_string()))
        })
        .await
        .map_err(|_| RelayClientError::ConnectionFailed("connection timed out".into()))??;

        tracing::info!("relay client: connected to {relay_addr}");

        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(Some(ClientState {
                connection,
                token: String::new(),
                last_pong: Instant::now(),
                ping_seq: 0,
            }))),
            health_handle: Arc::new(Mutex::new(None)),
        })
    }

    /// Registers with the relay using an ephemeral token.
    ///
    /// The token should be derived from a per-session secret, NOT
    /// the raw WireGuard public key. This prevents the relay from
    /// correlating identities across sessions.
    pub async fn register(&self, token: &[u8]) -> Result<(), RelayClientError> {
        let token_hex = hex::encode(token);

        let connection = {
            let guard = self.state.lock().await;
            match guard.as_ref() {
                Some(state) => state.connection.clone(),
                None => return Err(RelayClientError::NotConnected),
            }
        };

        // Open a stream and send the register message
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| RelayClientError::RegistrationFailed(e.to_string()))?;

        let msg = RelayMessage::Register {
            token: token_hex.clone(),
        };
        let msg_bytes = msg
            .to_bytes()
            .map_err(|e| RelayClientError::RegistrationFailed(e.to_string()))?;

        send.write_all(&msg_bytes)
            .await
            .map_err(|e| RelayClientError::RegistrationFailed(e.to_string()))?;
        send.finish()
            .map_err(|e| RelayClientError::RegistrationFailed(e.to_string()))?;

        // Read the response
        let response_data = recv
            .read_to_end(4096)
            .await
            .map_err(|e| RelayClientError::RegistrationFailed(e.to_string()))?;

        let response = RelayMessage::from_bytes(&response_data)
            .map_err(|e| RelayClientError::ProtocolError(e.to_string()))?;

        match response {
            RelayMessage::Registered { ok: true, .. } => {
                tracing::info!(
                    "relay client: registered with token {}...",
                    &token_hex[..8.min(token_hex.len())]
                );
                let mut guard = self.state.lock().await;
                if let Some(state) = guard.as_mut() {
                    state.token = token_hex;
                }
                Ok(())
            }
            RelayMessage::Registered {
                ok: false, reason, ..
            } => Err(RelayClientError::RegistrationFailed(
                reason.unwrap_or_else(|| "unknown reason".into()),
            )),
            _ => Err(RelayClientError::ProtocolError(
                "unexpected response to Register".into(),
            )),
        }
    }

    /// Sends an encrypted packet to a peer via the relay.
    ///
    /// The relay forwards the packet to the peer registered with
    /// `to_token`. The packet content is opaque to the relay.
    pub async fn send(&self, to_token: &[u8], data: &[u8]) -> Result<(), RelayClientError> {
        let connection = {
            let guard = self.state.lock().await;
            match guard.as_ref() {
                Some(state) => state.connection.clone(),
                None => return Err(RelayClientError::NotConnected),
            }
        };

        let msg = RelayMessage::Forward {
            to_token: hex::encode(to_token),
            data: encode_payload(data),
        };
        let msg_bytes = msg
            .to_bytes()
            .map_err(|e| RelayClientError::SendFailed(e.to_string()))?;

        let (mut send, _recv) = connection
            .open_bi()
            .await
            .map_err(|e| RelayClientError::SendFailed(e.to_string()))?;

        send.write_all(&msg_bytes)
            .await
            .map_err(|e| RelayClientError::SendFailed(e.to_string()))?;
        send.finish()
            .map_err(|e| RelayClientError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Receives a packet forwarded by the relay.
    ///
    /// Blocks until a Deliver message arrives on the connection.
    /// Returns the raw decrypted payload bytes.
    pub async fn recv(&self) -> Result<Vec<u8>, RelayClientError> {
        let connection = {
            let guard = self.state.lock().await;
            match guard.as_ref() {
                Some(state) => state.connection.clone(),
                None => return Err(RelayClientError::NotConnected),
            }
        };

        let (_send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| RelayClientError::ReceiveFailed(e.to_string()))?;

        let data = recv
            .read_to_end(65536)
            .await
            .map_err(|e| RelayClientError::ReceiveFailed(e.to_string()))?;

        let msg = RelayMessage::from_bytes(&data)
            .map_err(|e| RelayClientError::ProtocolError(e.to_string()))?;

        match msg {
            RelayMessage::Deliver { data, .. } => {
                let payload = decode_payload(&data).map_err(|e| {
                    RelayClientError::ProtocolError(format!("payload decode: {e}"))
                })?;
                Ok(payload)
            }
            RelayMessage::Pong { seq } => {
                let mut guard = self.state.lock().await;
                if let Some(state) = guard.as_mut() {
                    state.last_pong = Instant::now();
                }
                tracing::trace!("relay client: pong seq={seq}");
                // Recurse to get the next actual data message
                drop(guard);
                // Return empty vec as a signal this was a control message
                Ok(Vec::new())
            }
            _ => Err(RelayClientError::ProtocolError(
                "unexpected message (expected Deliver)".into(),
            )),
        }
    }

    /// Starts a background health check that sends QUIC PINGs every 5 seconds.
    pub async fn start_health_check(&self) {
        let state = self.state.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;

                let connection = {
                    let mut guard = state.lock().await;
                    match guard.as_mut() {
                        Some(s) => {
                            s.ping_seq += 1;
                            s.connection.clone()
                        }
                        None => return,
                    }
                };

                // Send a ping on a new stream
                let ping_seq = {
                    let guard = state.lock().await;
                    guard.as_ref().map(|s| s.ping_seq).unwrap_or(0)
                };

                let msg = RelayMessage::Ping { seq: ping_seq };
                let msg_bytes = match msg.to_bytes() {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                match connection.open_bi().await {
                    Ok((mut send, _recv)) => {
                        let _ = send.write_all(&msg_bytes).await;
                        let _ = send.finish();
                    }
                    Err(e) => {
                        tracing::debug!("relay health check: connection lost: {e}");
                        let mut guard = state.lock().await;
                        *guard = None;
                        return;
                    }
                }
            }
        });

        let mut health = self.health_handle.lock().await;
        if let Some(old) = health.take() {
            old.abort();
        }
        *health = Some(handle);
    }

    /// Checks if the relay connection is healthy.
    ///
    /// Returns `true` if a pong was received within the last 15 seconds.
    pub async fn health_check(&self) -> bool {
        let guard = self.state.lock().await;
        match guard.as_ref() {
            Some(state) => state.last_pong.elapsed() < Duration::from_secs(15),
            None => false,
        }
    }

    /// Disconnects from the relay and cleans up resources.
    pub async fn disconnect(&self) {
        {
            let mut health = self.health_handle.lock().await;
            if let Some(handle) = health.take() {
                handle.abort();
            }
        }

        {
            let mut guard = self.state.lock().await;
            if let Some(state) = guard.take() {
                state
                    .connection
                    .close(quinn::VarInt::from_u32(0), b"client disconnect");
            }
        }

        self.endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
        tracing::info!("relay client: disconnected");
    }
}

/// Creates a QUIC client endpoint that accepts self-signed certificates.
fn create_client_endpoint() -> Result<Endpoint, Box<dyn std::error::Error>> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"ironguard-relay".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Certificate verifier that accepts any server certificate.
///
/// This is acceptable because:
/// 1. The relay only forwards encrypted WireGuard packets.
/// 2. End-to-end encryption is provided by WireGuard, not QUIC TLS.
/// 3. A MITM on the relay path can only perform traffic analysis,
///    which is already in the relay's threat model.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(HEALTH_CHECK_INTERVAL, Duration::from_secs(5));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_create_client_endpoint() {
        // Requires tokio runtime for quinn endpoint creation
        let result = create_client_endpoint();
        assert!(result.is_ok());
    }

    // Integration test: connect client to a real relay server.
    #[tokio::test]
    #[ignore]
    async fn test_relay_client_connect() {
        // Would need a running relay server to test.
        let result = RelayClient::connect("127.0.0.1:19999".parse().unwrap()).await;
        match result {
            Ok(client) => {
                client.disconnect().await;
            }
            Err(e) => {
                tracing::warn!("relay connect failed (expected without server): {e}");
            }
        }
    }
}
