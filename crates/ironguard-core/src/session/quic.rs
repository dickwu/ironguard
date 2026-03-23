//! QUIC-based session setup for IronGuard.
//!
//! Provides message types and helpers for performing a data-plane key exchange
//! over a QUIC connection.  After the QUIC TLS handshake completes, both sides
//! exchange `DataPlaneInit` / `DataPlaneAck` messages as QUIC datagrams, then
//! derive symmetric data-plane keys from the TLS exporter secret using
//! [`super::keys::derive_initial_keys`].
//!
//! Gated behind `feature = "quic"`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::keys::{DataPlaneKeys, Role, derive_initial_keys};
use super::state::SessionError;

// ---------------------------------------------------------------------------
// Protocol messages
// ---------------------------------------------------------------------------

/// Sent by each side after the QUIC handshake to advertise its data-plane
/// parameters.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneInit {
    pub version: u8,
    pub data_port: u16,
    pub session_id: [u8; 4],
    pub receiver_id: u32,
}

/// Acknowledgement echoing the peer's data-plane parameters back.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneAck {
    pub version: u8,
    pub data_port: u16,
    pub session_id: [u8; 4],
    pub receiver_id: u32,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a QUIC-based session endpoint.
pub struct QuicSessionConfig {
    pub bind_addr: SocketAddr,
    /// ALPN protocol identifier.
    pub alpn: Vec<u8>,
    /// Optional path to a TLS certificate (PEM).
    pub cert_path: Option<PathBuf>,
    /// Optional path to the TLS private key (PEM).
    pub key_path: Option<PathBuf>,
}

impl Default for QuicSessionConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            alpn: b"ironguard/1".to_vec(),
            cert_path: None,
            key_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS helpers for testing
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts any server certificate.
///
/// Used only in tests and when no explicit certificate path is configured.
/// Real peer authentication happens at the WireGuard / session layer.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
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
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Generate a self-signed certificate and private key for testing.
fn generate_self_signed_cert() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert_params =
        rcgen::CertificateParams::new(vec!["ironguard".to_string()]).expect("cert params");
    let key_pair = rcgen::KeyPair::generate().expect("key pair");
    let cert = cert_params.self_signed(&key_pair).expect("self-signed");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    (vec![cert_der], key_der)
}

/// Build a `quinn::ServerConfig` with a self-signed certificate for testing.
pub fn make_test_server_config() -> quinn::ServerConfig {
    let (certs, key) = generate_self_signed_cert();

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server TLS config");

    // Enable the keying-material exporter so we can derive data-plane keys.
    server_tls.alpn_protocols = vec![b"ironguard/1".to_vec()];

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).expect("QUIC server config");
    quinn::ServerConfig::with_crypto(Arc::new(quic_server_config))
}

/// Build a `quinn::ClientConfig` that trusts any server certificate (for testing).
pub fn make_test_client_config() -> quinn::ClientConfig {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"ironguard/1".to_vec()];

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(quic_client_config))
}

// ---------------------------------------------------------------------------
// TLS exporter label
// ---------------------------------------------------------------------------

/// Label used with the TLS keying-material exporter (RFC 5705 / RFC 8446 s7.5).
const EXPORTER_LABEL: &str = "EXPORTER-ironguard-data-plane";

/// Length of the exported secret in bytes.
const EXPORTER_SECRET_LEN: usize = 64;

/// Extract the TLS exporter secret from a QUIC connection.
///
/// Returns an error if the connection does not support the exporter or the
/// export fails.
fn export_keying_material(
    connection: &quinn::Connection,
) -> Result<[u8; EXPORTER_SECRET_LEN], SessionError> {
    let mut secret = [0u8; EXPORTER_SECRET_LEN];
    connection
        .export_keying_material(&mut secret, EXPORTER_LABEL.as_bytes(), &[])
        .map_err(|_| SessionError::InvalidState)?;
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

/// Exchange data-plane parameters over a QUIC connection and derive keys.
///
/// After the QUIC TLS handshake completes:
/// 1. Sends our `DataPlaneInit` as a QUIC datagram.
/// 2. Waits for the peer's `DataPlaneInit` (treated as an implicit ack).
/// 3. Derives symmetric data-plane keys from the TLS exporter secret.
///
/// Returns the derived keys and the peer's `DataPlaneInit`.
pub async fn exchange_data_plane_keys(
    connection: &quinn::Connection,
    role: Role,
    data_port: u16,
    receiver_id: u32,
) -> Result<(DataPlaneKeys, DataPlaneInit), SessionError> {
    let session_id = rand::random::<[u8; 4]>();

    let our_init = DataPlaneInit {
        version: 1,
        data_port,
        session_id,
        receiver_id,
    };

    let our_init_bytes = serde_json::to_vec(&our_init).map_err(|_| SessionError::InvalidState)?;

    connection
        .send_datagram(our_init_bytes.into())
        .map_err(|e| SessionError::QuicDatagram(format!("send init: {e}")))?;

    // Wait for the peer's DataPlaneInit datagram.
    let peer_bytes = connection
        .read_datagram()
        .await
        .map_err(|e| SessionError::QuicDatagram(format!("read init: {e}")))?;

    let peer_init: DataPlaneInit =
        serde_json::from_slice(&peer_bytes).map_err(|_| SessionError::InvalidState)?;

    // Send an ack back so the peer knows we received their init.
    let ack = DataPlaneAck {
        version: peer_init.version,
        data_port: peer_init.data_port,
        session_id: peer_init.session_id,
        receiver_id: peer_init.receiver_id,
    };
    let ack_bytes = serde_json::to_vec(&ack).map_err(|_| SessionError::InvalidState)?;
    connection
        .send_datagram(ack_bytes.into())
        .map_err(|e| SessionError::QuicDatagram(format!("send ack: {e}")))?;

    // Derive data-plane keys from the TLS exporter.
    let exporter_secret = export_keying_material(connection)?;
    let keys = derive_initial_keys(&exporter_secret, role);

    Ok((keys, peer_init))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_plane_init_roundtrip() {
        let init = DataPlaneInit {
            version: 1,
            data_port: 51820,
            session_id: [1, 2, 3, 4],
            receiver_id: 42,
        };
        let bytes = serde_json::to_vec(&init).unwrap();
        let parsed: DataPlaneInit = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, init);
        assert_eq!(parsed.receiver_id, 42);
        assert_eq!(parsed.data_port, 51820);
    }

    #[test]
    fn test_data_plane_ack_roundtrip() {
        let ack = DataPlaneAck {
            version: 1,
            data_port: 12345,
            session_id: [10, 20, 30, 40],
            receiver_id: 99,
        };
        let bytes = serde_json::to_vec(&ack).unwrap();
        let parsed: DataPlaneAck = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, ack);
    }

    #[test]
    fn test_quic_session_config_default() {
        let config = QuicSessionConfig::default();
        assert_eq!(config.alpn, b"ironguard/1".to_vec());
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quic_session_handshake_and_key_exchange() {
        // Create server endpoint on loopback.
        let server_config = make_test_server_config();
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("server endpoint");
        let server_port = server_endpoint.local_addr().unwrap().port();

        // Use a barrier to keep the server connection alive until the client
        // has finished its key exchange. Without this, the server task can
        // complete and drop the connection before the client reads the
        // server's datagram.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let server_barrier = barrier.clone();

        // Spawn server task: accept connection, exchange keys as Server role.
        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept");
            let connection = incoming.await.expect("incoming connection");

            let result = exchange_data_plane_keys(&connection, Role::Server, 51821, 200)
                .await
                .expect("server key exchange");

            // Wait for the client to finish before dropping the connection.
            server_barrier.wait().await;
            result
        });

        // Create client endpoint and connect to the server.
        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        client_endpoint.set_default_client_config(make_test_client_config());

        let client_connection = client_endpoint
            .connect(
                format!("127.0.0.1:{server_port}").parse().unwrap(),
                "ironguard",
            )
            .expect("connect")
            .await
            .expect("client connection");

        // Client exchanges keys.
        let (client_keys, peer_init_from_server) =
            exchange_data_plane_keys(&client_connection, Role::Client, 51820, 100)
                .await
                .expect("client key exchange");

        // Signal the server it can drop the connection now.
        barrier.wait().await;

        // Wait for server.
        let (server_keys, peer_init_from_client) = server_handle.await.expect("server join");

        // Verify key symmetry: client.send_key == server.recv_key.
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

        // Verify both sides received the peer's init.
        // client received server's init (port 51821, receiver_id 200)
        assert_eq!(peer_init_from_server.data_port, 51821);
        assert_eq!(peer_init_from_server.receiver_id, 200);
        // server received client's init (port 51820, receiver_id 100)
        assert_eq!(peer_init_from_client.data_port, 51820);
        assert_eq!(peer_init_from_client.receiver_id, 100);
    }
}
