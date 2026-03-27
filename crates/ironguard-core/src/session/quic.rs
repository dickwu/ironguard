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

use base64::Engine;
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
    /// Optional SNI hostname for outbound connections.
    pub sni: Option<String>,
    /// This node's TLS certificate chain (DER-encoded). Used for mTLS.
    pub our_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// This node's TLS private key (DER-encoded). Used for mTLS.
    pub our_key: Option<rustls::pki_types::PrivateKeyDer<'static>>,
}

impl Default for QuicSessionConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            alpn: b"ironguard/1".to_vec(),
            cert_path: None,
            key_path: None,
            sni: None,
            our_certs: Vec::new(),
            our_key: None,
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
// Production TLS configs — mTLS with cert pinning
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts only a specific pinned server certificate.
///
/// Compares the presented end-entity certificate (DER bytes) against an
/// expected certificate. All other certificates are rejected. Signature
/// verification is delegated to the standard `WebPkiServerVerifier` schemes.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_cert_der: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_cert_der.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match pinned peer certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `quinn::ServerConfig` with mTLS — requires clients to present a
/// certificate. The server verifies client certs against a provided set of
/// trusted peer certificates.
///
/// `our_certs` and `our_key` are this node's TLS identity.
/// `trusted_client_certs` are the DER-encoded certificates of peers allowed
/// to connect.
pub fn make_server_config_mtls(
    our_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    our_key: rustls::pki_types::PrivateKeyDer<'static>,
    trusted_client_certs: &[rustls::pki_types::CertificateDer<'static>],
    alpn: &[u8],
) -> Result<quinn::ServerConfig, SessionError> {
    // Build a root cert store from the trusted client certificates.
    let mut root_store = rustls::RootCertStore::empty();
    for cert in trusted_client_certs {
        root_store
            .add(cert.clone())
            .map_err(|e| SessionError::QuicDatagram(format!("add trusted cert: {e}")))?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| SessionError::QuicDatagram(format!("client verifier: {e}")))?;

    let mut server_tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(our_certs, our_key)
        .map_err(|e| SessionError::QuicDatagram(format!("server TLS config: {e}")))?;

    server_tls.alpn_protocols = vec![alpn.to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
        .map_err(|e| SessionError::QuicDatagram(format!("QUIC server config: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quic_server_config,
    )))
}

/// Build a `quinn::ClientConfig` that pins a specific server certificate
/// and presents our own certificate for mTLS.
///
/// `peer_cert_der` is the expected server certificate (DER bytes).
/// `our_certs` and `our_key` are this client's TLS identity.
pub fn make_client_config_pinned(
    peer_cert_der: &[u8],
    our_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    our_key: rustls::pki_types::PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Result<quinn::ClientConfig, SessionError> {
    let verifier = PinnedCertVerifier {
        expected_cert_der: peer_cert_der.to_vec(),
    };

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(our_certs, our_key)
        .map_err(|e| SessionError::QuicDatagram(format!("client TLS config: {e}")))?;

    tls_config.alpn_protocols = vec![alpn.to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| SessionError::QuicDatagram(format!("QUIC client config: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_client_config)))
}

/// Generate a self-signed X.509 cert with the WireGuard public key in CN.
///
/// Sets `is_ca=true` for `WebPkiClientVerifier` trust anchor compatibility.
/// The CN is the base64-encoded 32-byte WireGuard public key.
pub fn generate_wg_cert(
    wg_pubkey: &[u8; 32],
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    SessionError,
> {
    let cn = base64::engine::general_purpose::STANDARD.encode(wg_pubkey);
    let mut params = rcgen::CertificateParams::new(vec!["ironguard".to_string()])
        .map_err(|e| SessionError::QuicDatagram(format!("cert params: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| SessionError::QuicDatagram(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| SessionError::QuicDatagram(format!("self-sign: {e}")))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| SessionError::QuicDatagram(format!("key DER: {e}")))?;

    Ok((cert_der, key_der))
}

/// Extract WireGuard public key from a certificate's CN field.
///
/// Parses the X.509 certificate and looks for a base64-encoded 32-byte
/// value in the Common Name. Returns `None` if parsing fails or the
/// decoded value is not exactly 32 bytes.
pub fn extract_wg_pubkey_from_cert(
    cert_der: &rustls::pki_types::CertificateDer,
) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let cn = cert.subject().iter_common_name().next()?;
    let cn_str = cn.as_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cn_str)
        .ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&decoded);
    Some(pk)
}

/// Extract peer identity from a QUIC connection's client certificate.
///
/// Returns the WireGuard public key embedded in the peer's TLS certificate
/// CN, or `None` if no certificate was presented or parsing fails.
pub fn extract_peer_identity(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    extract_wg_pubkey_from_cert(cert)
}

/// Extract the peer's TLS certificate from a QUIC connection (after handshake).
///
/// Returns the DER-encoded end-entity certificate, or an error if no peer
/// certificate was presented (e.g., the peer did not do client auth).
pub fn extract_peer_cert(connection: &quinn::Connection) -> Result<Vec<u8>, SessionError> {
    let peer_certs = connection
        .peer_identity()
        .and_then(|id| {
            id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .ok_or_else(|| {
            SessionError::QuicDatagram("peer did not present a TLS certificate".into())
        })?;

    peer_certs
        .first()
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| SessionError::QuicDatagram("peer certificate chain is empty".into()))
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

    #[test]
    fn generate_wg_cert_roundtrip() {
        let wg_pk = [42u8; 32];
        let (cert_der, _key_der) = generate_wg_cert(&wg_pk).unwrap();
        let extracted = extract_wg_pubkey_from_cert(&cert_der).unwrap();
        assert_eq!(extracted, wg_pk);
    }

    #[test]
    fn generate_wg_cert_has_ca_flag() {
        let wg_pk = [1u8; 32];
        let (cert_der, _) = generate_wg_cert(&wg_pk).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca);
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
