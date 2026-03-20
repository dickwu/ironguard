//! QUIC-based transport for IronGuard.
//!
//! Encapsulates WireGuard packets inside QUIC datagrams (RFC 9221) for
//! traversal of restrictive networks that block raw UDP. Falls back to
//! length-prefixed QUIC streams when datagrams are unavailable.
//!
//! Gated behind `feature = "quic"`.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig,
};
use tokio::sync::RwLock;

use crate::endpoint::Endpoint;
use crate::udp;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the QUIC transport layer.
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// The QUIC connection encountered an error.
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to initiate a QUIC connection.
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// No active QUIC connection.
    #[error("not connected")]
    NotConnected,

    /// An I/O error from the underlying socket.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS configuration error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Datagram send failed.
    #[error("datagram send error: {0}")]
    SendDatagram(#[from] quinn::SendDatagramError),

    /// Certificate generation error.
    #[error("certificate generation error: {0}")]
    CertGen(#[from] rcgen::Error),

    /// Stream write error.
    #[error("stream write error: {0}")]
    WriteError(#[from] quinn::WriteError),

    /// Stream read error.
    #[error("stream read error: {0}")]
    ReadError(#[from] quinn::ReadExactError),

    /// Stream was already closed.
    #[error("stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for QUIC transport.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Address of the remote QUIC endpoint (server side).
    pub relay_addr: SocketAddr,
    /// Local port to bind (0 for OS-assigned).
    pub port: u16,
    /// TLS SNI value. Defaults to `"ironguard"` if `None`.
    pub sni: Option<String>,
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// A QUIC-backed endpoint address, analogous to a UDP `SocketAddr`.
#[derive(Clone, Debug)]
pub struct QuicEndpoint {
    addr: SocketAddr,
}

impl Endpoint for QuicEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn to_address(&self) -> SocketAddr {
        self.addr
    }

    fn clear_src(&mut self) {
        // No-op -- QUIC connections are always associated with a single peer.
    }
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts any server certificate.
///
/// IronGuard peers authenticate through WireGuard's Noise_IKpsk2 handshake,
/// so TLS certificate verification is unnecessary. The QUIC layer is used
/// purely as a transport tunnel.
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

/// Generate a self-signed certificate for QUIC transport.
///
/// The certificate is throw-away: real peer authentication happens through
/// WireGuard's Noise handshake.
pub fn generate_self_signed_cert() -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    QuicError,
> {
    let cert_params = rcgen::CertificateParams::new(vec!["ironguard".to_string()])?;
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = cert_params.self_signed(&key_pair)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    Ok((vec![cert_der], key_der))
}

// ---------------------------------------------------------------------------
// QuicTransport
// ---------------------------------------------------------------------------

/// Shared QUIC transport state.
///
/// Wraps a `quinn::Endpoint` and an active `Connection`. Both reader and
/// writer hold an `Arc` reference to this struct.
pub struct QuicTransport {
    endpoint: QuinnEndpoint,
    connection: RwLock<Option<Connection>>,
    config: QuicConfig,
}

impl QuicTransport {
    /// Connect as a QUIC client to `config.relay_addr`.
    pub async fn connect(config: QuicConfig) -> Result<Arc<Self>, QuicError> {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| QuicError::Tls(format!("failed to build QUIC client config: {e}")))?;

        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse().unwrap();
        let mut endpoint = QuinnEndpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        let sni = config.sni.as_deref().unwrap_or("ironguard");
        let connection = endpoint.connect(config.relay_addr, sni)?.await?;

        tracing::info!(
            remote = %connection.remote_address(),
            "QUIC connection established"
        );

        Ok(Arc::new(Self {
            endpoint,
            connection: RwLock::new(Some(connection)),
            config,
        }))
    }

    /// Start a QUIC server listening for incoming connections.
    pub async fn listen(config: QuicConfig) -> Result<Arc<Self>, QuicError> {
        let (certs, key) = generate_self_signed_cert()?;

        let server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| QuicError::Tls(format!("failed to build server TLS config: {e}")))?,
        )
        .map_err(|e| QuicError::Tls(format!("failed to build QUIC server config: {e}")))?;

        let server_config = QuinnServerConfig::with_crypto(Arc::new(server_tls));

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse().unwrap();
        let endpoint = QuinnEndpoint::server(server_config, bind_addr)?;

        let actual_port = endpoint.local_addr()?.port();
        tracing::info!(port = actual_port, "QUIC server listening");

        // Accept the first incoming connection.
        let incoming = endpoint.accept().await.ok_or_else(|| {
            QuicError::Io(std::io::Error::other("endpoint closed before accepting"))
        })?;
        let connection = incoming.await?;

        tracing::info!(
            remote = %connection.remote_address(),
            "QUIC server accepted connection"
        );

        Ok(Arc::new(Self {
            endpoint,
            connection: RwLock::new(Some(connection)),
            config: QuicConfig {
                port: actual_port,
                ..config
            },
        }))
    }

    /// Return the local address the QUIC endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Return a reference to the relay address from the config.
    pub fn relay_addr(&self) -> SocketAddr {
        self.config.relay_addr
    }

    /// Attempt to re-establish the QUIC connection if it has been lost.
    pub async fn reconnect(&self) -> Result<(), QuicError> {
        let sni = self.config.sni.as_deref().unwrap_or("ironguard");
        let new_conn = self.endpoint.connect(self.config.relay_addr, sni)?.await?;
        let mut guard = self.connection.write().await;
        *guard = Some(new_conn);
        tracing::info!("QUIC reconnected");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader / Writer
// ---------------------------------------------------------------------------

/// Reads WireGuard packets from a QUIC connection (datagrams or streams).
pub struct QuicReader {
    transport: Arc<QuicTransport>,
}

impl QuicReader {
    /// Create a new reader for the given transport.
    pub fn new(transport: Arc<QuicTransport>) -> Self {
        Self { transport }
    }
}

/// Writes WireGuard packets to a QUIC connection (datagrams or streams).
pub struct QuicWriter {
    transport: Arc<QuicTransport>,
}

impl QuicWriter {
    /// Create a new writer for the given transport.
    pub fn new(transport: Arc<QuicTransport>) -> Self {
        Self { transport }
    }
}

impl udp::UdpReader<QuicEndpoint> for QuicReader {
    type Error = QuicError;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, QuicEndpoint), Self::Error> {
        let guard = self.transport.connection.read().await;
        let conn = guard.as_ref().ok_or(QuicError::NotConnected)?;

        // Try datagram first (RFC 9221).
        match conn.read_datagram().await {
            Ok(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                let ep = QuicEndpoint::from_address(conn.remote_address());
                Ok((len, ep))
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => Err(QuicError::NotConnected),
            Err(e) => {
                // Fallback: try to accept a bidirectional stream and read a
                // length-prefixed frame.
                tracing::warn!("datagram read failed ({e}), trying stream fallback");
                drop(guard);
                self.read_from_stream(buf).await
            }
        }
    }
}

impl QuicReader {
    /// Read a single length-prefixed WireGuard packet from a QUIC stream.
    async fn read_from_stream(&self, buf: &mut [u8]) -> Result<(usize, QuicEndpoint), QuicError> {
        let guard = self.transport.connection.read().await;
        let conn = guard.as_ref().ok_or(QuicError::NotConnected)?;

        let (_send, mut recv) = conn.accept_bi().await?;

        // Read 4-byte LE length prefix.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;
        let read_len = payload_len.min(buf.len());

        recv.read_exact(&mut buf[..read_len]).await?;

        // Discard any remaining bytes if the payload was larger than buf.
        if payload_len > buf.len() {
            let mut discard = vec![0u8; payload_len - buf.len()];
            recv.read_exact(&mut discard).await?;
        }

        let ep = QuicEndpoint::from_address(conn.remote_address());
        Ok((read_len, ep))
    }
}

impl udp::UdpWriter<QuicEndpoint> for QuicWriter {
    type Error = QuicError;

    async fn write(&self, buf: &[u8], _dst: &mut QuicEndpoint) -> Result<(), Self::Error> {
        let guard = self.transport.connection.read().await;
        let conn = guard.as_ref().ok_or(QuicError::NotConnected)?;

        // Try datagram first.
        match conn.send_datagram(Bytes::copy_from_slice(buf)) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::Disabled)
            | Err(quinn::SendDatagramError::UnsupportedByPeer) => {
                tracing::warn!("QUIC datagrams unavailable, falling back to streams");
                drop(guard);
                self.write_to_stream(buf).await
            }
            Err(quinn::SendDatagramError::TooLarge) => {
                tracing::warn!("datagram too large, falling back to streams");
                drop(guard);
                self.write_to_stream(buf).await
            }
            Err(e) => Err(QuicError::SendDatagram(e)),
        }
    }
}

impl QuicWriter {
    /// Write a single length-prefixed WireGuard packet to a QUIC stream.
    async fn write_to_stream(&self, buf: &[u8]) -> Result<(), QuicError> {
        let guard = self.transport.connection.read().await;
        let conn = guard.as_ref().ok_or(QuicError::NotConnected)?;

        let (mut send, _recv) = conn.open_bi().await?;

        let len_bytes = (buf.len() as u32).to_le_bytes();
        send.write_all(&len_bytes).await?;
        send.write_all(buf).await?;
        send.finish()?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trait impls for Udp / Owner
// ---------------------------------------------------------------------------

/// Marker type for the QUIC-based UDP abstraction.
pub struct QuicUdp;

impl udp::Udp for QuicUdp {
    type Error = QuicError;
    type Endpoint = QuicEndpoint;
    type Writer = QuicWriter;
    type Reader = QuicReader;
}

/// Ownership handle for a QUIC transport, providing the bound port.
pub struct QuicOwner {
    port: u16,
}

impl QuicOwner {
    /// Create a new owner with the given port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// The local port the QUIC endpoint is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl udp::Owner for QuicOwner {
    type Error = QuicError;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), Self::Error> {
        // fwmark is a Linux concept; no-op for QUIC transport.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::{UdpReader, UdpWriter};

    /// Loopback test: server + client exchange packets via QUIC datagrams.
    #[tokio::test]
    async fn test_quic_loopback() {
        let _ = tracing_subscriber::fmt::try_init();

        // 1. Start server on an OS-assigned port.
        let server_config = QuicConfig {
            relay_addr: "127.0.0.1:0".parse().unwrap(),
            port: 0,
            sni: None,
        };

        // The server blocks on accept(), so we need the client to connect to
        // the actual server port. We spawn the server and discover its port
        // via a channel.
        let (port_tx, port_rx) = tokio::sync::oneshot::channel::<u16>();

        let server_handle = tokio::spawn(async move {
            // Create server endpoint manually to discover port before blocking.
            let (certs, key) = generate_self_signed_cert().unwrap();
            let server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            )
            .unwrap();
            let sc = QuinnServerConfig::with_crypto(Arc::new(server_tls));
            let endpoint = QuinnEndpoint::server(sc, "127.0.0.1:0".parse().unwrap()).unwrap();
            let actual_port = endpoint.local_addr().unwrap().port();
            port_tx.send(actual_port).unwrap();

            // Accept connection.
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();

            let transport = Arc::new(QuicTransport {
                endpoint,
                connection: RwLock::new(Some(connection)),
                config: QuicConfig {
                    relay_addr: "127.0.0.1:0".parse().unwrap(),
                    port: actual_port,
                    sni: None,
                },
            });

            transport
        });

        let server_port = port_rx.await.unwrap();

        // 2. Connect client.
        let client_config = QuicConfig {
            relay_addr: format!("127.0.0.1:{server_port}").parse().unwrap(),
            port: 0,
            sni: None,
        };
        let client_transport = QuicTransport::connect(client_config).await.unwrap();

        // Wait for server transport to be ready.
        let server_transport = server_handle.await.unwrap();

        let client_writer = QuicWriter::new(Arc::clone(&client_transport));
        let server_reader = QuicReader::new(Arc::clone(&server_transport));
        let server_writer = QuicWriter::new(Arc::clone(&server_transport));
        let client_reader = QuicReader::new(Arc::clone(&client_transport));

        // 3. Send 100 packets client -> server.
        let send_handle = tokio::spawn(async move {
            for i in 0u32..100 {
                let payload = format!("client-to-server-{i}");
                let mut ep = QuicEndpoint::from_address("127.0.0.1:1".parse().unwrap());
                client_writer
                    .write(payload.as_bytes(), &mut ep)
                    .await
                    .unwrap();
            }
        });

        let recv_handle = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..100 {
                let mut buf = [0u8; 1500];
                let (len, _ep) = server_reader.read(&mut buf).await.unwrap();
                received.push(String::from_utf8_lossy(&buf[..len]).to_string());
            }
            received
        });

        send_handle.await.unwrap();
        let received = recv_handle.await.unwrap();
        assert_eq!(received.len(), 100);
        for (i, msg) in received.iter().enumerate() {
            assert_eq!(msg, &format!("client-to-server-{i}"));
        }

        // 4. Send 100 packets server -> client.
        let send_handle2 = tokio::spawn(async move {
            for i in 0u32..100 {
                let payload = format!("server-to-client-{i}");
                let mut ep = QuicEndpoint::from_address("127.0.0.1:1".parse().unwrap());
                server_writer
                    .write(payload.as_bytes(), &mut ep)
                    .await
                    .unwrap();
            }
        });

        let recv_handle2 = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..100 {
                let mut buf = [0u8; 1500];
                let (len, _ep) = client_reader.read(&mut buf).await.unwrap();
                received.push(String::from_utf8_lossy(&buf[..len]).to_string());
            }
            received
        });

        send_handle2.await.unwrap();
        let received2 = recv_handle2.await.unwrap();
        assert_eq!(received2.len(), 100);
        for (i, msg) in received2.iter().enumerate() {
            assert_eq!(msg, &format!("server-to-client-{i}"));
        }
    }

    /// Test stream fallback by disabling datagrams.
    #[tokio::test]
    async fn test_quic_stream_fallback() {
        let _ = tracing_subscriber::fmt::try_init();

        // Create server with datagrams disabled.
        let (certs, key) = generate_self_signed_cert().unwrap();
        let server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
        .unwrap();

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.datagram_receive_buffer_size(None);
        let mut sc = QuinnServerConfig::with_crypto(Arc::new(server_tls));
        sc.transport = Arc::new(transport_config);

        let endpoint = QuinnEndpoint::server(sc, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_port = endpoint.local_addr().unwrap().port();

        let (port_tx, port_rx) = tokio::sync::oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            port_tx.send(()).unwrap();
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();

            // Read packets via stream fallback.
            let mut received = Vec::new();
            for _ in 0..5 {
                let (_send, mut recv) = connection.accept_bi().await.unwrap();
                let mut len_buf = [0u8; 4];
                recv.read_exact(&mut len_buf).await.unwrap();
                let payload_len = u32::from_le_bytes(len_buf) as usize;
                let mut payload = vec![0u8; payload_len];
                recv.read_exact(&mut payload).await.unwrap();
                received.push(String::from_utf8(payload).unwrap());
            }
            received
        });

        port_rx.await.unwrap();

        // Connect client (datagrams will be disabled by server's transport config).
        let client_config = QuicConfig {
            relay_addr: format!("127.0.0.1:{server_port}").parse().unwrap(),
            port: 0,
            sni: None,
        };
        let client_transport = QuicTransport::connect(client_config).await.unwrap();
        let client_writer = QuicWriter::new(Arc::clone(&client_transport));

        // The server has datagram_receive_buffer_size = None, so send_datagram
        // should fail with Disabled, triggering stream fallback.
        for i in 0..5 {
            let payload = format!("stream-msg-{i}");
            let mut ep = QuicEndpoint::from_address("127.0.0.1:1".parse().unwrap());
            client_writer
                .write(payload.as_bytes(), &mut ep)
                .await
                .unwrap();
        }

        let received = server_handle.await.unwrap();
        assert_eq!(received.len(), 5);
        for (i, msg) in received.iter().enumerate() {
            assert_eq!(msg, &format!("stream-msg-{i}"));
        }
    }
}
