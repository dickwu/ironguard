use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub interfaces: HashMap<String, InterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<QuicConfig>,
    #[serde(default)]
    pub post_quantum: PostQuantumMode,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// ALPN protocol identifier for the QUIC handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Path to a TLS certificate (PEM) for the QUIC endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    /// Path to the TLS private key (PEM) for the QUIC endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// QUIC session mode: how the QUIC connection is used.
    #[serde(default)]
    pub mode: QuicMode,
    /// If true, use QUIC datagrams only (no streams).
    #[serde(default)]
    pub datagram_only: bool,
}

/// Controls how the QUIC session is used relative to the data plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicMode {
    /// QUIC is used only for the handshake / key exchange; the data plane
    /// uses raw UDP.
    #[default]
    HandshakeOnly,
    /// QUIC carries both the handshake and all data-plane traffic.
    FullTransport,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PostQuantumMode {
    #[default]
    False,
    True,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_comment")]
    pub comment: Option<String>,
    /// ML-KEM-768 encapsulation (public) key, hex-encoded.
    /// Used for post-quantum key exchange when `post_quantum` is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// Override the QUIC session port for this peer.
    /// Defaults to endpoint port + 1 when not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_port: Option<u16>,
}

fn default_transport() -> String {
    "udp".to_string()
}
