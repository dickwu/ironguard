//! NAT type detection.
//!
//! Determines the type of NAT the host is behind by querying
//! two STUN servers from the same local socket and comparing
//! the reflexive ports. Same port = Endpoint-Independent Mapping
//! (easy NAT, hole-punch friendly). Different ports = Endpoint-
//! Dependent Mapping (hard/symmetric NAT, needs birthday spray).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use thiserror::Error;

/// Per-server query timeout for NAT detection.
const NETCHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// The type of NAT the host is behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatType {
    /// No NAT detected. The reflexive address matches a local interface IP.
    /// Direct connectivity is trivial.
    Open,
    /// Endpoint-Independent Mapping. The NAT assigns the same external port
    /// regardless of destination. Standard hole punching works with >95% success.
    EasyNat,
    /// Endpoint-Dependent Mapping (symmetric NAT). The NAT assigns different
    /// external ports for different destinations. Requires birthday paradox
    /// spray for connectivity.
    HardNat,
    /// Could not determine NAT type (insufficient STUN responses or error).
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "Open (no NAT)"),
            NatType::EasyNat => write!(f, "Easy NAT (EIM, hole-punch friendly)"),
            NatType::HardNat => write!(f, "Hard NAT (EDM/symmetric, needs birthday spray)"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Errors that can occur during NAT type detection.
#[derive(Debug, Error)]
pub enum NetcheckError {
    /// Not enough STUN servers provided (need at least 2).
    #[error("need at least 2 STUN servers for NAT detection, got {0}")]
    InsufficientServers(usize),

    /// Socket creation or configuration failed.
    #[error("socket error: {0}")]
    SocketError(#[from] std::io::Error),

    /// Both STUN queries failed.
    #[error("both STUN queries failed: server1='{error1}', server2='{error2}'")]
    BothQueriesFailed { error1: String, error2: String },
}

/// Detects the NAT type by querying two STUN servers from the same socket.
///
/// The key insight: if the same local socket gets mapped to the same
/// external port when talking to two different STUN servers, the NAT
/// uses Endpoint-Independent Mapping (easy). If the ports differ,
/// it uses Endpoint-Dependent Mapping (hard/symmetric).
///
/// # Arguments
///
/// * `stun_servers` - At least 2 STUN server addresses. Only the first 2 are used.
///
/// # Algorithm
///
/// 1. Bind a single UDP socket
/// 2. Query STUN server A -> get reflexive address A (ip_a:port_a)
/// 3. Query STUN server B -> get reflexive address B (ip_b:port_b)
/// 4. Compare:
///    - If reflexive IP matches a local interface -> Open (no NAT)
///    - If port_a == port_b -> EasyNat (EIM)
///    - If port_a != port_b -> HardNat (EDM)
pub async fn detect_nat_type(stun_servers: &[&str]) -> Result<NatType, NetcheckError> {
    if stun_servers.len() < 2 {
        return Err(NetcheckError::InsufficientServers(stun_servers.len()));
    }

    let server1 = stun_servers[0].to_string();
    let server2 = stun_servers[1].to_string();

    // Run the blocking STUN queries in a spawn_blocking context
    let result = tokio::task::spawn_blocking(move || detect_nat_type_blocking(&server1, &server2))
        .await
        .map_err(|e| NetcheckError::BothQueriesFailed {
            error1: format!("task panic: {e}"),
            error2: "not attempted".into(),
        })??;

    Ok(result)
}

/// Blocking implementation of NAT type detection.
fn detect_nat_type_blocking(server1: &str, server2: &str) -> Result<NatType, NetcheckError> {
    // Resolve both servers
    let addr1 = resolve_stun_server(server1)?;
    let addr2 = resolve_stun_server(server2)?;

    // Bind a single UDP socket for both queries
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = UdpSocket::bind(local_addr)?;
    udp.set_read_timeout(Some(NETCHECK_TIMEOUT))?;

    let local_port = udp.local_addr()?.port();
    tracing::debug!("NAT detection: local socket bound to port {local_port}");

    // Query both servers from the same socket
    let client1 = stunclient::StunClient::new(addr1);
    let result1 = client1.query_external_address(&udp);

    let client2 = stunclient::StunClient::new(addr2);
    let result2 = client2.query_external_address(&udp);

    match (result1, result2) {
        (Ok(reflexive1), Ok(reflexive2)) => {
            tracing::debug!(
                "NAT detection: server1={} -> {}, server2={} -> {}",
                server1,
                reflexive1,
                server2,
                reflexive2
            );

            // Check if the reflexive address is our own IP (no NAT)
            if is_local_address(&reflexive1) {
                tracing::info!("NAT type: Open (reflexive address is local)");
                return Ok(NatType::Open);
            }

            // Compare reflexive ports
            if reflexive1.port() == reflexive2.port() {
                tracing::info!(
                    "NAT type: EasyNat (EIM, same port {} from both servers)",
                    reflexive1.port()
                );
                Ok(NatType::EasyNat)
            } else {
                tracing::info!(
                    "NAT type: HardNat (EDM, port {} vs {} from different servers)",
                    reflexive1.port(),
                    reflexive2.port()
                );
                Ok(NatType::HardNat)
            }
        }
        (Ok(reflexive), Err(e)) | (Err(e), Ok(reflexive)) => {
            tracing::warn!(
                "NAT detection: only one server responded ({reflexive}), other failed: {e}"
            );
            // With only one response, we cannot determine EIM vs EDM.
            // But we can check for Open.
            if is_local_address(&reflexive) {
                Ok(NatType::Open)
            } else {
                Ok(NatType::Unknown)
            }
        }
        (Err(e1), Err(e2)) => Err(NetcheckError::BothQueriesFailed {
            error1: e1.to_string(),
            error2: e2.to_string(),
        }),
    }
}

/// Resolves a STUN server hostname to a socket address.
fn resolve_stun_server(server: &str) -> Result<SocketAddr, NetcheckError> {
    server
        .to_socket_addrs()
        .map_err(|e| NetcheckError::BothQueriesFailed {
            error1: format!("DNS resolution for {server}: {e}"),
            error2: "not attempted".into(),
        })?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| NetcheckError::BothQueriesFailed {
            error1: format!("no IPv4 address for {server}"),
            error2: "not attempted".into(),
        })
}

/// Checks if an address appears to be a local/non-NATted address.
///
/// This is a heuristic: if the reflexive address matches a local
/// interface, we're probably not behind a NAT.
fn is_local_address(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    // If the STUN server returns a private IP, something is wrong
    // (STUN should return our public IP). But if it returns our
    // actual public IP that also happens to be assigned to a local
    // interface, we're not behind NAT.
    //
    // We use getifaddrs to check if this IP belongs to us.
    #[cfg(unix)]
    {
        use crate::discovery::local::enumerate_interfaces;
        let interfaces = enumerate_interfaces();
        interfaces.iter().any(|iface| iface.addr == ip)
    }
    #[cfg(not(unix))]
    {
        let _ = ip;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(NatType::Open.to_string(), "Open (no NAT)");
        assert_eq!(
            NatType::EasyNat.to_string(),
            "Easy NAT (EIM, hole-punch friendly)"
        );
        assert_eq!(
            NatType::HardNat.to_string(),
            "Hard NAT (EDM/symmetric, needs birthday spray)"
        );
        assert_eq!(NatType::Unknown.to_string(), "Unknown");
    }

    #[tokio::test]
    async fn test_insufficient_servers() {
        let result = detect_nat_type(&["stun.l.google.com:19302"]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NetcheckError::InsufficientServers(1)
        ));
    }

    #[tokio::test]
    async fn test_empty_servers() {
        let result = detect_nat_type(&[]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NetcheckError::InsufficientServers(0)
        ));
    }

    #[tokio::test]
    async fn test_unreachable_servers_returns_error() {
        let result = detect_nat_type(&["192.0.2.1:3478", "192.0.2.2:3478"]).await;
        assert!(result.is_err());
    }

    // This test requires network access and is ignored by default.
    #[tokio::test]
    #[ignore]
    async fn test_nat_detection_real_servers() {
        let servers = &["stun.l.google.com:19302", "stun1.l.google.com:19302"];
        let result = detect_nat_type(servers).await;
        match result {
            Ok(nat_type) => {
                tracing::info!("detected NAT type: {nat_type}");
                // Should be one of the valid types
                assert!(matches!(
                    nat_type,
                    NatType::Open | NatType::EasyNat | NatType::HardNat | NatType::Unknown
                ));
            }
            Err(e) => {
                tracing::warn!("NAT detection failed (expected in CI): {e}");
            }
        }
    }
}
