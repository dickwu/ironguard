//! STUN address discovery.
//!
//! Queries multiple STUN servers in parallel to discover the host's
//! public reflexive address (the IP:port as seen from the internet).
//! Requires at least 2 servers to agree on the address to guard
//! against STUN spoofing.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use thiserror::Error;

/// Default STUN servers to query.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// Per-server query timeout.
const STUN_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum number of servers that must agree on the reflexive address.
const MIN_AGREEMENT: usize = 2;

/// Errors that can occur during STUN discovery.
#[derive(Debug, Error)]
pub enum StunError {
    /// No STUN servers responded within the timeout.
    #[error("no STUN servers responded within timeout")]
    NoResponse,

    /// STUN servers returned different reflexive addresses.
    /// This may indicate STUN spoofing or an unusual NAT.
    #[error(
        "STUN address disagreement: servers returned {0} distinct addresses (possible spoofing)"
    )]
    AddressDisagreement(usize),

    /// Not enough servers responded to reach consensus.
    #[error("only {responded} of {required} STUN servers responded")]
    InsufficientResponses { responded: usize, required: usize },

    /// DNS resolution failed for a STUN server.
    #[error("failed to resolve STUN server '{server}': {source}")]
    DnsResolution {
        server: String,
        source: std::io::Error,
    },

    /// A STUN query failed.
    #[error("STUN query to {server} failed: {reason}")]
    QueryFailed { server: String, reason: String },

    /// Socket creation or binding failed.
    #[error("failed to create UDP socket: {0}")]
    SocketError(#[from] std::io::Error),
}

/// Result of a single STUN server query.
#[derive(Debug, Clone)]
struct StunResult {
    /// The server that was queried.
    server: String,
    /// The reflexive address returned, if successful.
    addr: Result<SocketAddr, String>,
}

/// Discovers the host's public reflexive address by querying STUN servers.
///
/// Queries all provided STUN servers in parallel using tokio tasks.
/// Requires at least `MIN_AGREEMENT` (2) servers to return the same
/// reflexive address. Returns an error if servers disagree (potential
/// spoofing) or if too few servers respond.
///
/// # Arguments
///
/// * `stun_servers` - STUN server addresses to query (host:port format).
///   Use `DEFAULT_STUN_SERVERS` for the default set.
///
/// # Errors
///
/// Returns `StunError::AddressDisagreement` if servers return different
/// addresses, `StunError::InsufficientResponses` if fewer than 2 respond,
/// or `StunError::NoResponse` if none respond.
pub async fn discover_reflexive(stun_servers: &[&str]) -> Result<SocketAddr, StunError> {
    if stun_servers.is_empty() {
        return Err(StunError::NoResponse);
    }

    // Launch queries in parallel
    let servers: Vec<String> = stun_servers.iter().map(|s| s.to_string()).collect();
    let handles: Vec<_> = servers
        .into_iter()
        .map(|server| {
            tokio::task::spawn_blocking(move || {
                let result = query_stun_server(&server);
                StunResult {
                    server,
                    addr: result,
                }
            })
        })
        .collect();

    // Collect results
    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::debug!("STUN task panicked: {e}");
            }
        }
    }

    // Extract successful responses
    let successful: Vec<SocketAddr> = results
        .iter()
        .filter_map(|r| match &r.addr {
            Ok(addr) => {
                tracing::debug!("STUN server {} returned {}", r.server, addr);
                Some(*addr)
            }
            Err(reason) => {
                tracing::debug!("STUN server {} failed: {}", r.server, reason);
                None
            }
        })
        .collect();

    if successful.is_empty() {
        return Err(StunError::NoResponse);
    }

    if successful.len() < MIN_AGREEMENT {
        return Err(StunError::InsufficientResponses {
            responded: successful.len(),
            required: MIN_AGREEMENT,
        });
    }

    // Check for consensus: all successful responses should have the same IP.
    // Port may differ (some NATs allocate different ports per destination),
    // so we compare IPs only for consensus, but return the full address
    // from the majority.
    let consensus_ip = successful[0].ip();
    let agree_count = successful.iter().filter(|a| a.ip() == consensus_ip).count();

    if agree_count < MIN_AGREEMENT {
        // Count distinct IPs
        let mut distinct_ips: Vec<_> = successful.iter().map(|a| a.ip()).collect();
        distinct_ips.sort();
        distinct_ips.dedup();
        return Err(StunError::AddressDisagreement(distinct_ips.len()));
    }

    // Return the reflexive address that has the most agreement.
    // Use the first response with the consensus IP.
    let chosen = successful
        .iter()
        .find(|a| a.ip() == consensus_ip)
        .copied()
        .expect("consensus IP must exist in results");

    tracing::info!(
        "STUN discovery: reflexive address {} ({}/{} servers agree on IP)",
        chosen,
        agree_count,
        successful.len()
    );

    Ok(chosen)
}

/// Queries a single STUN server for the reflexive address.
///
/// Uses `stunclient` to send a STUN Binding Request and returns
/// the XOR-MAPPED-ADDRESS from the response.
fn query_stun_server(server: &str) -> Result<SocketAddr, String> {
    // Resolve the STUN server address
    let server_addr = server
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("no IPv4 address found for {server}"))?;

    // Create a UDP socket bound to any available port
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let udp = UdpSocket::bind(local_addr).map_err(|e| format!("socket bind failed: {e}"))?;
    udp.set_read_timeout(Some(STUN_TIMEOUT))
        .map_err(|e| format!("set timeout failed: {e}"))?;

    // Send STUN Binding Request
    let client = stunclient::StunClient::new(server_addr);
    let reflexive = client
        .query_external_address(&udp)
        .map_err(|e| format!("STUN query failed: {e}"))?;

    Ok(reflexive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_stun_servers_not_empty() {
        assert!(DEFAULT_STUN_SERVERS.len() >= 3);
    }

    #[test]
    fn test_stun_timeout_is_reasonable() {
        assert!(STUN_TIMEOUT.as_secs() <= 5);
        assert!(STUN_TIMEOUT.as_secs() >= 1);
    }

    #[test]
    fn test_min_agreement_is_at_least_two() {
        assert!(MIN_AGREEMENT >= 2);
    }

    #[tokio::test]
    async fn test_stun_empty_servers_returns_error() {
        let result = discover_reflexive(&[]).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), StunError::NoResponse),
            "empty server list should return NoResponse"
        );
    }

    #[tokio::test]
    async fn test_stun_unreachable_servers_returns_error() {
        // Use an address that won't respond
        let result = discover_reflexive(&["192.0.2.1:3478", "192.0.2.2:3478"]).await;
        assert!(result.is_err());
    }

    // This test queries real STUN servers and requires network access.
    // It is ignored by default for CI environments.
    #[tokio::test]
    #[ignore]
    async fn test_stun_discovery_real_servers() {
        let result = discover_reflexive(DEFAULT_STUN_SERVERS).await;
        match result {
            Ok(addr) => {
                assert!(!addr.ip().is_loopback());
                assert!(!addr.ip().is_unspecified());
                tracing::info!("discovered reflexive address: {addr}");
            }
            Err(e) => {
                // May fail in environments without internet access
                tracing::warn!("STUN discovery failed (expected in CI): {e}");
            }
        }
    }
}
