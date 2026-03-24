//! Connection manager for orchestrating candidate gathering.
//!
//! The `ConnectionManager` coordinates local interface discovery,
//! STUN reflexive address discovery, and NAT type detection to
//! produce a prioritized list of candidate addresses for reaching
//! a peer.

use std::net::{IpAddr, SocketAddr};

use crate::candidate::{Candidate, CandidateKind};
use crate::discovery::local::{InterfaceInfo, enumerate_interfaces};
use crate::netcheck::NatType;
use crate::stun;

/// Configuration for the connection manager.
#[derive(Clone, Debug)]
pub struct ConnectionManagerConfig {
    /// STUN servers to query for reflexive address discovery.
    /// Defaults to `stun::DEFAULT_STUN_SERVERS`.
    pub stun_servers: Vec<String>,

    /// The WireGuard listen port to use for host candidates.
    pub listen_port: u16,

    /// Whether to include IPv6 link-local candidates.
    pub include_link_local: bool,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            stun_servers: stun::DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            listen_port: 51820,
            include_link_local: true,
        }
    }
}

/// Orchestrates candidate gathering for peer connectivity.
///
/// Combines local interface discovery, STUN reflexive address discovery,
/// and link-local IPv6 to produce a prioritized list of candidates.
/// Candidates are sorted by priority (highest first) so that direct
/// LAN paths are tried before NAT-traversed or relayed paths.
pub struct ConnectionManager {
    config: ConnectionManagerConfig,
}

impl ConnectionManager {
    /// Creates a new connection manager with the given configuration.
    pub fn new(config: ConnectionManagerConfig) -> Self {
        Self { config }
    }

    /// Creates a new connection manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ConnectionManagerConfig::default())
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &ConnectionManagerConfig {
        &self.config
    }

    /// Gathers all available candidates for establishing a peer connection.
    ///
    /// The gathering process:
    /// 1. Enumerate local physical interfaces -> Host candidates
    /// 2. Collect IPv6 link-local addresses -> LinkLocal candidates
    /// 3. Query STUN servers -> ServerReflexive candidate
    ///
    /// Results are sorted by priority (highest first):
    /// Host (1000) > PortMapped (800) > ServerReflexive (500) > LinkLocal (400) > Relay (100)
    pub async fn gather_candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();

        // 1. Host candidates from physical interfaces
        let interfaces = enumerate_interfaces();
        tracing::debug!("discovered {} physical interfaces", interfaces.len());

        let host_candidates = self.gather_host_candidates(&interfaces);
        candidates.extend(host_candidates);

        // 2. IPv6 link-local candidates
        if self.config.include_link_local {
            let link_local = self.gather_link_local_candidates(&interfaces);
            candidates.extend(link_local);
        }

        // 3. STUN reflexive candidates
        match self.gather_stun_candidates().await {
            Ok(stun_candidates) => candidates.extend(stun_candidates),
            Err(e) => {
                tracing::warn!(
                    "STUN discovery failed, proceeding without reflexive candidate: {e}"
                );
            }
        }

        // Sort by priority (highest first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        tracing::info!(
            "gathered {} candidates: {} host, {} link-local, {} reflexive",
            candidates.len(),
            candidates
                .iter()
                .filter(|c| c.kind == CandidateKind::Host)
                .count(),
            candidates
                .iter()
                .filter(|c| c.kind == CandidateKind::LinkLocal)
                .count(),
            candidates
                .iter()
                .filter(|c| c.kind == CandidateKind::ServerReflexive)
                .count(),
        );

        candidates
    }

    /// Gathers host candidates from physical interfaces.
    ///
    /// Each physical interface with an IPv4 address produces a Host candidate
    /// with the configured listen port.
    fn gather_host_candidates(&self, interfaces: &[InterfaceInfo]) -> Vec<Candidate> {
        interfaces
            .iter()
            .filter(|iface| matches!(iface.addr, IpAddr::V4(_)))
            .map(|iface| {
                Candidate::new(
                    SocketAddr::new(iface.addr, self.config.listen_port),
                    CandidateKind::Host,
                    Some(iface.name.clone()),
                )
            })
            .collect()
    }

    /// Gathers IPv6 link-local candidates from physical interfaces.
    ///
    /// Only fe80:: addresses are included as LinkLocal candidates.
    /// These are useful for same-segment connectivity without any
    /// routing infrastructure.
    fn gather_link_local_candidates(&self, interfaces: &[InterfaceInfo]) -> Vec<Candidate> {
        interfaces
            .iter()
            .filter(|iface| matches!(iface.addr, IpAddr::V6(v6) if is_link_local_v6(&v6)))
            .map(|iface| {
                Candidate::new(
                    SocketAddr::new(iface.addr, self.config.listen_port),
                    CandidateKind::LinkLocal,
                    Some(iface.name.clone()),
                )
            })
            .collect()
    }

    /// Queries STUN servers to discover the reflexive (public) address.
    async fn gather_stun_candidates(&self) -> Result<Vec<Candidate>, stun::StunError> {
        let servers: Vec<&str> = self
            .config
            .stun_servers
            .iter()
            .map(|s| s.as_str())
            .collect();

        let reflexive_addr = stun::discover_reflexive(&servers).await?;

        Ok(vec![Candidate::new(
            reflexive_addr,
            CandidateKind::ServerReflexive,
            None,
        )])
    }

    /// Detects the NAT type by querying STUN servers.
    ///
    /// This is a convenience method that wraps `netcheck::detect_nat_type`.
    pub async fn detect_nat_type(&self) -> NatType {
        let servers: Vec<&str> = self
            .config
            .stun_servers
            .iter()
            .map(|s| s.as_str())
            .collect();

        if servers.len() < 2 {
            tracing::warn!("need at least 2 STUN servers for NAT detection");
            return NatType::Unknown;
        }

        match crate::netcheck::detect_nat_type(&servers).await {
            Ok(nat_type) => {
                tracing::info!("detected NAT type: {nat_type}");
                nat_type
            }
            Err(e) => {
                tracing::warn!("NAT detection failed: {e}");
                NatType::Unknown
            }
        }
    }
}

/// Checks if an IPv6 address is link-local (fe80::/10).
fn is_link_local_v6(addr: &std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_default_config() {
        let config = ConnectionManagerConfig::default();
        assert_eq!(config.listen_port, 51820);
        assert!(config.include_link_local);
        assert!(!config.stun_servers.is_empty());
    }

    #[test]
    fn test_is_link_local_v6() {
        assert!(is_link_local_v6(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_link_local_v6(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0x2345, 0x6789
        )));
        assert!(!is_link_local_v6(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_link_local_v6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_gather_host_candidates() {
        let manager = ConnectionManager::with_defaults();

        let interfaces = vec![
            InterfaceInfo {
                name: "en0".into(),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                flags: 0,
            },
            InterfaceInfo {
                name: "en1".into(),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                flags: 0,
            },
        ];

        let candidates = manager.gather_host_candidates(&interfaces);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.kind == CandidateKind::Host));
        assert!(candidates.iter().all(|c| c.priority == 1000));
        assert_eq!(
            candidates[0].addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820)
        );
    }

    #[test]
    fn test_gather_link_local_candidates() {
        let manager = ConnectionManager::with_defaults();

        let interfaces = vec![
            InterfaceInfo {
                name: "en0".into(),
                addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                netmask: None,
                flags: 0,
            },
            InterfaceInfo {
                name: "en0".into(),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                flags: 0,
            },
            InterfaceInfo {
                name: "en0".into(),
                addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                netmask: None,
                flags: 0,
            },
        ];

        let candidates = manager.gather_link_local_candidates(&interfaces);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::LinkLocal);
        assert_eq!(candidates[0].priority, 400);
    }

    #[test]
    fn test_gather_host_candidates_skips_ipv6() {
        let manager = ConnectionManager::with_defaults();

        let interfaces = vec![InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            netmask: None,
            flags: 0,
        }];

        let candidates = manager.gather_host_candidates(&interfaces);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_gather_link_local_disabled() {
        let config = ConnectionManagerConfig {
            include_link_local: false,
            ..Default::default()
        };
        let manager = ConnectionManager::new(config);

        let interfaces = vec![InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            netmask: None,
            flags: 0,
        }];

        // Link-local is disabled, so even though we have a fe80 interface,
        // gather_link_local_candidates would return results but the manager
        // won't call it when include_link_local is false.
        let candidates = manager.gather_link_local_candidates(&interfaces);
        // The method itself always returns results; the config check is in gather_candidates
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn test_custom_listen_port() {
        let config = ConnectionManagerConfig {
            listen_port: 12345,
            ..Default::default()
        };
        let manager = ConnectionManager::new(config);

        let interfaces = vec![InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            flags: 0,
        }];

        let candidates = manager.gather_host_candidates(&interfaces);
        assert_eq!(candidates[0].addr.port(), 12345);
    }

    #[tokio::test]
    async fn test_gather_candidates_includes_host() {
        // Use unreachable STUN servers so STUN fails fast
        let config = ConnectionManagerConfig {
            stun_servers: vec!["192.0.2.1:3478".into()],
            listen_port: 51820,
            include_link_local: true,
        };
        let manager = ConnectionManager::new(config);

        let candidates = manager.gather_candidates().await;

        // Should have at least host candidates from physical interfaces
        // (assuming the test runs on a machine with a NIC)
        let host_count = candidates
            .iter()
            .filter(|c| c.kind == CandidateKind::Host)
            .count();

        // On a real machine, we should have at least one host candidate.
        // The STUN candidates will fail (unreachable server), which is expected.
        if host_count > 0 {
            // Verify ordering: host candidates should come first
            assert_eq!(candidates[0].kind, CandidateKind::Host);
        }

        // Verify all candidates are sorted by priority descending
        for window in candidates.windows(2) {
            assert!(
                window[0].priority >= window[1].priority,
                "candidates should be sorted by priority descending"
            );
        }
    }
}
