//! Candidate addresses for peer connectivity.
//!
//! Each candidate represents a potential network path to a peer,
//! with a priority that determines probe ordering. Higher priority
//! candidates are tried first.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// A candidate address that may be used to reach a peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The socket address (IP + port) for this candidate.
    pub addr: SocketAddr,
    /// What kind of candidate this is (host, STUN-reflexive, etc.).
    pub kind: CandidateKind,
    /// Priority for probe ordering. Higher values are tried first.
    pub priority: u32,
    /// The network interface this candidate was discovered on, if applicable.
    pub interface: Option<String>,
}

/// The type of a candidate address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateKind {
    /// Local interface IP address (highest priority for direct LAN).
    Host,
    /// IPv6 link-local address (fe80::, same-segment only).
    LinkLocal,
    /// STUN-discovered reflexive address (public IP:port as seen by STUN server).
    ServerReflexive,
    /// UPnP/NAT-PMP mapped port (explicit port forwarding).
    PortMapped,
    /// Relay server address (guaranteed fallback, highest latency).
    Relay,
}

impl CandidateKind {
    /// Returns the default priority for this candidate kind.
    ///
    /// Higher values indicate preferred paths. Host candidates are
    /// tried first (direct LAN), relays last (fallback).
    pub fn default_priority(&self) -> u32 {
        match self {
            CandidateKind::Host => 1000,
            CandidateKind::PortMapped => 800,
            CandidateKind::ServerReflexive => 500,
            CandidateKind::LinkLocal => 400,
            CandidateKind::Relay => 100,
        }
    }
}

impl Candidate {
    /// Creates a new candidate with the default priority for its kind.
    pub fn new(addr: SocketAddr, kind: CandidateKind, interface: Option<String>) -> Self {
        let priority = kind.default_priority();
        Self {
            addr,
            kind,
            priority,
            interface,
        }
    }

    /// Creates a new candidate with a custom priority.
    pub fn with_priority(
        addr: SocketAddr,
        kind: CandidateKind,
        priority: u32,
        interface: Option<String>,
    ) -> Self {
        Self {
            addr,
            kind,
            priority,
            interface,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_default_priorities() {
        assert_eq!(CandidateKind::Host.default_priority(), 1000);
        assert_eq!(CandidateKind::PortMapped.default_priority(), 800);
        assert_eq!(CandidateKind::ServerReflexive.default_priority(), 500);
        assert_eq!(CandidateKind::LinkLocal.default_priority(), 400);
        assert_eq!(CandidateKind::Relay.default_priority(), 100);
    }

    #[test]
    fn test_candidate_priority_ordering() {
        let host = Candidate::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820),
            CandidateKind::Host,
            Some("en0".into()),
        );
        let port_mapped = Candidate::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820),
            CandidateKind::PortMapped,
            None,
        );
        let reflexive = Candidate::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 45000),
            CandidateKind::ServerReflexive,
            None,
        );
        let link_local = Candidate::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                51820,
            ),
            CandidateKind::LinkLocal,
            Some("en0".into()),
        );
        let relay = Candidate::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 0, 0, 1)), 443),
            CandidateKind::Relay,
            None,
        );

        let mut candidates = vec![
            relay.clone(),
            reflexive.clone(),
            host.clone(),
            link_local.clone(),
            port_mapped.clone(),
        ];
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        assert_eq!(candidates[0].kind, CandidateKind::Host);
        assert_eq!(candidates[1].kind, CandidateKind::PortMapped);
        assert_eq!(candidates[2].kind, CandidateKind::ServerReflexive);
        assert_eq!(candidates[3].kind, CandidateKind::LinkLocal);
        assert_eq!(candidates[4].kind, CandidateKind::Relay);
    }

    #[test]
    fn test_candidate_new_sets_default_priority() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        let c = Candidate::new(addr, CandidateKind::Host, Some("en0".into()));
        assert_eq!(c.priority, 1000);
        assert_eq!(c.interface, Some("en0".into()));
    }

    #[test]
    fn test_candidate_with_custom_priority() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        let c = Candidate::with_priority(addr, CandidateKind::Host, 1500, None);
        assert_eq!(c.priority, 1500);
    }

    #[test]
    fn test_candidate_serialization_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        let original = Candidate::new(addr, CandidateKind::ServerReflexive, None);
        let json = serde_json::to_string(&original).unwrap();
        let restored: Candidate = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }
}
