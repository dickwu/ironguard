//! Same-subnet detection for local connectivity fast path.
//!
//! Compares candidate peer addresses against local interface
//! network masks to determine if a peer is on the same LAN.
//! Same-subnet peers can skip the entire NAT traversal stack
//! and connect directly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::local::InterfaceInfo;

/// Checks whether a candidate socket address is on the same subnet as
/// any of the provided local interfaces.
///
/// This enables the same-subnet fast path: when both peers are on the
/// same LAN, direct communication is possible without STUN, hole
/// punching, or relay servers.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use ironguard_connect::discovery::local::InterfaceInfo;
/// use ironguard_connect::discovery::subnet::is_same_subnet;
///
/// let interfaces = vec![InterfaceInfo {
///     name: "en0".into(),
///     addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
///     netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
///     flags: 0,
/// }];
///
/// let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51820);
/// assert!(is_same_subnet(&peer, &interfaces));
///
/// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);
/// assert!(!is_same_subnet(&remote, &interfaces));
/// ```
pub fn is_same_subnet(addr: &SocketAddr, interfaces: &[InterfaceInfo]) -> bool {
    let candidate_ip = addr.ip();

    interfaces.iter().any(|iface| {
        let Some(mask) = iface.netmask else {
            return false;
        };
        ips_share_subnet(&candidate_ip, &iface.addr, &mask)
    })
}

/// Returns the name of the local interface that shares a subnet with
/// the given address, if any.
pub fn matching_interface<'a>(
    addr: &SocketAddr,
    interfaces: &'a [InterfaceInfo],
) -> Option<&'a InterfaceInfo> {
    let candidate_ip = addr.ip();

    interfaces.iter().find(|iface| {
        let Some(mask) = iface.netmask else {
            return false;
        };
        ips_share_subnet(&candidate_ip, &iface.addr, &mask)
    })
}

/// Checks if two IP addresses are on the same subnet given a netmask.
fn ips_share_subnet(a: &IpAddr, b: &IpAddr, mask: &IpAddr) -> bool {
    match (a, b, mask) {
        (IpAddr::V4(a4), IpAddr::V4(b4), IpAddr::V4(m4)) => ipv4_same_subnet(a4, b4, m4),
        (IpAddr::V6(a6), IpAddr::V6(b6), IpAddr::V6(m6)) => ipv6_same_subnet(a6, b6, m6),
        _ => false, // Mismatched address families
    }
}

fn ipv4_same_subnet(a: &Ipv4Addr, b: &Ipv4Addr, mask: &Ipv4Addr) -> bool {
    let a_bits = u32::from(*a);
    let b_bits = u32::from(*b);
    let mask_bits = u32::from(*mask);
    (a_bits & mask_bits) == (b_bits & mask_bits)
}

fn ipv6_same_subnet(a: &Ipv6Addr, b: &Ipv6Addr, mask: &Ipv6Addr) -> bool {
    let a_bits = u128::from(*a);
    let b_bits = u128::from(*b);
    let mask_bits = u128::from(*mask);
    (a_bits & mask_bits) == (b_bits & mask_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_interface(ip: Ipv4Addr, mask: Ipv4Addr) -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(ip),
            netmask: Some(IpAddr::V4(mask)),
            flags: 0,
        }
    }

    #[test]
    fn test_same_subnet_24() {
        let interfaces = vec![make_interface(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        )];

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51820);
        assert!(is_same_subnet(&peer, &interfaces));

        let peer_far = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)), 51820);
        assert!(is_same_subnet(&peer_far, &interfaces));
    }

    #[test]
    fn test_different_subnet_24() {
        let interfaces = vec![make_interface(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        )];

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 51820);
        assert!(!is_same_subnet(&peer, &interfaces));

        let peer2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);
        assert!(!is_same_subnet(&peer2, &interfaces));
    }

    #[test]
    fn test_same_subnet_16() {
        let interfaces = vec![make_interface(
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(255, 255, 0, 0),
        )];

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 5, 100)), 51820);
        assert!(is_same_subnet(&peer, &interfaces));

        let peer_diff = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)), 51820);
        assert!(!is_same_subnet(&peer_diff, &interfaces));
    }

    #[test]
    fn test_same_subnet_with_multiple_interfaces() {
        let interfaces = vec![
            make_interface(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 0)),
            make_interface(
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
        ];

        // Matches second interface
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        assert!(is_same_subnet(&peer, &interfaces));

        // Matches neither
        let peer2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 51820);
        assert!(!is_same_subnet(&peer2, &interfaces));
    }

    #[test]
    fn test_no_netmask_returns_false() {
        let interfaces = vec![InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            netmask: None,
            flags: 0,
        }];

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51820);
        assert!(!is_same_subnet(&peer, &interfaces));
    }

    #[test]
    fn test_empty_interfaces_returns_false() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820);
        assert!(!is_same_subnet(&peer, &[]));
    }

    #[test]
    fn test_ipv6_same_subnet() {
        let interfaces = vec![InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            netmask: Some(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            flags: 0,
        }];

        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
            51820,
        );
        assert!(is_same_subnet(&peer, &interfaces));

        let peer_diff = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            51820,
        );
        assert!(!is_same_subnet(&peer_diff, &interfaces));
    }

    #[test]
    fn test_matching_interface_returns_correct_iface() {
        let interfaces = vec![
            InterfaceInfo {
                name: "en0".into(),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                flags: 0,
            },
            InterfaceInfo {
                name: "en1".into(),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                flags: 0,
            },
        ];

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 51820);
        let matched = matching_interface(&peer, &interfaces);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, "en1");
    }

    #[test]
    fn test_mismatched_address_family_returns_false() {
        // IPv6 candidate against IPv4-only interfaces
        let interfaces = vec![make_interface(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        )];

        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            51820,
        );
        assert!(!is_same_subnet(&peer, &interfaces));
    }
}
