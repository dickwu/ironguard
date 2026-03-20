use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ip_network_table_deps_treebitmap::IpLookupTable;
use spin::RwLock;

const VERSION_IP4: u8 = 4;
const VERSION_IP6: u8 = 6;

/// Mask trait for zeroing host bits beyond cidr length.
trait Mask: Sized {
    fn mask(self, cidr: u32) -> Self;
}

impl Mask for Ipv4Addr {
    fn mask(self, cidr: u32) -> Self {
        let bits = u32::from(self);
        let masked = if cidr == 0 {
            0
        } else if cidr >= 32 {
            bits
        } else {
            bits & !((1u32 << (32 - cidr)) - 1)
        };
        Ipv4Addr::from(masked)
    }
}

impl Mask for Ipv6Addr {
    fn mask(self, cidr: u32) -> Self {
        let bits = u128::from(self);
        let masked = if cidr == 0 {
            0
        } else if cidr >= 128 {
            bits
        } else {
            bits & !((1u128 << (128 - cidr)) - 1)
        };
        Ipv6Addr::from(masked)
    }
}

/// Crypto-key routing table with longest-prefix-match for IPv4 and IPv6.
pub struct RoutingTable<T: Eq + Clone> {
    ipv4: RwLock<IpLookupTable<Ipv4Addr, T>>,
    ipv6: RwLock<IpLookupTable<Ipv6Addr, T>>,
}

impl<T: Eq + Clone> Default for RoutingTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Eq + Clone> RoutingTable<T> {
    pub fn new() -> Self {
        RoutingTable {
            ipv4: RwLock::new(IpLookupTable::new()),
            ipv6: RwLock::new(IpLookupTable::new()),
        }
    }

    /// Insert a route entry, masking the IP to cidr bits before storing.
    pub fn insert(&self, ip: IpAddr, cidr: u32, value: T) {
        match ip {
            IpAddr::V4(v4) => {
                self.ipv4.write().insert(v4.mask(cidr), cidr, value);
            }
            IpAddr::V6(v6) => {
                self.ipv6.write().insert(v6.mask(cidr), cidr, value);
            }
        }
    }

    /// List all CIDRs mapped to the given value.
    pub fn list(&self, value: &T) -> Vec<(IpAddr, u32)> {
        let mut res = Vec::new();
        for (ip, cidr, v) in self.ipv4.read().iter() {
            if v == value {
                res.push((IpAddr::V4(ip), cidr));
            }
        }
        for (ip, cidr, v) in self.ipv6.read().iter() {
            if v == value {
                res.push((IpAddr::V6(ip), cidr));
            }
        }
        res
    }

    /// Remove all entries mapped to the given value.
    pub fn remove(&self, value: &T) {
        let mut v4 = self.ipv4.write();
        let to_remove: Vec<_> = v4
            .iter()
            .filter(|(_, _, v)| *v == value)
            .map(|(ip, cidr, _)| (ip, cidr))
            .collect();
        for (ip, cidr) in to_remove {
            v4.remove(ip, cidr);
        }

        let mut v6 = self.ipv6.write();
        let to_remove: Vec<_> = v6
            .iter()
            .filter(|(_, _, v)| *v == value)
            .map(|(ip, cidr, _)| (ip, cidr))
            .collect();
        for (ip, cidr) in to_remove {
            v6.remove(ip, cidr);
        }
    }

    /// Look up the peer for an outbound IP packet by destination address (LPM).
    #[inline(always)]
    pub fn get_route(&self, packet: &[u8]) -> Option<T> {
        match packet.first()? >> 4 {
            VERSION_IP4 => {
                if packet.len() < 20 {
                    return None;
                }
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                self.ipv4
                    .read()
                    .longest_match(dst)
                    .map(|(_, _, v)| v.clone())
            }
            VERSION_IP6 => {
                if packet.len() < 40 {
                    return None;
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&packet[24..40]);
                let dst = Ipv6Addr::from(addr);
                self.ipv6
                    .read()
                    .longest_match(dst)
                    .map(|(_, _, v)| v.clone())
            }
            _ => None,
        }
    }

    /// Check that an inbound packet's source address matches the expected peer (allowed-IPs filtering).
    #[inline(always)]
    pub fn check_route(&self, peer: &T, packet: &[u8]) -> bool {
        match packet.first().map(|v| v >> 4) {
            Some(VERSION_IP4) => {
                if packet.len() < 20 {
                    return false;
                }
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                self.ipv4
                    .read()
                    .longest_match(src)
                    .map(|(_, _, v)| v == peer)
                    .unwrap_or(false)
            }
            Some(VERSION_IP6) => {
                if packet.len() < 40 {
                    return false;
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&packet[8..24]);
                let src = Ipv6Addr::from(addr);
                self.ipv6
                    .read()
                    .longest_match(src)
                    .map(|(_, _, v)| v == peer)
                    .unwrap_or(false)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 packet with the given src and dst addresses.
    fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        // version (4) + IHL (5) in first nibble
        pkt[0] = 0x45;
        // total length = 20
        pkt[2] = 0;
        pkt[3] = 20;
        // src at [12..16]
        pkt[12..16].copy_from_slice(&src.octets());
        // dst at [16..20]
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt
    }

    /// Build a minimal IPv6 packet with the given src and dst addresses.
    fn make_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        // version (6) in first nibble
        pkt[0] = 0x60;
        // src at [8..24]
        pkt[8..24].copy_from_slice(&src.octets());
        // dst at [24..40]
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt
    }

    #[test]
    fn test_ipv4_route_lookup() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("10.0.0.0".parse().unwrap(), 24, 1);
        rt.insert("10.0.1.0".parse().unwrap(), 24, 2);

        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(1));

        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.0.1.5".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(2));

        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.0.2.5".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), None);
    }

    #[test]
    fn test_ipv6_route_lookup() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("2001:db8::".parse().unwrap(), 32, 1);
        rt.insert("2001:db9::".parse().unwrap(), 32, 2);

        let pkt = make_ipv6_packet("::1".parse().unwrap(), "2001:db8::1".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(1));

        let pkt = make_ipv6_packet("::1".parse().unwrap(), "2001:db9::1".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(2));

        let pkt = make_ipv6_packet("::1".parse().unwrap(), "2001:dba::1".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), None);
    }

    #[test]
    fn test_longest_prefix_match() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("10.0.0.0".parse().unwrap(), 8, 1);
        rt.insert("10.0.0.0".parse().unwrap(), 24, 2);

        // Packet to 10.0.0.5 should match /24 (peer 2), not /8
        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(2));

        // Packet to 10.1.0.5 should match /8 (peer 1)
        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.1.0.5".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(1));
    }

    #[test]
    fn test_check_route_allowed_ips() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("10.0.0.0".parse().unwrap(), 24, 1);
        rt.insert("10.0.1.0".parse().unwrap(), 24, 2);

        // Source 10.0.0.5 belongs to peer 1
        let pkt = make_ipv4_packet("10.0.0.5".parse().unwrap(), "192.168.1.1".parse().unwrap());
        assert!(rt.check_route(&1, &pkt));
        assert!(!rt.check_route(&2, &pkt));

        // Source 10.0.1.5 belongs to peer 2
        let pkt = make_ipv4_packet("10.0.1.5".parse().unwrap(), "192.168.1.1".parse().unwrap());
        assert!(!rt.check_route(&1, &pkt));
        assert!(rt.check_route(&2, &pkt));
    }

    #[test]
    fn test_check_route_ipv6() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("2001:db8::".parse().unwrap(), 32, 1);

        let pkt = make_ipv6_packet("2001:db8::1".parse().unwrap(), "::1".parse().unwrap());
        assert!(rt.check_route(&1, &pkt));
        assert!(!rt.check_route(&2, &pkt));
    }

    #[test]
    fn test_list_and_remove() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("10.0.0.0".parse().unwrap(), 24, 1);
        rt.insert("10.0.1.0".parse().unwrap(), 24, 1);
        rt.insert("192.168.0.0".parse().unwrap(), 16, 2);

        let list1 = rt.list(&1);
        assert_eq!(list1.len(), 2);

        let list2 = rt.list(&2);
        assert_eq!(list2.len(), 1);

        rt.remove(&1);

        let list1 = rt.list(&1);
        assert_eq!(list1.len(), 0);

        // Peer 2 routes should still be there
        let list2 = rt.list(&2);
        assert_eq!(list2.len(), 1);
    }

    #[test]
    fn test_insert_masks_host_bits() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        // Insert with host bits set - should be masked to 10.0.0.0/24
        rt.insert("10.0.0.128".parse().unwrap(), 24, 1);

        let pkt = make_ipv4_packet("127.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap());
        assert_eq!(rt.get_route(&pkt), Some(1));
    }

    #[test]
    fn test_empty_or_short_packet() {
        let rt: RoutingTable<u32> = RoutingTable::new();
        rt.insert("10.0.0.0".parse().unwrap(), 8, 1);

        assert_eq!(rt.get_route(&[]), None);
        assert_eq!(rt.get_route(&[0x45]), None); // too short for IPv4
        assert!(!rt.check_route(&1, &[]));
    }
}
