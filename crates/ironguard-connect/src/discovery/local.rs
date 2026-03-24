//! Local network interface enumeration.
//!
//! Uses `getifaddrs()` via libc to discover physical network interfaces,
//! filtering out virtual interfaces (VPN tunnels, Docker bridges, etc.)
//! that could cause routing loops.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Information about a local network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "en0", "eth0").
    pub name: String,
    /// IP address assigned to this interface.
    pub addr: IpAddr,
    /// Network mask (subnet mask) for this interface.
    pub netmask: Option<IpAddr>,
    /// Interface flags from the OS (IFF_UP, IFF_RUNNING, etc.).
    pub flags: u32,
}

impl InterfaceInfo {
    /// Returns the network prefix length (CIDR notation) from the netmask.
    pub fn prefix_len(&self) -> u32 {
        match self.netmask {
            Some(IpAddr::V4(mask)) => {
                let bits = u32::from(mask);
                bits.count_ones()
            }
            Some(IpAddr::V6(mask)) => {
                let bits = u128::from(mask);
                bits.count_ones()
            }
            None => 0,
        }
    }

    /// Returns the network address (IP & netmask) for this interface.
    pub fn network_addr(&self) -> Option<IpAddr> {
        match (self.addr, self.netmask?) {
            (IpAddr::V4(addr), IpAddr::V4(mask)) => {
                let net = u32::from(addr) & u32::from(mask);
                Some(IpAddr::V4(Ipv4Addr::from(net)))
            }
            (IpAddr::V6(addr), IpAddr::V6(mask)) => {
                let net = u128::from(addr) & u128::from(mask);
                Some(IpAddr::V6(Ipv6Addr::from(net)))
            }
            _ => None,
        }
    }
}

/// Prefixes that identify virtual/tunnel interfaces to exclude.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "utun",      // macOS userspace tunnels (WireGuard, etc.)
    "tun",       // TUN devices
    "tap",       // TAP devices
    "docker",    // Docker bridge interfaces
    "br-",       // Docker/Linux bridge interfaces
    "veth",      // Docker/container veth pairs
    "wg",        // WireGuard kernel interfaces
    "tailscale", // Tailscale interfaces
    "lo",        // Loopback
];

/// Prefixes that identify physical network interfaces to include.
const PHYSICAL_INTERFACE_PREFIXES: &[&str] = &[
    "en",   // macOS Ethernet/WiFi (en0, en1, etc.)
    "eth",  // Linux Ethernet
    "wlan", // Linux WiFi
];

/// Returns true if the interface name matches a virtual/tunnel interface.
fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Returns true if the interface name matches a physical network interface.
fn is_physical_interface(name: &str) -> bool {
    PHYSICAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Enumerates local physical network interfaces with their IP addresses.
///
/// Filters out:
/// - Virtual interfaces (utun, tun, tap, docker, br-, veth, wg, tailscale, lo)
/// - Interfaces with IFF_POINTOPOINT flag (PPP links)
/// - Interfaces with IFF_LOOPBACK flag
/// - Interfaces that are not up (IFF_UP not set)
/// - Non-physical interface names (only en*, eth*, wlan* pass)
///
/// Returns only interfaces with valid IPv4 or IPv6 addresses.
pub fn enumerate_interfaces() -> Vec<InterfaceInfo> {
    #[cfg(unix)]
    {
        enumerate_interfaces_unix()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

#[cfg(unix)]
fn enumerate_interfaces_unix() -> Vec<InterfaceInfo> {
    use std::ptr;

    let mut ifaddrs_ptr: *mut libc::ifaddrs = ptr::null_mut();

    // SAFETY: getifaddrs allocates and populates a linked list.
    // We free it with freeifaddrs before returning.
    let ret = unsafe { libc::getifaddrs(&mut ifaddrs_ptr) };
    if ret != 0 {
        tracing::warn!("getifaddrs() failed: {}", std::io::Error::last_os_error());
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut current = ifaddrs_ptr;

    while !current.is_null() {
        // SAFETY: current is non-null and was populated by getifaddrs.
        let ifa = unsafe { &*current };

        if let Some(info) = parse_interface(ifa) {
            results.push(info);
        }

        current = ifa.ifa_next;
    }

    // SAFETY: ifaddrs_ptr was allocated by getifaddrs.
    unsafe {
        libc::freeifaddrs(ifaddrs_ptr);
    }

    results
}

#[cfg(unix)]
fn parse_interface(ifa: &libc::ifaddrs) -> Option<InterfaceInfo> {
    // Get interface name
    if ifa.ifa_name.is_null() {
        return None;
    }
    // SAFETY: ifa_name is a C string populated by getifaddrs.
    let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
        .to_str()
        .ok()?
        .to_owned();

    let flags = ifa.ifa_flags;

    // Filter: must be up
    if flags & (libc::IFF_UP as u32) == 0 {
        return None;
    }

    // Filter: skip loopback
    if flags & (libc::IFF_LOOPBACK as u32) != 0 {
        return None;
    }

    // Filter: skip point-to-point (PPP, tunnel)
    if flags & (libc::IFF_POINTOPOINT as u32) != 0 {
        return None;
    }

    // Filter: skip virtual interfaces by name
    if is_virtual_interface(&name) {
        return None;
    }

    // Filter: only include physical interfaces by name
    if !is_physical_interface(&name) {
        return None;
    }

    // Get IP address
    if ifa.ifa_addr.is_null() {
        return None;
    }

    let addr = sockaddr_to_ip(ifa.ifa_addr)?;

    // Get netmask
    let netmask = if ifa.ifa_netmask.is_null() {
        None
    } else {
        sockaddr_to_ip(ifa.ifa_netmask)
    };

    Some(InterfaceInfo {
        name,
        addr,
        netmask,
        flags,
    })
}

/// Converts a libc sockaddr pointer to a Rust IpAddr.
///
/// Supports AF_INET (IPv4) and AF_INET6 (IPv6).
#[cfg(unix)]
fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }

    // SAFETY: sa is non-null and was populated by getifaddrs.
    let family = unsafe { (*sa).sa_family } as i32;

    match family {
        libc::AF_INET => {
            // SAFETY: We checked sa_family == AF_INET, so this is a sockaddr_in.
            let sa_in = unsafe { &*(sa as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sa_in.sin_addr.s_addr));
            Some(IpAddr::V4(ip))
        }
        libc::AF_INET6 => {
            // SAFETY: We checked sa_family == AF_INET6, so this is a sockaddr_in6.
            let sa_in6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sa_in6.sin6_addr.s6_addr);
            Some(IpAddr::V6(ip))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_interfaces_returns_results() {
        let interfaces = enumerate_interfaces();
        // On any real machine, there should be at least one physical interface
        // (en0 on macOS, eth0 on Linux). This test may fail in containers
        // without physical NICs.
        assert!(
            !interfaces.is_empty(),
            "expected at least one physical interface"
        );

        for iface in &interfaces {
            assert!(
                is_physical_interface(&iface.name),
                "interface '{}' should be physical",
                iface.name
            );
            assert!(
                !is_virtual_interface(&iface.name),
                "interface '{}' should not be virtual",
                iface.name
            );
        }
    }

    #[test]
    fn test_filter_virtual_interfaces() {
        assert!(is_virtual_interface("utun0"));
        assert!(is_virtual_interface("utun3"));
        assert!(is_virtual_interface("tun0"));
        assert!(is_virtual_interface("tap0"));
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("br-abc123"));
        assert!(is_virtual_interface("veth1234"));
        assert!(is_virtual_interface("wg0"));
        assert!(is_virtual_interface("tailscale0"));
        assert!(is_virtual_interface("lo"));
        assert!(is_virtual_interface("lo0"));

        assert!(!is_virtual_interface("en0"));
        assert!(!is_virtual_interface("eth0"));
        assert!(!is_virtual_interface("wlan0"));
    }

    #[test]
    fn test_physical_interface_detection() {
        assert!(is_physical_interface("en0"));
        assert!(is_physical_interface("en1"));
        assert!(is_physical_interface("eth0"));
        assert!(is_physical_interface("eth1"));
        assert!(is_physical_interface("wlan0"));

        assert!(!is_physical_interface("utun0"));
        assert!(!is_physical_interface("lo0"));
        assert!(!is_physical_interface("docker0"));
    }

    #[test]
    fn test_interface_info_prefix_len() {
        let info = InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            flags: 0,
        };
        assert_eq!(info.prefix_len(), 24);

        let info16 = InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 0, 0))),
            flags: 0,
        };
        assert_eq!(info16.prefix_len(), 16);
    }

    #[test]
    fn test_interface_info_network_addr() {
        let info = InterfaceInfo {
            name: "en0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            flags: 0,
        };
        assert_eq!(
            info.network_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)))
        );
    }

    #[test]
    fn test_enumerated_interfaces_have_valid_addrs() {
        let interfaces = enumerate_interfaces();
        for iface in &interfaces {
            // All returned interfaces should have non-loopback addresses
            match iface.addr {
                IpAddr::V4(v4) => {
                    assert!(!v4.is_loopback(), "should not include loopback addresses");
                }
                IpAddr::V6(v6) => {
                    assert!(!v6.is_loopback(), "should not include loopback addresses");
                }
            }
        }
    }
}
