use anyhow::Result;
use std::net::IpAddr;

/// Operations recorded by the dummy network manager for test assertions.
#[derive(Clone, Debug, PartialEq)]
pub enum NetManagerOp {
    AddAddress {
        iface: String,
        addr: IpAddr,
        prefix_len: u8,
    },
    RemoveAddress {
        iface: String,
        addr: IpAddr,
        prefix_len: u8,
    },
    AddRoute {
        iface: String,
        dest: IpAddr,
        prefix_len: u8,
    },
    RemoveRoute {
        iface: String,
        dest: IpAddr,
        prefix_len: u8,
    },
    AddMasquerade {
        tun_iface: String,
        tun_subnet: String,
        out_ifaces: Vec<String>,
    },
    RemoveMasquerade {
        tun_iface: String,
    },
    RunHook {
        command: String,
        iface: String,
    },
}

/// Platform-agnostic network configuration interface.
///
/// Implementations manage IP addresses, routes, NAT masquerade rules, and
/// lifecycle hooks for a tunnel interface. All methods are idempotent --
/// applying the same operation twice must not fail.
pub trait NetworkManager: Send + Sync {
    /// Assign an IP address to a network interface.
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;

    /// Remove an IP address from a network interface.
    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()>;

    /// Add a route directing traffic for `dest/prefix_len` through `iface`.
    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;

    /// Remove a previously added route.
    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()>;

    /// Install NAT masquerade rules so that traffic from `tun_subnet` leaving
    /// through any of `out_ifaces` is source-NATed.
    fn add_masquerade(
        &self,
        tun_iface: &str,
        tun_subnet: &str,
        out_ifaces: &[String],
    ) -> Result<()>;

    /// Remove all masquerade rules associated with `tun_iface`.
    fn remove_masquerade(&self, tun_iface: &str) -> Result<()>;

    /// Run a user-defined hook command, replacing `%i` with `iface`.
    fn run_hook(&self, command: &str, iface: &str) -> Result<()>;
}
