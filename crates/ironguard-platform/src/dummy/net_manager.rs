use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::Result;

use crate::net_manager::{NetManagerOp, NetworkManager};

/// In-memory network manager that records all operations for test assertions.
///
/// Every method appends a [`NetManagerOp`] to an internal log rather than
/// executing real system commands. Use [`DummyNetManager::ops`] to inspect
/// the recorded operations.
pub struct DummyNetManager {
    ops: Mutex<Vec<NetManagerOp>>,
}

impl DummyNetManager {
    pub fn new() -> Self {
        Self {
            ops: Mutex::new(Vec::new()),
        }
    }

    /// Return a snapshot of all recorded operations.
    pub fn ops(&self) -> Vec<NetManagerOp> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .clone()
    }

    /// Clear the operation log.
    pub fn clear(&self) {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .clear();
    }
}

impl Default for DummyNetManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkManager for DummyNetManager {
    fn add_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::AddAddress {
                iface: iface.to_owned(),
                addr,
                prefix_len,
            });
        Ok(())
    }

    fn remove_address(&self, iface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::RemoveAddress {
                iface: iface.to_owned(),
                addr,
                prefix_len,
            });
        Ok(())
    }

    fn add_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::AddRoute {
                iface: iface.to_owned(),
                dest,
                prefix_len,
            });
        Ok(())
    }

    fn remove_route(&self, iface: &str, dest: IpAddr, prefix_len: u8) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::RemoveRoute {
                iface: iface.to_owned(),
                dest,
                prefix_len,
            });
        Ok(())
    }

    fn add_masquerade(
        &self,
        tun_iface: &str,
        tun_subnet: &str,
        out_ifaces: &[String],
    ) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::AddMasquerade {
                tun_iface: tun_iface.to_owned(),
                tun_subnet: tun_subnet.to_owned(),
                out_ifaces: out_ifaces.to_vec(),
            });
        Ok(())
    }

    fn remove_masquerade(&self, tun_iface: &str) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::RemoveMasquerade {
                tun_iface: tun_iface.to_owned(),
            });
        Ok(())
    }

    fn run_hook(&self, command: &str, iface: &str) -> Result<()> {
        self.ops
            .lock()
            .expect("DummyNetManager lock poisoned")
            .push(NetManagerOp::RunHook {
                command: command.to_owned(),
                iface: iface.to_owned(),
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn records_address_operations() {
        let mgr = DummyNetManager::new();
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

        mgr.add_address("utun7", v4, 24).unwrap();
        mgr.add_address("utun7", v6, 64).unwrap();
        mgr.remove_address("utun7", v4, 24).unwrap();

        let ops = mgr.ops();
        assert_eq!(ops.len(), 3);
        assert_eq!(
            ops[0],
            NetManagerOp::AddAddress {
                iface: "utun7".into(),
                addr: v4,
                prefix_len: 24,
            }
        );
        assert_eq!(
            ops[1],
            NetManagerOp::AddAddress {
                iface: "utun7".into(),
                addr: v6,
                prefix_len: 64,
            }
        );
        assert_eq!(
            ops[2],
            NetManagerOp::RemoveAddress {
                iface: "utun7".into(),
                addr: v4,
                prefix_len: 24,
            }
        );
    }

    #[test]
    fn records_route_operations() {
        let mgr = DummyNetManager::new();
        let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));

        mgr.add_route("utun7", dest, 24).unwrap();
        mgr.remove_route("utun7", dest, 24).unwrap();

        let ops = mgr.ops();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            NetManagerOp::AddRoute {
                iface: "utun7".into(),
                dest,
                prefix_len: 24,
            }
        );
        assert_eq!(
            ops[1],
            NetManagerOp::RemoveRoute {
                iface: "utun7".into(),
                dest,
                prefix_len: 24,
            }
        );
    }

    #[test]
    fn records_masquerade_operations() {
        let mgr = DummyNetManager::new();

        mgr.add_masquerade("utun7", "10.0.0.0/24", &["en0".into(), "en1".into()])
            .unwrap();
        mgr.remove_masquerade("utun7").unwrap();

        let ops = mgr.ops();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            NetManagerOp::AddMasquerade {
                tun_iface: "utun7".into(),
                tun_subnet: "10.0.0.0/24".into(),
                out_ifaces: vec!["en0".into(), "en1".into()],
            }
        );
        assert_eq!(
            ops[1],
            NetManagerOp::RemoveMasquerade {
                tun_iface: "utun7".into(),
            }
        );
    }

    #[test]
    fn records_hook_operations() {
        let mgr = DummyNetManager::new();

        mgr.run_hook("echo %i is up", "utun7").unwrap();

        let ops = mgr.ops();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            NetManagerOp::RunHook {
                command: "echo %i is up".into(),
                iface: "utun7".into(),
            }
        );
    }

    #[test]
    fn clear_resets_log() {
        let mgr = DummyNetManager::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        mgr.add_address("utun7", addr, 24).unwrap();
        assert_eq!(mgr.ops().len(), 1);

        mgr.clear();
        assert!(mgr.ops().is_empty());
    }

    #[test]
    fn default_starts_empty() {
        let mgr = DummyNetManager::default();
        assert!(mgr.ops().is_empty());
    }
}
