use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;

/// Maps receiver IDs to relay target addresses for opaque packet forwarding.
///
/// When a packet arrives with a receiver ID in this table, it is forwarded
/// directly to the target address without decryption. This enables a node
/// to act as an opaque relay, forwarding encrypted WireGuard packets to
/// their intended destination without holding any key material for those
/// sessions.
pub type RelayTable = Arc<RwLock<HashMap<u32, SocketAddr>>>;

/// Create a new empty relay table.
pub fn new_relay_table() -> RelayTable {
    Arc::new(RwLock::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_relay_table_is_empty() {
        let table = new_relay_table();
        assert!(table.read().is_empty());
    }

    #[test]
    fn test_relay_table_insert_and_lookup() {
        let table = new_relay_table();
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        table.write().insert(999, addr);

        assert_eq!(table.read().get(&999), Some(&addr));
        assert_eq!(table.read().get(&1000), None);
    }

    #[test]
    fn test_relay_table_remove() {
        let table = new_relay_table();
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        table.write().insert(42, addr);

        assert!(table.read().contains_key(&42));
        table.write().remove(&42);
        assert!(!table.read().contains_key(&42));
    }
}
