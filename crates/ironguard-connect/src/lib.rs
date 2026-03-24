//! IronGuard Connect: NAT traversal and direct connectivity.
//!
//! Provides STUN address discovery, local interface enumeration,
//! NAT type detection, and candidate gathering for automatic
//! peer-to-peer connectivity.

pub mod candidate;
pub mod discovery;
pub mod netcheck;
pub mod stun;

mod manager;
pub use manager::ConnectionManager;
