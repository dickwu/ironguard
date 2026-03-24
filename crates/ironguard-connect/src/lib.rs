//! IronGuard Connect: NAT traversal and direct connectivity.
//!
//! Provides STUN address discovery, local interface enumeration,
//! NAT type detection, UPnP port mapping, coordinated hole punching,
//! birthday paradox spray, mDNS LAN discovery, and relay fallback
//! for automatic peer-to-peer connectivity.

pub mod birthday;
pub mod candidate;
pub mod discovery;
pub mod holepunch;
pub mod netcheck;
pub mod portmap;
pub mod relay;
pub mod stun;

mod manager;
pub use manager::{ConnectedPath, ConnectionConfig, ConnectionManager};
