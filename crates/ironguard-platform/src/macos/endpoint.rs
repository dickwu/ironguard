use std::net::SocketAddr;

use crate::endpoint::Endpoint;

#[derive(Clone, Debug)]
pub struct MacosEndpoint {
    addr: SocketAddr,
}

impl Endpoint for MacosEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn to_address(&self) -> SocketAddr {
        self.addr
    }

    fn clear_src(&mut self) {
        // No-op on macOS -- there is no IP_PKTINFO sticky source address
    }
}
