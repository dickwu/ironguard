use std::net::SocketAddr;

use crate::endpoint::Endpoint;

#[derive(Clone, Debug)]
pub struct LinuxEndpoint {
    addr: SocketAddr,
}

impl Endpoint for LinuxEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn to_address(&self) -> SocketAddr {
        self.addr
    }

    fn clear_src(&mut self) {
        // No-op for now -- could use IP_PKTINFO to clear sticky source later
    }
}
