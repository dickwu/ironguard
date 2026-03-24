use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crate::endpoint::Endpoint;
use crate::udp;

use super::endpoint::MacosEndpoint;

#[derive(Debug, thiserror::Error)]
pub enum MacosUdpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("udp error: {0}")]
    Udp(String),
}

pub struct MacosUdpWriter {
    socket: Arc<tokio::net::UdpSocket>,
}

impl udp::UdpWriter<MacosEndpoint> for MacosUdpWriter {
    type Error = MacosUdpError;

    async fn write(&self, buf: &[u8], dst: &mut MacosEndpoint) -> Result<(), Self::Error> {
        self.socket.send_to(buf, dst.to_address()).await?;
        Ok(())
    }
}

pub struct MacosUdpReader {
    socket: Arc<tokio::net::UdpSocket>,
}

impl udp::UdpReader<MacosEndpoint> for MacosUdpReader {
    type Error = MacosUdpError;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint), Self::Error> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        Ok((len, MacosEndpoint::from_address(addr)))
    }
}

pub struct MacosUdp;

impl udp::Udp for MacosUdp {
    type Error = MacosUdpError;
    type Endpoint = MacosEndpoint;
    type Writer = MacosUdpWriter;
    type Reader = MacosUdpReader;
}

pub struct MacosOwner {
    port: u16,
}

impl MacosOwner {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl udp::Owner for MacosOwner {
    type Error = MacosUdpError;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), Self::Error> {
        // fwmark is a Linux concept; no-op on macOS
        Ok(())
    }
}

impl udp::PlatformUdp for MacosUdp {
    type Owner = MacosOwner;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

        // Create a std::net::UdpSocket first, then convert to tokio
        let std_socket = std::net::UdpSocket::bind(addr)?;
        std_socket.set_nonblocking(true)?;

        // Increase socket buffers to 1 MB for high-throughput batch I/O.
        // Default macOS buffers are too small and cause drops under load.
        let buf_size: libc::c_int = 1_048_576;
        let fd = std_socket.as_raw_fd();
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        tracing::debug!("set UDP SO_RCVBUF/SO_SNDBUF to 1MB");

        let actual_port = std_socket.local_addr()?.port();

        let socket = Arc::new(
            tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| MacosUdpError::Udp(format!("failed to convert socket: {e}")))?,
        );

        let reader = MacosUdpReader {
            socket: Arc::clone(&socket),
        };
        let writer = MacosUdpWriter { socket };
        let owner = MacosOwner { port: actual_port };

        tracing::info!(port = actual_port, "bound UDP socket");

        Ok((vec![reader], writer, owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::PlatformUdp;

    #[tokio::test]
    async fn test_macos_udp_bind() {
        let result = MacosUdp::bind(0);
        assert!(result.is_ok(), "UDP bind failed: {:?}", result.err());
        let (_readers, _writer, owner) = result.unwrap();
        assert!(owner.port() > 0, "should have been assigned a port");
    }
}
