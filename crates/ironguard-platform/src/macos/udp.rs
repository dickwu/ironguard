use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crate::endpoint::Endpoint;
use crate::udp;

use super::darwin_batch::{DarwinBatchIo, pending_recv_count};
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
    batch_io: Arc<DarwinBatchIo>,
}

impl udp::UdpWriter<MacosEndpoint> for MacosUdpWriter {
    type Error = MacosUdpError;

    async fn write(&self, buf: &[u8], dst: &mut MacosEndpoint) -> Result<(), Self::Error> {
        self.socket.send_to(buf, dst.to_address()).await?;
        Ok(())
    }

    /// Send multiple datagrams in a single syscall via sendmsg_x.
    /// Falls back to individual sendto if sendmsg_x is unavailable.
    async fn write_batch(&self, msgs: &[(Vec<u8>, SocketAddr)]) -> Result<usize, Self::Error> {
        if msgs.is_empty() {
            return Ok(0);
        }

        // Wait for the socket to be writable before attempting the batch.
        self.socket.writable().await?;

        let fd = self.socket.as_raw_fd();
        let batch_io = Arc::clone(&self.batch_io);

        // DarwinBatchIo::send_batch is a synchronous FFI call. Clone the
        // data into a Vec so it can be sent to a blocking thread safely.
        let msgs_owned: Vec<(Vec<u8>, SocketAddr)> = msgs.to_vec();

        let result = tokio::task::spawn_blocking(move || batch_io.send_batch(fd, &msgs_owned))
            .await
            .map_err(|e| MacosUdpError::Udp(format!("spawn_blocking join error: {e}")))?;

        Ok(result?)
    }
}

pub struct MacosUdpReader {
    socket: Arc<tokio::net::UdpSocket>,
    batch_io: Arc<DarwinBatchIo>,
}

impl udp::UdpReader<MacosEndpoint> for MacosUdpReader {
    type Error = MacosUdpError;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint), Self::Error> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        Ok((len, MacosEndpoint::from_address(addr)))
    }

    /// Receive multiple datagrams in a single syscall via recvmsg_x.
    /// Falls back to individual recvfrom if recvmsg_x is unavailable.
    async fn read_batch(
        &self,
        bufs: &mut [Vec<u8>],
        max: usize,
    ) -> Result<Vec<(usize, MacosEndpoint)>, Self::Error> {
        if max == 0 || bufs.is_empty() {
            return Ok(Vec::new());
        }

        // Wait for the socket to be readable before attempting the batch.
        self.socket.readable().await?;

        let fd = self.socket.as_raw_fd();
        let batch_io = Arc::clone(&self.batch_io);

        // Convert the mutable slice into owned Vecs for the blocking task.
        let mut owned_bufs: Vec<Vec<u8>> = bufs.to_vec();
        let batch_max = max.min(owned_bufs.len());

        let (result, returned_bufs) = tokio::task::spawn_blocking(move || {
            let r = batch_io.recv_batch(fd, &mut owned_bufs, batch_max);
            (r, owned_bufs)
        })
        .await
        .map_err(|e| MacosUdpError::Udp(format!("spawn_blocking join error: {e}")))?;

        // Copy the received data back into the caller's buffers.
        for (i, buf) in returned_bufs.into_iter().enumerate() {
            if i < bufs.len() {
                bufs[i] = buf;
            }
        }

        let raw_results = result?;
        let endpoints = raw_results
            .into_iter()
            .map(|(n, addr)| (n, MacosEndpoint::from_address(addr)))
            .collect();
        Ok(endpoints)
    }

    /// Query the number of datagrams queued in the receive buffer via SO_NUMRCVPKT.
    fn pending_recv_count(&self) -> Option<u32> {
        pending_recv_count(self.socket.as_raw_fd())
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

        // Probe for sendmsg_x/recvmsg_x once at bind time and share across
        // reader and writer. This avoids repeated dlsym lookups.
        let batch_io = Arc::new(DarwinBatchIo::probe());
        if batch_io.is_available() {
            tracing::info!("sendmsg_x/recvmsg_x batch I/O available");
        } else {
            tracing::warn!("sendmsg_x/recvmsg_x not available; using single-packet fallback");
        }

        let reader = MacosUdpReader {
            socket: Arc::clone(&socket),
            batch_io: Arc::clone(&batch_io),
        };
        let writer = MacosUdpWriter { socket, batch_io };
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
