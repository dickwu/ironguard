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
    ///
    /// Each entry is `(buffer, byte_offset, destination)`. Wire data is
    /// at `buffer[offset..]`, avoiding the memmove that `buf.drain(..offset)`
    /// would require in the caller.
    async fn write_batch(&self, msgs: &[(&[u8], usize, SocketAddr)]) -> Result<usize, Self::Error> {
        if msgs.is_empty() {
            return Ok(0);
        }

        // Wait for the socket to be writable, then call the batch syscall
        // directly on the raw fd. On EWOULDBLOCK, retry after waiting again.
        // Unlike the read path, the write spin is benign: we only call
        // write_batch when we have data, and send_batch almost always
        // succeeds on a writable UDP socket.
        loop {
            self.socket.writable().await?;
            let fd = self.socket.as_raw_fd();

            match self.batch_io.send_batch(fd, msgs) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(MacosUdpError::Io(e)),
            }
        }
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
    ///
    /// Strategy: receive the first packet through tokio's async `recv_from`
    /// (which properly manages kqueue readiness), then drain additional
    /// queued packets with non-blocking `recvmsg_x` on the raw fd.
    ///
    /// This avoids the readiness spin bug where `readable().await` + raw fd
    /// syscall bypasses tokio's readiness tracking: after the first packet,
    /// readiness is never cleared, so `readable()` resolves immediately on
    /// every loop iteration even when no data is available.
    async fn read_batch(
        &self,
        bufs: &mut [Vec<u8>],
        max: usize,
    ) -> Result<Vec<(usize, MacosEndpoint)>, Self::Error> {
        if max == 0 || bufs.is_empty() {
            return Ok(Vec::new());
        }

        // Step 1: Block-wait for the first packet via tokio's async recv.
        // This properly manages kqueue readiness (clears it on WouldBlock).
        let (first_len, first_addr) = self.socket.recv_from(&mut bufs[0]).await?;
        let mut results = vec![(first_len, MacosEndpoint::from_address(first_addr))];

        // Step 2: Drain additional queued packets via non-blocking batch recv.
        // This avoids one-syscall-per-packet when the queue has depth > 1.
        if max > 1 && bufs.len() > 1 {
            let fd = self.socket.as_raw_fd();
            let remaining = (max - 1).min(bufs.len() - 1);

            if let Ok(extra) = self.batch_io.recv_batch(fd, &mut bufs[1..], remaining) {
                for (n, addr) in extra {
                    results.push((n, MacosEndpoint::from_address(addr)));
                }
            }
        }

        Ok(results)
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

        // Increase socket buffers to 7 MB for high-throughput batch I/O.
        // Default macOS buffers are too small and cause drops under load.
        // 7MB matches wireguard-go's target (PR #64) and provides ~175ms of
        // buffering at 400 Mbps with 1420-byte packets. Requires
        // kern.ipc.maxsockbuf >= 8MB (set in tun.rs at startup).
        let buf_size: libc::c_int = 7_340_032;
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

            // Verify the kernel accepted the requested buffer sizes.
            // macOS silently clamps to kern.ipc.maxsockbuf/2 if the
            // request exceeds the limit. Log a warning when the actual
            // size is less than half what was requested.
            let mut actual_rcvbuf: libc::c_int = 0;
            let mut actual_sndbuf: libc::c_int = 0;
            let mut optlen: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut actual_rcvbuf as *mut _ as *mut libc::c_void,
                &mut optlen,
            );
            optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &mut actual_sndbuf as *mut _ as *mut libc::c_void,
                &mut optlen,
            );

            if actual_rcvbuf < buf_size / 2 {
                tracing::warn!(
                    requested = buf_size,
                    actual = actual_rcvbuf,
                    "SO_RCVBUF below half of requested — \
                     increase kern.ipc.maxsockbuf to raise the ceiling"
                );
            } else {
                tracing::debug!(actual = actual_rcvbuf, "SO_RCVBUF verified");
            }
            if actual_sndbuf < buf_size / 2 {
                tracing::warn!(
                    requested = buf_size,
                    actual = actual_sndbuf,
                    "SO_SNDBUF below half of requested — \
                     increase kern.ipc.maxsockbuf to raise the ceiling"
                );
            } else {
                tracing::debug!(actual = actual_sndbuf, "SO_SNDBUF verified");
            }
        }
        tracing::debug!("set UDP SO_RCVBUF/SO_SNDBUF to 7MB");

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
