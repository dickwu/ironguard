use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crate::endpoint::Endpoint;
use crate::udp;

use super::endpoint::LinuxEndpoint;

#[derive(Debug, thiserror::Error)]
pub enum LinuxUdpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("udp error: {0}")]
    Udp(String),
}

pub struct LinuxUdpWriter {
    socket: Arc<tokio::net::UdpSocket>,
}

impl udp::UdpWriter<LinuxEndpoint> for LinuxUdpWriter {
    type Error = LinuxUdpError;

    async fn write(&self, buf: &[u8], dst: &mut LinuxEndpoint) -> Result<(), Self::Error> {
        self.socket.send_to(buf, dst.to_address()).await?;
        Ok(())
    }
}

pub struct LinuxUdpReader {
    socket: Arc<tokio::net::UdpSocket>,
}

impl udp::UdpReader<LinuxEndpoint> for LinuxUdpReader {
    type Error = LinuxUdpError;

    async fn read(&self, buf: &mut [u8]) -> Result<(usize, LinuxEndpoint), Self::Error> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        Ok((len, LinuxEndpoint::from_address(addr)))
    }
}

pub struct LinuxUdp;

impl udp::Udp for LinuxUdp {
    type Error = LinuxUdpError;
    type Endpoint = LinuxEndpoint;
    type Writer = LinuxUdpWriter;
    type Reader = LinuxUdpReader;
}

pub struct LinuxOwner {
    port: u16,
    socket: Arc<tokio::net::UdpSocket>,
}

impl LinuxOwner {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl udp::Owner for LinuxOwner {
    type Error = LinuxUdpError;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        let mark = value.unwrap_or(0);
        let fd = self.socket.as_raw_fd();

        // SAFETY: we pass a valid fd and a pointer to a u32 with correct size
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if ret != 0 {
            return Err(LinuxUdpError::Udp(format!(
                "setsockopt SO_MARK failed: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(())
    }
}

impl udp::PlatformUdp for LinuxUdp {
    type Owner = LinuxOwner;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

        // Create a std::net::UdpSocket first, then convert to tokio
        let std_socket = std::net::UdpSocket::bind(addr)?;
        std_socket.set_nonblocking(true)?;

        let actual_port = std_socket.local_addr()?.port();

        let socket = Arc::new(
            tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| LinuxUdpError::Udp(format!("failed to convert socket: {e}")))?,
        );

        let reader = LinuxUdpReader {
            socket: Arc::clone(&socket),
        };
        let writer = LinuxUdpWriter {
            socket: Arc::clone(&socket),
        };
        let owner = LinuxOwner {
            port: actual_port,
            socket,
        };

        tracing::info!(port = actual_port, "bound UDP socket");

        Ok((vec![reader], writer, owner))
    }
}

// ---------------------------------------------------------------------------
// Batch I/O: sendmmsg / recvmmsg
//
// These are Linux-only syscalls that send/receive multiple datagrams in a
// single kernel transition, amortizing the syscall overhead across many
// packets. This is the foundation for 10+ Gbps throughput.
// ---------------------------------------------------------------------------

/// Maximum number of messages in a single sendmmsg/recvmmsg batch.
pub const MAX_BATCH_SIZE: usize = 64;

/// Convert a `SocketAddr` to a raw `libc::sockaddr_storage` + length pair.
fn addr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sa: &mut libc::sockaddr_in = unsafe { &mut *(&raw mut storage as *mut _) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sa: &mut libc::sockaddr_in6 = unsafe { &mut *(&raw mut storage as *mut _) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sa.sin6_scope_id = v6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (storage, len)
}

/// Parse a `libc::sockaddr_storage` back into a `SocketAddr`.
///
/// Returns `None` if the address family is unrecognized.
fn raw_to_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sa: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let sa: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

/// Read multiple UDP datagrams in a single syscall using `recvmmsg(2)`.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor of the bound UDP socket.
/// * `bufs` - Mutable slice of buffers; each entry receives one datagram.
/// * `endpoints` - Output slice filled with the source address of each datagram.
///
/// Both slices must have the same length, which must be <= `MAX_BATCH_SIZE`.
///
/// # Returns
///
/// The number of datagrams actually received (may be less than `bufs.len()`).
pub fn recv_batch(
    fd: std::os::fd::RawFd,
    bufs: &mut [&mut [u8]],
    endpoints: &mut [SocketAddr],
) -> io::Result<usize> {
    let count = bufs.len().min(endpoints.len()).min(MAX_BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }

    // Allocate the per-message control structures on the stack.
    let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; count];
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
    let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(count);

    for buf in &mut bufs[..count] {
        iovecs.push(libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        });
    }

    for i in 0..count {
        let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
        hdr.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        msghdrs.push(hdr);
    }

    // SAFETY: all pointers in iovecs and msghdrs point to valid, live memory
    // whose lifetimes extend past the syscall. `fd` is a valid socket fd.
    let ret = unsafe {
        libc::recvmmsg(
            fd,
            msghdrs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(), // no timeout
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let received = ret as usize;
    for i in 0..received {
        endpoints[i] = raw_to_addr(&addrs[i])
            .unwrap_or_else(|| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));
    }

    Ok(received)
}

/// Send multiple UDP datagrams in a single syscall using `sendmmsg(2)`.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor of the bound UDP socket.
/// * `bufs` - Slice of buffers; each entry is one datagram payload.
/// * `endpoints` - Destination address for each datagram.
///
/// Both slices must have the same length, which must be <= `MAX_BATCH_SIZE`.
///
/// # Returns
///
/// The number of datagrams actually sent (may be less than `bufs.len()`).
pub fn send_batch(
    fd: std::os::fd::RawFd,
    bufs: &[&[u8]],
    endpoints: &[SocketAddr],
) -> io::Result<usize> {
    let count = bufs.len().min(endpoints.len()).min(MAX_BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }

    let mut addrs: Vec<(libc::sockaddr_storage, libc::socklen_t)> =
        endpoints[..count].iter().map(addr_to_raw).collect();

    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
    for buf in &bufs[..count] {
        iovecs.push(libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        });
    }

    let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(count);
    for i in 0..count {
        let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
        hdr.msg_hdr.msg_name = &mut addrs[i].0 as *mut _ as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = addrs[i].1;
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        msghdrs.push(hdr);
    }

    // SAFETY: all pointers in iovecs and msghdrs point to valid, live memory.
    let ret = unsafe {
        libc::sendmmsg(
            fd,
            msghdrs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::PlatformUdp;

    #[tokio::test]
    async fn test_linux_udp_bind() {
        let result = LinuxUdp::bind(0);
        assert!(result.is_ok(), "UDP bind failed: {:?}", result.err());
        let (_readers, _writer, owner) = result.unwrap();
        assert!(owner.port() > 0, "should have been assigned a port");
    }

    #[tokio::test]
    async fn test_send_batch_recv_batch_loopback() {
        // Bind two UDP sockets on loopback
        let sender_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender_std.set_nonblocking(true).unwrap();
        let sender_fd = sender_std.as_raw_fd();

        let receiver_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver_std.set_nonblocking(true).unwrap();
        let receiver_fd = receiver_std.as_raw_fd();

        let receiver_addr = receiver_std.local_addr().unwrap();

        // Prepare payloads
        let payload_a: Vec<u8> = b"batch-packet-one".to_vec();
        let payload_b: Vec<u8> = b"batch-packet-two".to_vec();
        let payload_c: Vec<u8> = b"batch-packet-three".to_vec();
        let send_bufs: Vec<&[u8]> = vec![&payload_a, &payload_b, &payload_c];
        let send_endpoints = vec![receiver_addr; 3];

        // Send batch
        let sent = send_batch(sender_fd, &send_bufs, &send_endpoints).unwrap();
        assert_eq!(sent, 3, "should have sent 3 datagrams");

        // Small delay to let the kernel deliver
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Receive batch
        let mut buf_a = vec![0u8; 256];
        let mut buf_b = vec![0u8; 256];
        let mut buf_c = vec![0u8; 256];
        let mut recv_bufs: Vec<&mut [u8]> = vec![&mut buf_a, &mut buf_b, &mut buf_c];
        let mut recv_endpoints =
            vec![SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0); 3];

        let received = recv_batch(receiver_fd, &mut recv_bufs, &mut recv_endpoints).unwrap();
        assert_eq!(received, 3, "should have received 3 datagrams");

        // Verify source address is the sender
        let sender_addr = sender_std.local_addr().unwrap();
        for ep in &recv_endpoints[..received] {
            assert_eq!(ep.ip(), sender_addr.ip());
            assert_eq!(ep.port(), sender_addr.port());
        }
    }

    #[test]
    fn test_send_batch_empty() {
        let bufs: Vec<&[u8]> = vec![];
        let endpoints: Vec<SocketAddr> = vec![];
        let result = send_batch(0, &bufs, &endpoints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_recv_batch_empty() {
        let mut bufs: Vec<&mut [u8]> = vec![];
        let mut endpoints: Vec<SocketAddr> = vec![];
        let result = recv_batch(0, &mut bufs, &mut endpoints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_addr_roundtrip_v4() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let (raw, _len) = addr_to_raw(&addr);
        let back = raw_to_addr(&raw).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_addr_roundtrip_v6() {
        let addr: SocketAddr = "[::1]:54321".parse().unwrap();
        let (raw, _len) = addr_to_raw(&addr);
        let back = raw_to_addr(&raw).unwrap();
        assert_eq!(addr, back);
    }
}
