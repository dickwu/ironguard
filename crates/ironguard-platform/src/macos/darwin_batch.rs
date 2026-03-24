//! Darwin-specific batch UDP I/O via sendmsg_x/recvmsg_x.
//!
//! These are undocumented XNU syscalls (#480/#481) available since macOS 10.11.
//! They batch up to 100 UDP datagrams per syscall, analogous to Linux's
//! sendmmsg/recvmmsg.
//!
//! Safety: resolved at runtime via dlsym to gracefully degrade if Apple
//! removes them in a future macOS release.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;

/// Darwin `msghdr_x` struct from XNU `bsd/sys/socket_private.h`.
#[repr(C)]
pub struct MsghdrX {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: libc::socklen_t,
    pub msg_iov: *mut libc::iovec,
    pub msg_iovlen: libc::c_int,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: libc::socklen_t,
    pub msg_flags: libc::c_int,
    pub msg_datalen: usize,
}

type SendmsgXFn =
    unsafe extern "C" fn(libc::c_int, *const MsghdrX, libc::c_uint, libc::c_int) -> libc::ssize_t;

type RecvmsgXFn =
    unsafe extern "C" fn(libc::c_int, *mut MsghdrX, libc::c_uint, libc::c_int) -> libc::ssize_t;

/// Runtime-resolved batch syscall function pointers.
/// `None` if the symbols are not available (future macOS removal).
pub struct DarwinBatchIo {
    sendmsg_x: Option<SendmsgXFn>,
    recvmsg_x: Option<RecvmsgXFn>,
}

impl DarwinBatchIo {
    /// Probe for sendmsg_x/recvmsg_x via dlsym. Returns an instance
    /// with `None` function pointers if the symbols are not found.
    pub fn probe() -> Self {
        unsafe {
            let send_sym = libc::dlsym(libc::RTLD_DEFAULT, c"sendmsg_x".as_ptr());
            let recv_sym = libc::dlsym(libc::RTLD_DEFAULT, c"recvmsg_x".as_ptr());
            Self {
                sendmsg_x: if send_sym.is_null() {
                    None
                } else {
                    Some(std::mem::transmute::<*mut libc::c_void, SendmsgXFn>(
                        send_sym,
                    ))
                },
                recvmsg_x: if recv_sym.is_null() {
                    None
                } else {
                    Some(std::mem::transmute::<*mut libc::c_void, RecvmsgXFn>(
                        recv_sym,
                    ))
                },
            }
        }
    }

    /// Returns true if batch syscalls are available.
    pub fn is_available(&self) -> bool {
        self.sendmsg_x.is_some() && self.recvmsg_x.is_some()
    }

    /// Send multiple datagrams in a single syscall.
    /// Returns the number of messages sent, or falls back to
    /// looped sendto if batch is unavailable.
    pub fn send_batch(&self, fd: RawFd, msgs: &[(Vec<u8>, SocketAddr)]) -> io::Result<usize> {
        if let Some(sendmsg_x) = self.sendmsg_x {
            self.send_batch_x(sendmsg_x, fd, msgs)
        } else {
            self.send_batch_fallback(fd, msgs)
        }
    }

    /// Receive multiple datagrams in a single syscall.
    /// Returns Vec of (bytes_received, source_addr).
    pub fn recv_batch(
        &self,
        fd: RawFd,
        bufs: &mut [Vec<u8>],
        max: usize,
    ) -> io::Result<Vec<(usize, SocketAddr)>> {
        if let Some(recvmsg_x) = self.recvmsg_x {
            self.recv_batch_x(recvmsg_x, fd, bufs, max)
        } else {
            self.recv_batch_fallback(fd, bufs, max)
        }
    }

    fn send_batch_x(
        &self,
        sendmsg_x: SendmsgXFn,
        fd: RawFd,
        msgs: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }

        let count = msgs.len().min(100); // XNU default limit
        let mut headers: Vec<MsghdrX> = Vec::with_capacity(count);
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
        let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(count);
        let mut addr_lens: Vec<libc::socklen_t> = Vec::with_capacity(count);

        for (data, addr) in msgs.iter().take(count) {
            iovecs.push(libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            });

            let (sa, sa_len) = socket_addr_to_raw(addr);
            addrs.push(sa);
            addr_lens.push(sa_len);
        }

        for i in 0..count {
            headers.push(MsghdrX {
                msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                msg_namelen: addr_lens[i],
                msg_iov: &mut iovecs[i] as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            });
        }

        let sent = unsafe { sendmsg_x(fd, headers.as_ptr(), count as libc::c_uint, 0) };

        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }

    fn send_batch_fallback(&self, fd: RawFd, msgs: &[(Vec<u8>, SocketAddr)]) -> io::Result<usize> {
        let mut sent = 0;
        for (data, addr) in msgs {
            let (sa, sa_len) = socket_addr_to_raw(addr);
            let n = unsafe {
                libc::sendto(
                    fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                    &sa as *const _ as *const libc::sockaddr,
                    sa_len,
                )
            };
            if n < 0 {
                if sent == 0 {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            sent += 1;
        }
        Ok(sent)
    }

    fn recv_batch_x(
        &self,
        recvmsg_x: RecvmsgXFn,
        fd: RawFd,
        bufs: &mut [Vec<u8>],
        max: usize,
    ) -> io::Result<Vec<(usize, SocketAddr)>> {
        let count = max.min(bufs.len()).min(100);
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut headers: Vec<MsghdrX> = Vec::with_capacity(count);
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
        let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; count];

        for buf in bufs.iter_mut().take(count) {
            iovecs.push(libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            });
        }

        for i in 0..count {
            headers.push(MsghdrX {
                msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                msg_iov: &mut iovecs[i] as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            });
        }

        let received = unsafe { recvmsg_x(fd, headers.as_mut_ptr(), count as libc::c_uint, 0) };

        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut results = Vec::with_capacity(received as usize);
        for header in headers.iter().take(received as usize) {
            let bytes_received = header.msg_datalen;
            let src = raw_to_socket_addr(&addrs[results.len()])
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            results.push((bytes_received, src));
        }

        Ok(results)
    }

    fn recv_batch_fallback(
        &self,
        fd: RawFd,
        bufs: &mut [Vec<u8>],
        max: usize,
    ) -> io::Result<Vec<(usize, SocketAddr)>> {
        // Single-packet fallback
        if bufs.is_empty() || max == 0 {
            return Ok(Vec::new());
        }
        let buf = &mut bufs[0];
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let src = raw_to_socket_addr(&addr).unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        Ok(vec![(n as usize, src)])
    }
}

/// Query `SO_NUMRCVPKT` -- number of datagrams queued in receive buffer.
/// Returns `None` if the syscall fails (non-macOS or unsupported).
pub fn pending_recv_count(fd: RawFd) -> Option<u32> {
    const SO_NUMRCVPKT: libc::c_int = 0x1112;
    let mut count: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_NUMRCVPKT,
            &mut count as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 { Some(count as u32) } else { None }
}

// --- Helper functions for sockaddr conversion ---

fn socket_addr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in = unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 = unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn raw_to_socket_addr(sa: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match sa.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe { &*(sa as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr).to_be_bytes());
            Some(SocketAddr::new(ip.into(), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 = unsafe { &*(sa as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlsym_probe_succeeds_on_macos() {
        let batch = DarwinBatchIo::probe();
        // On macOS 10.11+, both should resolve
        assert!(
            batch.is_available(),
            "sendmsg_x/recvmsg_x should be available on macOS 10.11+"
        );
    }

    #[test]
    fn test_msghdr_x_size() {
        // Verify struct layout matches XNU definition
        // On 64-bit: 8 + 4 + 8 + 4 + 8 + 4 + 4 + 8 = ~48-56 bytes (with alignment)
        assert!(
            std::mem::size_of::<MsghdrX>() >= 48,
            "MsghdrX should be at least 48 bytes"
        );
    }

    #[test]
    fn test_sockaddr_roundtrip_v4() {
        let addr: SocketAddr = "10.0.0.1:51820".parse().unwrap();
        let (raw, len) = socket_addr_to_raw(&addr);
        assert!(len > 0);
        let recovered = raw_to_socket_addr(&raw).expect("should parse back");
        assert_eq!(recovered, addr);
    }

    #[test]
    fn test_sockaddr_roundtrip_v6() {
        let addr: SocketAddr = "[::1]:51820".parse().unwrap();
        let (raw, len) = socket_addr_to_raw(&addr);
        assert!(len > 0);
        let recovered = raw_to_socket_addr(&raw).expect("should parse back");
        assert_eq!(recovered, addr);
    }

    #[test]
    fn test_send_batch_empty_input() {
        let batch = DarwinBatchIo::probe();
        // Should handle empty input gracefully regardless of availability
        let result = batch.send_batch(-1, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_recv_batch_empty_input() {
        let batch = DarwinBatchIo::probe();
        let mut bufs: Vec<Vec<u8>> = Vec::new();
        let result = batch.recv_batch(-1, &mut bufs, 0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
