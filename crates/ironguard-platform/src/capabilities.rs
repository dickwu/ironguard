/// Runtime-detected platform capabilities for I/O optimization.
///
/// Capabilities are detected once at startup and remain constant for
/// the lifetime of the process.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Whether the TUN device supports multi-queue (multiple read/write fds).
    pub tun_multi_queue: bool,
    /// Whether the TUN device supports GSO/GRO (Generic Segmentation/Receive Offload).
    pub tun_gso_gro: bool,
    /// Whether the platform supports `sendmmsg` for batched UDP sends.
    pub udp_sendmmsg: bool,
    /// Whether the platform supports UDP GSO (Generic Segmentation Offload).
    pub udp_gso: bool,
    /// Maximum number of TUN queues supported by the platform.
    pub max_tun_queues: usize,
}

impl PlatformCapabilities {
    /// Detect capabilities for the current platform.
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                tun_multi_queue: true,
                tun_gso_gro: Self::check_kernel_version(6, 2),
                udp_sendmmsg: true,
                udp_gso: true,
                max_tun_queues: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
            }
        }
        #[cfg(target_os = "macos")]
        {
            Self {
                tun_multi_queue: false,
                tun_gso_gro: false,
                udp_sendmmsg: false,
                udp_gso: false,
                max_tun_queues: 1,
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Self {
                tun_multi_queue: false,
                tun_gso_gro: false,
                udp_sendmmsg: false,
                udp_gso: false,
                max_tun_queues: 1,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn check_kernel_version(major: u32, minor: u32) -> bool {
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut utsname) } != 0 {
            return false;
        }
        let release = unsafe { std::ffi::CStr::from_ptr(utsname.release.as_ptr()) };
        let release_str = release.to_str().unwrap_or("");
        // Parse "6.2.0-xxx" style kernel version
        let mut parts = release_str.split('.');
        let kern_major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let kern_minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        (kern_major, kern_minor) >= (major, minor)
    }

    /// Check whether an existing TUN device was created with `IFF_VNET_HDR`.
    ///
    /// This queries the kernel via `ioctl(TUNGETIFF)` on `/dev/net/tun` to
    /// inspect the device flags. When `IFF_VNET_HDR` is set, the device
    /// prepends a `virtio_net_hdr` to every packet, enabling GSO/GRO.
    ///
    /// Returns `false` as a safe default if detection fails (e.g., the device
    /// does not exist, or the process lacks `CAP_NET_ADMIN`).
    ///
    /// # Platform
    ///
    /// Linux only. Requires the TUN device to already exist.
    #[cfg(target_os = "linux")]
    pub fn tun_supports_vnet_hdr(tun_name: &str) -> bool {
        // IFF_VNET_HDR = 0x4000 (from linux/if_tun.h)
        const IFF_VNET_HDR: libc::c_short = 0x4000;
        // TUNGETIFF = _IOR('T', 210, sizeof(struct ifreq))
        // On Linux amd64: 0x800454D2
        const TUNGETIFF: libc::c_ulong = 0x800454D2;

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return false;
        }

        // struct ifreq is 40 bytes; we only need the first 16 (name) + 2 (flags)
        let mut ifr = [0u8; 40];
        let name_bytes = tun_name.as_bytes();
        let copy_len = name_bytes.len().min(15); // IFNAMSIZ - 1
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // SAFETY: ifr is a valid stack buffer of the right size for struct ifreq,
        // and fd is a valid open file descriptor for /dev/net/tun.
        let ret = unsafe { libc::ioctl(fd, TUNGETIFF, ifr.as_mut_ptr()) };
        unsafe { libc::close(fd) };

        if ret < 0 {
            return false;
        }

        // ifr_flags is at offset 16 in struct ifreq (a c_short = i16)
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        (flags & IFF_VNET_HDR) != 0
    }

    /// Non-Linux stub: always returns `false`.
    #[cfg(not(target_os = "linux"))]
    pub fn tun_supports_vnet_hdr(_tun_name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_valid_capabilities() {
        let caps = PlatformCapabilities::detect();
        assert!(caps.max_tun_queues >= 1);
    }

    #[test]
    fn test_detect_is_deterministic() {
        let a = PlatformCapabilities::detect();
        let b = PlatformCapabilities::detect();
        assert_eq!(a.tun_multi_queue, b.tun_multi_queue);
        assert_eq!(a.tun_gso_gro, b.tun_gso_gro);
        assert_eq!(a.udp_sendmmsg, b.udp_sendmmsg);
        assert_eq!(a.udp_gso, b.udp_gso);
        assert_eq!(a.max_tun_queues, b.max_tun_queues);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_capabilities() {
        let caps = PlatformCapabilities::detect();
        assert!(!caps.tun_multi_queue);
        assert!(!caps.tun_gso_gro);
        assert!(!caps.udp_sendmmsg);
        assert!(!caps.udp_gso);
        assert_eq!(caps.max_tun_queues, 1);
    }

    #[test]
    fn test_vnet_hdr_nonexistent_device() {
        // Querying a device that does not exist should return false, not panic.
        let result = PlatformCapabilities::tun_supports_vnet_hdr("nonexistent99");
        assert!(!result);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_vnet_hdr_non_linux_always_false() {
        assert!(!PlatformCapabilities::tun_supports_vnet_hdr("wg0"));
        assert!(!PlatformCapabilities::tun_supports_vnet_hdr(""));
    }
}
