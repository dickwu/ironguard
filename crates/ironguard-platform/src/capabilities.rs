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
}
