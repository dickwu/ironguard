use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::tun;

#[derive(Debug, thiserror::Error)]
pub enum MacosTunError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("tun device error: {0}")]
    Device(String),
    #[error("status channel closed")]
    StatusClosed,
}

/// Wrapper around `tun_rs::SyncDevice` that implements `AsRawFd` so it can
/// be registered with `AsyncFd`.
struct TunDevice {
    device: tun_rs::SyncDevice,
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.device.as_raw_fd()
    }
}

/// A duplicated file descriptor wrapped in an `OwnedFd`.
///
/// This newtype exists so we can register a dup'd fd with `AsyncFd`,
/// which requires `AsRawFd`. The `OwnedFd` ensures the descriptor is
/// closed on drop.
struct DupFd {
    fd: OwnedFd,
}

impl AsRawFd for DupFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Duplicate a raw file descriptor via `libc::dup()` and set the result
/// non-blocking. Returns an error if `dup()` fails or `fcntl` fails.
fn dup_nonblocking(raw: RawFd) -> Result<DupFd, MacosTunError> {
    // Safety: raw is a valid open fd obtained from TunDevice.
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd == -1 {
        return Err(MacosTunError::Device(format!(
            "dup() failed: {}",
            io::Error::last_os_error()
        )));
    }

    // Safety: new_fd is a valid descriptor just returned by dup().
    let owned = unsafe { OwnedFd::from_raw_fd(new_fd) };

    // Set non-blocking via fcntl.
    let flags = unsafe { libc::fcntl(new_fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(MacosTunError::Device(format!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        )));
    }
    let rc = unsafe { libc::fcntl(new_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc == -1 {
        return Err(MacosTunError::Device(format!(
            "fcntl(F_SETFL, O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(DupFd { fd: owned })
}

pub struct MacosTunWriter {
    inner: Arc<AsyncFd<DupFd>>,
    /// Keep the original device alive so the underlying TUN interface is not
    /// torn down while the writer is still in use.
    _device: Arc<AsyncFd<TunDevice>>,
}

impl tun::Writer for MacosTunWriter {
    type Error = MacosTunError;

    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|fd| {
                let n = unsafe {
                    libc::write(
                        fd.get_ref().as_raw_fd(),
                        src.as_ptr() as *const libc::c_void,
                        src.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct MacosTunReader {
    inner: Arc<AsyncFd<TunDevice>>,
}

impl tun::Reader for MacosTunReader {
    type Error = MacosTunError;

    async fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|fd| fd.get_ref().device.recv(&mut buf[offset..])) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct MacosTunStatus {
    rx: mpsc::Receiver<tun::TunEvent>,
}

impl tun::Status for MacosTunStatus {
    type Error = MacosTunError;

    async fn event(&mut self) -> Result<tun::TunEvent, Self::Error> {
        self.rx.recv().await.ok_or(MacosTunError::StatusClosed)
    }
}

pub struct MacosTun;

impl tun::Tun for MacosTun {
    type Writer = MacosTunWriter;
    type Reader = MacosTunReader;
    type Error = MacosTunError;
}

impl tun::PlatformTun for MacosTun {
    type Status = MacosTunStatus;

    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        // tun-rs requires utun names on macOS
        let tun_name = if name.starts_with("utun") {
            name.to_string()
        } else {
            // Map non-utun names (e.g. "wg0") to auto-assigned utun
            tracing::info!(
                requested_name = %name,
                "macOS requires utun names; using auto-assignment"
            );
            String::new()
        };

        let mut builder = tun_rs::DeviceBuilder::new();
        if !tun_name.is_empty() {
            builder = builder.name(&tun_name);
        }

        let device = builder
            .build_sync()
            .map_err(|e| MacosTunError::Device(format!("failed to create TUN device: {e}")))?;

        // Set non-blocking for use with AsyncFd
        device
            .set_nonblocking(true)
            .map_err(|e| MacosTunError::Device(format!("failed to set non-blocking: {e}")))?;

        let actual_name = device.name().unwrap_or_default();
        tracing::info!(interface = %actual_name, "created macOS utun device");

        let raw_fd = device.as_raw_fd();

        let tun_device = TunDevice { device };
        let read_fd = Arc::new(
            AsyncFd::with_interest(tun_device, Interest::READABLE).map_err(|e| {
                MacosTunError::Device(format!("AsyncFd creation (reader) failed: {e}"))
            })?,
        );

        // Duplicate the fd for the writer so read and write have independent
        // kqueue registrations, avoiding edge-triggered readiness contention.
        let dup_fd = dup_nonblocking(raw_fd)?;
        let write_fd = Arc::new(AsyncFd::with_interest(dup_fd, Interest::WRITABLE).map_err(
            |e| MacosTunError::Device(format!("AsyncFd creation (writer) failed: {e}")),
        )?);

        let reader = MacosTunReader {
            inner: Arc::clone(&read_fd),
        };
        let writer = MacosTunWriter {
            inner: write_fd,
            _device: Arc::clone(&read_fd),
        };

        // Status channel -- the CLI will send Up/Down events
        let (tx, rx) = mpsc::channel(4);
        let status = MacosTunStatus { rx };

        // Send an initial Up event (the device is created and ready)
        // This is done via a background task to avoid blocking
        tokio::spawn(async move {
            let _ = tx.send(tun::TunEvent::Up(1420)).await;
            // Keep tx alive so the status channel stays open.
            // It will be dropped when the task is cancelled or the
            // receiver is dropped.
            std::future::pending::<()>().await;
        });

        Ok((vec![reader], writer, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::PlatformTun;

    #[tokio::test]
    #[ignore] // requires sudo
    async fn test_macos_tun_create() {
        let result = MacosTun::create("utun99");
        assert!(result.is_ok(), "TUN creation failed: {:?}", result.err());
        let (readers, _writer, _status) = result.unwrap();
        assert_eq!(readers.len(), 1);
    }

    #[test]
    fn test_dup_nonblocking_creates_distinct_fd() {
        // Use a pipe to get a valid fd without needing a TUN device.
        let mut fds: [libc::c_int; 2] = [0; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed");

        let read_fd = fds[0];
        let _write_fd = fds[1];

        let result = dup_nonblocking(read_fd);
        assert!(result.is_ok(), "dup_nonblocking failed: {:?}", result.err());

        let dup = result.unwrap();
        let dup_raw = dup.as_raw_fd();

        // The dup'd fd must be different from the original.
        assert_ne!(dup_raw, read_fd);

        // The dup'd fd must be non-blocking.
        let flags = unsafe { libc::fcntl(dup_raw, libc::F_GETFL) };
        assert_ne!(flags, -1, "fcntl(F_GETFL) failed");
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "dup'd fd should be non-blocking"
        );

        // Clean up the pipe fds (dup is closed via OwnedFd drop).
        unsafe {
            libc::close(read_fd);
            libc::close(_write_fd);
        }
    }

    #[test]
    fn test_dup_nonblocking_invalid_fd_returns_error() {
        let result = dup_nonblocking(-1);
        assert!(result.is_err(), "dup_nonblocking should fail with fd -1");
    }
}
