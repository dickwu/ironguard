use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::tun;

#[derive(Debug, thiserror::Error)]
pub enum LinuxTunError {
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

pub struct LinuxTunWriter {
    inner: Arc<AsyncFd<TunDevice>>,
}

impl tun::Writer for LinuxTunWriter {
    type Error = LinuxTunError;

    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|fd| fd.get_ref().device.send(src)) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct LinuxTunReader {
    inner: Arc<AsyncFd<TunDevice>>,
}

impl tun::Reader for LinuxTunReader {
    type Error = LinuxTunError;

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

pub struct LinuxTunStatus {
    rx: mpsc::Receiver<tun::TunEvent>,
}

impl tun::Status for LinuxTunStatus {
    type Error = LinuxTunError;

    async fn event(&mut self) -> Result<tun::TunEvent, Self::Error> {
        self.rx.recv().await.ok_or(LinuxTunError::StatusClosed)
    }
}

pub struct LinuxTun;

impl tun::Tun for LinuxTun {
    type Writer = LinuxTunWriter;
    type Reader = LinuxTunReader;
    type Error = LinuxTunError;
}

impl tun::PlatformTun for LinuxTun {
    type Status = LinuxTunStatus;

    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        Self::create_with_queues(name, 1)
    }
}

impl LinuxTun {
    /// Create a TUN device with the specified number of reader queues.
    ///
    /// `queue_count` controls how many independent file descriptors (and thus
    /// readers) are created for the same TUN device. Each reader gets its own
    /// fd registered with Tokio, enabling parallel read processing across
    /// multiple async tasks.
    ///
    /// # Multi-queue expansion
    ///
    /// The Linux kernel supports multi-queue TUN devices via the
    /// `IFF_MULTI_QUEUE` flag. When `queue_count > 1`, this method would
    /// ideally create multiple fds for the same device using
    /// `ioctl(TUNSETIFF)` with `IFF_MULTI_QUEUE`. Currently, `tun-rs` does
    /// not directly expose multi-queue creation, so we create a single device
    /// and share it across readers via `Arc<AsyncFd<TunDevice>>`.
    ///
    /// To enable true multi-queue (separate fds per reader), the following
    /// would be needed:
    ///
    /// 1. Open `/dev/net/tun` multiple times
    /// 2. Call `ioctl(fd, TUNSETIFF, &ifr)` on each with `IFF_MULTI_QUEUE`
    ///    and the same interface name
    /// 3. Wrap each fd in its own `AsyncFd`
    ///
    /// For now, `queue_count` controls the number of `LinuxTunReader`
    /// instances sharing the same underlying fd, which still allows the
    /// pipeline to distribute work across multiple async tasks.
    pub fn create_with_queues(
        name: &str,
        queue_count: usize,
    ) -> Result<(Vec<LinuxTunReader>, LinuxTunWriter, LinuxTunStatus), LinuxTunError> {
        let queue_count = queue_count.max(1);

        let mut builder = tun_rs::DeviceBuilder::new();
        builder = builder.name(name);

        let device = builder
            .build_sync()
            .map_err(|e| LinuxTunError::Device(format!("failed to create TUN device: {e}")))?;

        // Set non-blocking for use with AsyncFd
        device
            .set_nonblocking(true)
            .map_err(|e| LinuxTunError::Device(format!("failed to set non-blocking: {e}")))?;

        let actual_name = device.name().unwrap_or_default();
        tracing::info!(
            interface = %actual_name,
            queues = queue_count,
            "created Linux TUN device"
        );

        let tun_device = TunDevice { device };
        let async_fd = Arc::new(
            AsyncFd::with_interest(tun_device, Interest::READABLE | Interest::WRITABLE)
                .map_err(|e| LinuxTunError::Device(format!("AsyncFd creation failed: {e}")))?,
        );

        // Create `queue_count` readers sharing the same fd.
        // With true IFF_MULTI_QUEUE support, each would have its own fd.
        let readers: Vec<LinuxTunReader> = (0..queue_count)
            .map(|_| LinuxTunReader {
                inner: Arc::clone(&async_fd),
            })
            .collect();

        let writer = LinuxTunWriter {
            inner: Arc::clone(&async_fd),
        };

        // Status channel -- the CLI will send Up/Down events
        let (tx, rx) = mpsc::channel(4);
        let status = LinuxTunStatus { rx };

        // Send an initial Up event (the device is created and ready)
        // This is done via a background task to avoid blocking
        tokio::spawn(async move {
            let _ = tx.send(tun::TunEvent::Up(1420)).await;
            // Keep tx alive so the status channel stays open.
            // It will be dropped when the task is cancelled or the
            // receiver is dropped.
            std::future::pending::<()>().await;
        });

        Ok((readers, writer, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::PlatformTun;

    #[tokio::test]
    #[ignore] // requires sudo / CAP_NET_ADMIN
    async fn test_linux_tun_create() {
        let result = LinuxTun::create("wg0");
        assert!(result.is_ok(), "TUN creation failed: {:?}", result.err());
        let (readers, _writer, _status) = result.unwrap();
        assert_eq!(readers.len(), 1);
    }

    #[tokio::test]
    #[ignore] // requires sudo / CAP_NET_ADMIN
    async fn test_linux_tun_multi_queue() {
        let result = LinuxTun::create_with_queues("wg1", 4);
        assert!(
            result.is_ok(),
            "TUN multi-queue creation failed: {:?}",
            result.err()
        );
        let (readers, _writer, _status) = result.unwrap();
        assert_eq!(readers.len(), 4, "should have 4 reader queues");
    }
}
