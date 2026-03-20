use std::io;
use std::os::fd::AsRawFd;
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

pub struct MacosTunWriter {
    inner: Arc<AsyncFd<TunDevice>>,
}

impl tun::Writer for MacosTunWriter {
    type Error = MacosTunError;

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

        let tun_device = TunDevice { device };
        let async_fd = Arc::new(
            AsyncFd::with_interest(tun_device, Interest::READABLE | Interest::WRITABLE)
                .map_err(|e| MacosTunError::Device(format!("AsyncFd creation failed: {e}")))?,
        );

        let reader = MacosTunReader {
            inner: Arc::clone(&async_fd),
        };
        let writer = MacosTunWriter {
            inner: Arc::clone(&async_fd),
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
}
