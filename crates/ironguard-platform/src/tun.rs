use std::error::Error;
use std::future::Future;

#[derive(Debug, Clone, Copy)]
pub enum TunEvent {
    Up(usize),
    Down,
}

pub trait Status: Send + 'static {
    type Error: Error;
    fn event(&mut self) -> impl Future<Output = Result<TunEvent, Self::Error>> + Send;
}

pub trait Writer: Send + Sync + 'static {
    type Error: Error;
    fn write(&self, src: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Attempt a non-blocking write. Returns `Err` with `WouldBlock` if the
    /// device is not immediately ready. The default implementation always
    /// returns `WouldBlock` so that implementations that do not support
    /// non-blocking writes fall back gracefully to the async path.
    fn try_write(&self, _src: &[u8]) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
}

pub trait Reader: Send + 'static {
    type Error: Error;
    fn read(
        &self,
        buf: &mut [u8],
        offset: usize,
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;
}

pub trait Tun: Send + Sync + 'static {
    type Writer: Writer;
    type Reader: Reader;
    type Error: Error;
}

pub trait PlatformTun: Tun {
    type Status: Status;
    #[allow(clippy::type_complexity)]
    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error>;
}
