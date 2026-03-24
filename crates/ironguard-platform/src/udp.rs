use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;

use super::endpoint::Endpoint;

pub trait UdpReader<E: Endpoint>: Send + Sync {
    type Error: Error;
    fn read(&self, buf: &mut [u8]) -> impl Future<Output = Result<(usize, E), Self::Error>> + Send;

    /// Receive multiple datagrams in a batch.
    ///
    /// Waits for at least one datagram, then attempts to read up to `max`
    /// datagrams. Each received datagram is truncated in `bufs` and its
    /// source endpoint is returned.
    ///
    /// The default implementation reads a single datagram via `read()`.
    /// Platform-specific implementations (e.g. macOS recvmsg_x, Linux
    /// recvmmsg) override this with a single-syscall batch receive.
    ///
    /// Returns a Vec of (bytes_received, source_endpoint) pairs.
    fn read_batch<'a>(
        &'a self,
        bufs: &'a mut [Vec<u8>],
        _max: usize,
    ) -> impl Future<Output = Result<Vec<(usize, E)>, Self::Error>> + Send + 'a {
        async move {
            // Default: read a single packet using the first buffer.
            if bufs.is_empty() {
                return Ok(Vec::new());
            }
            let (n, ep) = self.read(&mut bufs[0]).await?;
            Ok(vec![(n, ep)])
        }
    }

    /// Query the number of datagrams queued in the receive buffer.
    ///
    /// Returns `None` if the platform does not support this query.
    /// Used to size the batch for `read_batch`.
    fn pending_recv_count(&self) -> Option<u32> {
        None
    }
}

pub trait UdpWriter<E: Endpoint>: Send + Sync + 'static {
    type Error: Error;
    fn write(
        &self,
        buf: &[u8],
        dst: &mut E,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Send multiple datagrams in a batch, returning the number sent.
    ///
    /// The default implementation falls back to individual `write()` calls.
    /// Platform-specific implementations (e.g. macOS sendmsg_x, Linux
    /// sendmmsg) override this with a single-syscall batch send.
    fn write_batch<'a>(
        &'a self,
        msgs: &'a [(Vec<u8>, SocketAddr)],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send + 'a
    where
        E: Endpoint,
    {
        async move {
            let mut sent = 0usize;
            for (buf, addr) in msgs {
                let mut ep = E::from_address(*addr);
                match self.write(buf, &mut ep).await {
                    Ok(()) => sent += 1,
                    Err(e) => {
                        if sent == 0 {
                            return Err(e);
                        }
                        break;
                    }
                }
            }
            Ok(sent)
        }
    }
}

pub trait Udp: Send + Sync + 'static {
    type Error: Error;
    type Endpoint: Endpoint;
    type Writer: UdpWriter<Self::Endpoint>;
    type Reader: UdpReader<Self::Endpoint>;
}

pub trait Owner: Send {
    type Error: Error;
    fn get_port(&self) -> u16;
    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error>;
}

pub trait PlatformUdp: Udp {
    type Owner: Owner;
    #[allow(clippy::type_complexity)]
    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error>;
}
