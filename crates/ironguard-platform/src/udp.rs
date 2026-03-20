use std::error::Error;
use std::future::Future;

use super::endpoint::Endpoint;

pub trait UdpReader<E: Endpoint>: Send + Sync {
    type Error: Error;
    fn read(&self, buf: &mut [u8]) -> impl Future<Output = Result<(usize, E), Self::Error>> + Send;
}

pub trait UdpWriter<E: Endpoint>: Send + Sync + 'static {
    type Error: Error;
    fn write(&self, buf: &[u8], dst: &mut E) -> impl Future<Output = Result<(), Self::Error>> + Send;
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
