use std::net::SocketAddr;
use tokio::sync::mpsc;
use crate::endpoint::Endpoint;
use crate::udp;

#[derive(Debug, thiserror::Error)]
#[error("dummy udp error: {0}")]
pub struct DummyUdpError(pub String);

#[derive(Clone, Debug)]
pub struct DummyEndpoint {
    addr: SocketAddr,
}

impl Endpoint for DummyEndpoint {
    fn from_address(addr: SocketAddr) -> Self { Self { addr } }
    fn to_address(&self) -> SocketAddr { self.addr }
    fn clear_src(&mut self) {}
}

pub struct DummyUdpWriter {
    tx: mpsc::Sender<(Vec<u8>, DummyEndpoint)>,
}

impl udp::UdpWriter<DummyEndpoint> for DummyUdpWriter {
    type Error = DummyUdpError;
    async fn write(&self, buf: &[u8], dst: &mut DummyEndpoint) -> Result<(), Self::Error> {
        self.tx.send((buf.to_vec(), dst.clone())).await
            .map_err(|e| DummyUdpError(e.to_string()))
    }
}

pub struct DummyUdpReader {
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, DummyEndpoint)>>,
}

impl udp::UdpReader<DummyEndpoint> for DummyUdpReader {
    type Error = DummyUdpError;
    async fn read(&self, buf: &mut [u8]) -> Result<(usize, DummyEndpoint), Self::Error> {
        let (packet, endpoint) = self.rx.lock().await.recv().await
            .ok_or_else(|| DummyUdpError("channel closed".to_string()))?;
        let len = packet.len();
        buf[..len].copy_from_slice(&packet);
        Ok((len, endpoint))
    }
}

pub struct DummyUdp;

impl udp::Udp for DummyUdp {
    type Error = DummyUdpError;
    type Endpoint = DummyEndpoint;
    type Writer = DummyUdpWriter;
    type Reader = DummyUdpReader;
}

pub struct DummyOwner;

impl udp::Owner for DummyOwner {
    type Error = DummyUdpError;
    fn get_port(&self) -> u16 { 0 }
    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), Self::Error> { Ok(()) }
}

pub fn create_pair() -> (
    Vec<DummyUdpReader>, DummyUdpWriter, DummyOwner,
    Vec<DummyUdpReader>, DummyUdpWriter, DummyOwner,
) {
    let (tx_a, rx_a) = mpsc::channel(256);
    let (tx_b, rx_b) = mpsc::channel(256);
    (
        vec![DummyUdpReader { rx: tokio::sync::Mutex::new(rx_b) }],
        DummyUdpWriter { tx: tx_a },
        DummyOwner,
        vec![DummyUdpReader { rx: tokio::sync::Mutex::new(rx_a) }],
        DummyUdpWriter { tx: tx_b },
        DummyOwner,
    )
}
