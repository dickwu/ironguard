use crate::tun;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
#[error("dummy tun error: {0}")]
pub struct DummyTunError(pub String);

pub struct DummyTunWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

impl tun::Writer for DummyTunWriter {
    type Error = DummyTunError;
    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        self.tx
            .send(src.to_vec())
            .await
            .map_err(|e| DummyTunError(e.to_string()))
    }
}

pub struct DummyTunReader {
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl tun::Reader for DummyTunReader {
    type Error = DummyTunError;
    async fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        let packet = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| DummyTunError("channel closed".to_string()))?;
        let len = packet.len();
        buf[offset..offset + len].copy_from_slice(&packet);
        Ok(len)
    }
}

pub struct DummyTunStatus {
    rx: tokio::sync::Mutex<mpsc::Receiver<tun::TunEvent>>,
}

impl tun::Status for DummyTunStatus {
    type Error = DummyTunError;
    async fn event(&mut self) -> Result<tun::TunEvent, Self::Error> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| DummyTunError("channel closed".to_string()))
    }
}

pub struct DummyTun;

impl tun::Tun for DummyTun {
    type Writer = DummyTunWriter;
    type Reader = DummyTunReader;
    type Error = DummyTunError;
}

pub fn create_pair() -> (
    Vec<DummyTunReader>,
    DummyTunWriter,
    Vec<DummyTunReader>,
    DummyTunWriter,
) {
    let (tx_a, rx_a) = mpsc::channel(256);
    let (tx_b, rx_b) = mpsc::channel(256);
    (
        vec![DummyTunReader {
            rx: tokio::sync::Mutex::new(rx_b),
        }],
        DummyTunWriter { tx: tx_a },
        vec![DummyTunReader {
            rx: tokio::sync::Mutex::new(rx_a),
        }],
        DummyTunWriter { tx: tx_b },
    )
}
