// Transport-layer batch I/O abstraction.
//
// This trait decouples the pipeline from the underlying transport mechanism.
// Raw UDP (with sendmmsg/recvmmsg on Linux, sendto/recvfrom elsewhere) and
// QUIC implement this trait differently, but the pipeline treats them
// uniformly through the same batch-oriented interface.

use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;

use super::pool::{BufferPool, PacketRef};

/// Metadata associated with a received packet.
///
/// Carries the source endpoint so the router can update peer addresses
/// and the pipeline can route responses back.
#[derive(Clone, Debug)]
pub struct RecvMeta {
    /// Source address of the received datagram.
    pub src: SocketAddr,
    /// Number of bytes received (redundant with PacketRef.len but useful
    /// for callers that only have the meta, not the PacketRef).
    pub len: usize,
}

/// Transport-layer batch I/O interface.
///
/// Raw UDP and QUIC implement this differently. The pipeline uses this
/// trait to read and send packets in batches, amortizing syscall overhead.
///
/// Implementations must be `Send + Sync + 'static` so they can be shared
/// across async tasks.
pub trait TransportIO: Send + Sync + 'static {
    /// Error type for I/O operations.
    type Error: Error + Send + Sync;

    /// Read up to `max` packets from the transport into the buffer pool.
    ///
    /// For each received datagram:
    /// 1. Allocates a buffer from `pool`
    /// 2. Reads the datagram into that buffer
    /// 3. Pushes a `PacketRef` into `batch` and a `RecvMeta` into `meta`
    ///
    /// Returns the number of datagrams actually received.
    ///
    /// Implementations should use platform-optimal batch reads where
    /// available (e.g., `recvmmsg` on Linux).
    fn recv_batch(
        &self,
        pool: &BufferPool,
        batch: &mut Vec<PacketRef>,
        meta: &mut Vec<RecvMeta>,
        max: usize,
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;

    /// Send all packets in the batch through the transport.
    ///
    /// Each `PacketRef` references a buffer in `pool` containing the
    /// datagram payload. `destinations` provides the target address for
    /// each packet (parallel array with `batch`).
    ///
    /// Returns the number of datagrams actually sent.
    ///
    /// Implementations should use platform-optimal batch sends where
    /// available (e.g., `sendmmsg` on Linux).
    fn send_batch(
        &self,
        pool: &BufferPool,
        batch: &[PacketRef],
        destinations: &[SocketAddr],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;

    /// Query the number of datagrams pending in the receive buffer.
    ///
    /// Returns `None` if the platform does not support this query.
    /// On macOS, implementations can use `SO_NUMRCVPKT` to query the
    /// kernel for the exact datagram count, enabling adaptive batch
    /// sizing (allocate exactly as many buffers as there are packets).
    /// On Linux, this is not supported and returns `None`.
    ///
    /// The default implementation returns `None`.
    fn pending_recv(&self) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::pool::{BufferPool, PacketRef};
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A dummy TransportIO implementation for testing.
    ///
    /// Stores packets in memory instead of doing real I/O, allowing
    /// the trait contract to be verified without sockets.
    struct DummyTransport {
        recv_count: AtomicUsize,
        send_count: AtomicUsize,
    }

    impl DummyTransport {
        fn new() -> Self {
            Self {
                recv_count: AtomicUsize::new(0),
                send_count: AtomicUsize::new(0),
            }
        }
    }

    impl TransportIO for DummyTransport {
        type Error = io::Error;

        async fn recv_batch(
            &self,
            pool: &BufferPool,
            batch: &mut Vec<PacketRef>,
            meta: &mut Vec<RecvMeta>,
            max: usize,
        ) -> Result<usize, Self::Error> {
            // Simulate receiving up to `max` packets
            let to_recv = max.min(3);
            for i in 0..to_recv {
                let mut guard = pool
                    .alloc_small()
                    .ok_or_else(|| io::Error::other("pool exhausted"))?;
                let payload = format!("dummy-packet-{i}");
                let payload_bytes = payload.as_bytes();
                guard.as_mut()[..payload_bytes.len()].copy_from_slice(payload_bytes);
                batch.push(PacketRef {
                    pool_idx: guard.pool_idx(),
                    offset: 0,
                    len: payload_bytes.len() as u16,
                    peer_idx: 0,
                });
                meta.push(RecvMeta {
                    src: "127.0.0.1:12345".parse().unwrap(),
                    len: payload_bytes.len(),
                });
                // Intentionally leak the guard so the pool index stays valid
                // for the duration of the test. In production, ownership
                // transfers to the pipeline.
                std::mem::forget(guard);
            }
            self.recv_count.fetch_add(to_recv, Ordering::Relaxed);
            Ok(to_recv)
        }

        async fn send_batch(
            &self,
            _pool: &BufferPool,
            batch: &[PacketRef],
            _destinations: &[SocketAddr],
        ) -> Result<usize, Self::Error> {
            let count = batch.len();
            self.send_count.fetch_add(count, Ordering::Relaxed);
            Ok(count)
        }
    }

    #[tokio::test]
    async fn test_dummy_recv_batch() {
        let transport = DummyTransport::new();
        let pool = BufferPool::new();
        let mut batch = Vec::new();
        let mut meta = Vec::new();

        let received = transport
            .recv_batch(&pool, &mut batch, &mut meta, 10)
            .await
            .unwrap();

        assert_eq!(received, 3, "dummy transport returns at most 3 packets");
        assert_eq!(batch.len(), 3);
        assert_eq!(meta.len(), 3);

        // Verify the packet data is accessible through the pool
        for (i, pref) in batch.iter().enumerate() {
            let buf = pool.get(pref.pool_idx);
            let expected = format!("dummy-packet-{i}");
            assert_eq!(
                &buf[..pref.len as usize],
                expected.as_bytes(),
                "packet {i} payload mismatch"
            );
        }

        assert_eq!(transport.recv_count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_dummy_send_batch() {
        let transport = DummyTransport::new();
        let pool = BufferPool::new();
        let batch = vec![
            PacketRef {
                pool_idx: 0,
                offset: 0,
                len: 100,
                peer_idx: 0,
            },
            PacketRef {
                pool_idx: 1,
                offset: 0,
                len: 200,
                peer_idx: 0,
            },
        ];
        let destinations = vec![
            "10.0.0.1:51820".parse().unwrap(),
            "10.0.0.2:51820".parse().unwrap(),
        ];

        let sent = transport
            .send_batch(&pool, &batch, &destinations)
            .await
            .unwrap();

        assert_eq!(sent, 2);
        assert_eq!(transport.send_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_recv_batch_zero_max() {
        let transport = DummyTransport::new();
        let pool = BufferPool::new();
        let mut batch = Vec::new();
        let mut meta = Vec::new();

        let received = transport
            .recv_batch(&pool, &mut batch, &mut meta, 0)
            .await
            .unwrap();

        assert_eq!(received, 0);
        assert!(batch.is_empty());
        assert!(meta.is_empty());
    }

    #[tokio::test]
    async fn test_send_batch_empty() {
        let transport = DummyTransport::new();
        let pool = BufferPool::new();

        let sent = transport.send_batch(&pool, &[], &[]).await.unwrap();

        assert_eq!(sent, 0);
    }

    /// Verify the trait is object-safe enough for our use case by ensuring
    /// the concrete type satisfies Send + Sync + 'static.
    #[test]
    fn test_transport_io_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<DummyTransport>();
    }

    #[test]
    fn test_pending_recv_default_returns_none() {
        let transport = DummyTransport::new();
        // Default implementation should return None
        assert_eq!(transport.pending_recv(), None);
    }

    /// A transport that overrides pending_recv to return a count.
    struct MockCountTransport {
        pending: u32,
    }

    impl TransportIO for MockCountTransport {
        type Error = io::Error;

        async fn recv_batch(
            &self,
            _pool: &BufferPool,
            _batch: &mut Vec<PacketRef>,
            _meta: &mut Vec<RecvMeta>,
            _max: usize,
        ) -> Result<usize, Self::Error> {
            Ok(0)
        }

        async fn send_batch(
            &self,
            _pool: &BufferPool,
            _batch: &[PacketRef],
            _destinations: &[SocketAddr],
        ) -> Result<usize, Self::Error> {
            Ok(0)
        }

        fn pending_recv(&self) -> Option<u32> {
            Some(self.pending)
        }
    }

    #[test]
    fn test_pending_recv_custom_impl() {
        let transport = MockCountTransport { pending: 42 };
        assert_eq!(transport.pending_recv(), Some(42));
    }
}
