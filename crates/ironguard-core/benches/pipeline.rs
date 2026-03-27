use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use ironguard_core::constants::SIZE_MESSAGE_PREFIX;
use ironguard_core::router::device::DeviceHandle;
use ironguard_core::router::types::Callbacks;
use ironguard_core::types::{CachedAeadKey, Key, KeyPair};
use ironguard_core::workers::{tun_write_worker, udp_write_worker};

use ironguard_platform::dummy::tun as dummy_tun;
use ironguard_platform::dummy::udp as dummy_udp;
use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::udp::UdpReader;

// ---------------------------------------------------------------------------
// Existing benchmarks
// ---------------------------------------------------------------------------

fn bench_buffer_pool_alloc_free(c: &mut Criterion) {
    use ironguard_core::pipeline::pool::BufferPool;
    let pool = BufferPool::new();
    c.bench_function("buffer_pool_alloc_free", |b| {
        b.iter(|| {
            let guard = pool.alloc_small().unwrap();
            black_box(guard.pool_idx());
        });
    });
}

fn bench_aes_gcm_seal_1500(c: &mut Criterion) {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key_bytes = [0x42u8; 32];
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let nonce_bytes = [0u8; 12];

    c.bench_function("aes_256_gcm_seal_1500", |b| {
        let mut buf = vec![0u8; 1500];
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf)
                .unwrap();
            let _ = black_box(tag);
        });
    });
}

fn bench_aes_gcm_open_1500(c: &mut Criterion) {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key_bytes = [0x42u8; 32];

    // Seal first to get valid ciphertext
    let seal_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let mut buf = vec![0u8; 1500 + 16]; // payload + tag space
    buf[..1500].fill(0xAA);
    let nonce_bytes = [0u8; 12];
    let tag = seal_key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut buf[..1500],
        )
        .unwrap();
    buf[1500..].copy_from_slice(tag.as_ref());

    let open_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());

    c.bench_function("aes_256_gcm_open_1500", |b| {
        b.iter(|| {
            let mut test_buf = buf.clone();
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let result = open_key.open_in_place(nonce, Aad::empty(), &mut test_buf);
            let _ = black_box(result);
        });
    });
}

// ---------------------------------------------------------------------------
// Pipeline benchmark helpers
// ---------------------------------------------------------------------------

type BenchRouter = DeviceHandle<
    dummy_udp::DummyEndpoint,
    BenchCallbacks,
    dummy_tun::DummyTunWriter,
    dummy_udp::DummyUdpWriter,
>;

/// Lightweight event tracker for benchmark callbacks.
struct EventTracker<E> {
    rx: Mutex<Receiver<E>>,
    tx: Mutex<Sender<E>>,
}

impl<E> EventTracker<E> {
    fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
        }
    }

    fn log(&self, e: E) {
        let _ = self.tx.lock().unwrap().send(e);
    }

    fn wait(&self, timeout: Duration) -> Option<E> {
        self.rx.lock().unwrap().recv_timeout(timeout).ok()
    }
}

struct BenchInner {
    send: EventTracker<(usize, bool)>,
    recv: EventTracker<(usize, bool)>,
    need_key: EventTracker<()>,
    key_confirmed: EventTracker<()>,
}

#[derive(Clone)]
struct BenchOpaque {
    inner: Arc<BenchInner>,
}

impl std::ops::Deref for BenchOpaque {
    type Target = BenchInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BenchOpaque {
    fn new() -> Self {
        Self {
            inner: Arc::new(BenchInner {
                send: EventTracker::new(),
                recv: EventTracker::new(),
                need_key: EventTracker::new(),
                key_confirmed: EventTracker::new(),
            }),
        }
    }
}

struct BenchCallbacks;

impl Callbacks for BenchCallbacks {
    type Opaque = BenchOpaque;

    fn send(t: &Self::Opaque, size: usize, sent: bool, _kp: &Arc<KeyPair>, _ctr: u64) {
        t.send.log((size, sent));
    }
    fn recv(t: &Self::Opaque, size: usize, sent: bool, _kp: &Arc<KeyPair>) {
        t.recv.log((size, sent));
    }
    fn need_key(t: &Self::Opaque) {
        t.need_key.log(());
    }
    fn key_confirmed(t: &Self::Opaque) {
        t.key_confirmed.log(());
    }
}

const BENCH_CHANNEL_CAP: usize = 4096;
const WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Create a matched keypair: the initiator side and the responder side share
/// send/recv keys in opposite directions.
fn make_keypair(initiator: bool) -> KeyPair {
    let k1_bytes = [0x53u8; 32];
    let k2_bytes = [0x52u8; 32];
    let k1 = Key {
        cached_aead: CachedAeadKey::new(&k1_bytes),
        key: k1_bytes,
        id: 0x646e6573,
    };
    let k2 = Key {
        cached_aead: CachedAeadKey::new(&k2_bytes),
        key: k2_bytes,
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}

/// Build a minimal IPv4 packet with given src, dst, and body size.
fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4], body_size: usize) -> Vec<u8> {
    let total_len = 20 + body_size;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt
}

/// Prepend SIZE_MESSAGE_PREFIX zero bytes for in-place header construction.
fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0u8; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..].copy_from_slice(msg);
    o
}

/// Build a router with spawned write workers on the given Tokio runtime.
fn make_bench_router(
    rt: &tokio::runtime::Runtime,
    tun_writer: dummy_tun::DummyTunWriter,
    udp_writer: dummy_udp::DummyUdpWriter,
) -> BenchRouter {
    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, usize)>(BENCH_CHANNEL_CAP);
    let (udp_tx, udp_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, usize, dummy_udp::DummyEndpoint)>(BENCH_CHANNEL_CAP);

    let router: BenchRouter = DeviceHandle::new(num_cpus::get(), tun_tx, udp_tx);

    let pool = std::sync::Arc::new(ironguard_core::pipeline::vec_pool::VecPool::default());
    rt.spawn(tun_write_worker(tun_rx, tun_writer, pool.clone()));
    rt.spawn(udp_write_worker(udp_rx, udp_writer, pool));

    router.set_outbound_ready();
    router
}

// ---------------------------------------------------------------------------
// Encrypt benchmark: router.send() through the full pipeline
// ---------------------------------------------------------------------------

fn bench_pipeline_encrypt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let mut group = c.benchmark_group("pipeline_encrypt");

    for &pkt_body_size in &[64usize, 512, 1400] {
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], pkt_body_size);
        let total_pkt_size = ip_pkt.len() as u64;

        group.throughput(Throughput::Bytes(total_pkt_size));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{pkt_body_size}B")),
            &pkt_body_size,
            |b, _| {
                // Set up per-iteration: fresh router + peer with key
                let (_, tun_writer, _, _) = dummy_tun::create_pair();
                let (udp_readers, udp_writer, _, _, _, _) = dummy_udp::create_pair();
                let router = make_bench_router(&rt, tun_writer, udp_writer);

                let opaque = BenchOpaque::new();
                let peer = router.new_peer(opaque.clone());
                peer.add_allowed_ip("10.0.0.0".parse().unwrap(), 8);
                peer.set_endpoint(dummy_udp::DummyEndpoint::from_address(
                    "127.0.0.1:9999".parse().unwrap(),
                ));
                peer.add_keypair(make_keypair(true));

                // Drain the initial keepalive so we start clean
                let reader = &udp_readers[0];
                let _ = opaque.send.wait(WAIT_TIMEOUT);
                rt.block_on(async {
                    let mut buf = vec![0u8; 4096];
                    let _ = tokio::time::timeout(Duration::from_millis(500), reader.read(&mut buf))
                        .await;
                });

                b.iter(|| {
                    let msg = pad(&ip_pkt);
                    router.send(msg).unwrap();

                    // Wait for the send callback confirming encryption completed
                    let evt = opaque.send.wait(WAIT_TIMEOUT);
                    black_box(evt);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Roundtrip benchmark: encrypt on router A, decrypt on router B
// ---------------------------------------------------------------------------

fn bench_pipeline_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let mut group = c.benchmark_group("pipeline_roundtrip");

    for &pkt_body_size in &[64usize, 512, 1400] {
        // Packet flows: A sends to 192.168.1.x (routed via peer_a to B),
        // B decrypts and delivers.
        let ip_pkt = make_ipv4_packet([192, 168, 2, 10], [192, 168, 1, 20], pkt_body_size);
        let total_pkt_size = ip_pkt.len() as u64;

        group.throughput(Throughput::Bytes(total_pkt_size));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{pkt_body_size}B")),
            &pkt_body_size,
            |b, _| {
                // Router A (initiator) and Router B (responder) connected via dummy UDP
                let (_, tun_writer_a, _, _) = dummy_tun::create_pair();
                let (_, tun_writer_b, _, _) = dummy_tun::create_pair();
                let (udp_readers_a, udp_writer_a, _, udp_readers_b, udp_writer_b, _) =
                    dummy_udp::create_pair();

                let router_a = make_bench_router(&rt, tun_writer_a, udp_writer_a);
                let router_b = make_bench_router(&rt, tun_writer_b, udp_writer_b);

                let opaque_a = BenchOpaque::new();
                let opaque_b = BenchOpaque::new();

                let peer_a = router_a.new_peer(opaque_a.clone());
                let peer_b = router_b.new_peer(opaque_b.clone());

                // peer_a on router_a: packets to 192.168.1.0/24 route to this peer
                // (i.e. this peer represents B as seen by A)
                peer_a.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);
                peer_a.set_endpoint(dummy_udp::DummyEndpoint::from_address(
                    "127.0.0.1:9999".parse().unwrap(),
                ));

                // peer_b on router_b: packets to 192.168.2.0/24 route to this peer
                // (i.e. this peer represents A as seen by B)
                peer_b.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);

                // Install matched keypairs: A is initiator, B is responder
                peer_b.add_keypair(make_keypair(false));
                peer_a.add_keypair(make_keypair(true));

                // Drain initial keepalive: A sends keepalive -> arrives at B
                let _ = opaque_a.send.wait(WAIT_TIMEOUT);

                // udp_readers_a receives what was written by udp_writer_a (router_a's output)
                // In create_pair: writer_a writes to tx_a -> rx_b, so udp_readers_b reads
                // what router_a wrote. Let me use the correct readers.
                //
                // dummy_udp::create_pair() returns:
                //   (readers_a, writer_a, owner_a, readers_b, writer_b, owner_b)
                // where writer_a -> readers_b (A writes, B reads)
                // and   writer_b -> readers_a (B writes, A reads)
                let reader_b_side = &udp_readers_b[0]; // reads router_a's output
                let _reader_a_side = &udp_readers_a[0]; // reads router_b's output

                rt.block_on(async {
                    let mut buf = vec![0u8; 4096];
                    if let Ok(Ok((len, from))) = tokio::time::timeout(
                        Duration::from_millis(500),
                        reader_b_side.read(&mut buf),
                    )
                    .await
                    {
                        buf.truncate(len);
                        let _ = router_b.recv(from, buf);
                    }
                });

                // Wait for B to confirm the key
                let _ = opaque_b.recv.wait(WAIT_TIMEOUT);
                let _ = opaque_b.key_confirmed.wait(WAIT_TIMEOUT);

                b.iter(|| {
                    // A encrypts and sends a packet destined for 192.168.1.20
                    let msg = pad(&ip_pkt);
                    router_a.send(msg).unwrap();

                    // Wait for A's send callback
                    let _ = opaque_a.send.wait(WAIT_TIMEOUT);

                    // Read encrypted packet from A's UDP output (B's reader side)
                    let recv_result = rt.block_on(async {
                        let mut buf = vec![0u8; 4096];
                        let result = tokio::time::timeout(
                            Duration::from_millis(500),
                            reader_b_side.read(&mut buf),
                        )
                        .await;
                        match result {
                            Ok(Ok((len, from))) => {
                                buf.truncate(len);
                                Some((buf, from))
                            }
                            _ => None,
                        }
                    });

                    // B decrypts
                    if let Some((encrypted, from)) = recv_result {
                        let _ = router_b.recv(from, encrypted);
                        // Wait for B's recv callback
                        let evt = opaque_b.recv.wait(WAIT_TIMEOUT);
                        black_box(evt);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_buffer_pool_alloc_free,
    bench_aes_gcm_seal_1500,
    bench_aes_gcm_open_1500,
    bench_pipeline_encrypt,
    bench_pipeline_roundtrip
);
criterion_main!(benches);
