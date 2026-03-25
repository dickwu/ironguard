use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use spin::RwLock;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::Notify;
use tokio::sync::mpsc as tokio_mpsc;

#[cfg(feature = "legacy-wireguard")]
use crate::handshake;
use crate::peer::PeerInner;
use crate::queue::ParallelQueue;
use crate::router;
use crate::timers::{TIMERS_TICK, TIMERS_TICK_IDLE};
use crate::types::PublicKey;
#[cfg(feature = "legacy-wireguard")]
use crate::types::StaticSecret;
#[cfg(feature = "legacy-wireguard")]
use crate::workers::handshake_worker;
use crate::workers::{HandshakeJob, tun_worker, tun_write_worker, udp_worker, udp_write_worker};

use ironguard_platform::tun;
use ironguard_platform::udp;

use crate::pipeline::pool::BufferPool;

/// Time horizon used to initialise timestamps in the past.
const TIME_HORIZON: std::time::Duration = std::time::Duration::from_secs(3600);

/// Interior state shared via `Arc`.
pub struct WireGuardInner<T: tun::Tun, B: udp::Udp> {
    // identifier
    pub id: u32,

    // device enabled
    pub enabled: RwLock<bool>,

    // shutdown notification
    pub shutdown: Notify,

    // current MTU (0 = device down)
    pub mtu: AtomicUsize,

    // handshake device + peer map (legacy WireGuard Noise handshake)
    #[cfg(feature = "legacy-wireguard")]
    #[allow(clippy::type_complexity)]
    pub peers: RwLock<
        handshake::device::Device<
            router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,
        >,
    >,

    // crypto-key router
    pub router: router::DeviceHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,

    // handshake queue state
    pub last_under_load: Mutex<Instant>,
    pub pending: AtomicUsize,
    pub queue: ParallelQueue<HandshakeJob<B::Endpoint>>,

    // peer handles for looking up by public key (needed by handshake workers)
    #[allow(clippy::type_complexity)]
    pub peer_handles: RwLock<
        HashMap<[u8; 32], router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>>,
    >,

    // Receiver end of the UDP write channel, consumed when set_writer() is called.
    #[allow(clippy::type_complexity)]
    pub udp_write_rx: Mutex<Option<tokio_mpsc::Receiver<(Vec<u8>, B::Endpoint)>>>,

    // v2 pipeline buffer pool for zero-allocation packet processing
    pub pool: Arc<BufferPool>,

    // Tokio handle for spawning async tasks.
    pub handle: Handle,

    // Owned Tokio runtime — present only when the device created its own
    // runtime (via `new()`). When the caller supplies a `Handle` (via
    // `new_with_handle()`), this is `None` and the caller's runtime is used.
    _owned_runtime: Option<Runtime>,
}

/// Top-level WireGuard device handle.
pub struct WireGuard<T: tun::Tun, B: udp::Udp> {
    inner: Arc<WireGuardInner<T, B>>,
}

impl<T: tun::Tun, B: udp::Udp> fmt::Display for WireGuard<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: tun::Tun, B: udp::Udp> Deref for WireGuard<T, B> {
    type Target = WireGuardInner<T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: tun::Tun, B: udp::Udp> Clone for WireGuard<T, B> {
    fn clone(&self) -> Self {
        WireGuard {
            inner: self.inner.clone(),
        }
    }
}

impl<T: tun::Tun, B: udp::Udp> WireGuard<T, B> {
    /// Create a new WireGuard device.
    ///
    /// Spawns `num_cpus` handshake worker threads and router worker threads.
    /// Creates a Tokio runtime internally for async task management.
    ///
    /// **Note:** prefer [`new_with_handle`] when a Tokio runtime already exists
    /// (e.g. inside an `async fn` or `#[tokio::main]`).  Creating a second
    /// runtime causes `AsyncFd`-based readers (macOS TUN/UDP) to hang because
    /// the fd is registered with the outer reactor while the worker polls the
    /// inner one.
    /// Bounded channel capacity for the TUN and UDP write workers.
    const WRITE_CHANNEL_CAPACITY: usize = 256;

    pub fn new(writer: T::Writer) -> WireGuard<T, B> {
        let runtime = Runtime::new().expect("failed to create Tokio runtime");
        let handle = runtime.handle().clone();
        let _guard = runtime.enter();
        Self::build(writer, handle, Some(runtime))
    }

    /// Create a new WireGuard device that spawns tasks on the provided
    /// Tokio runtime handle.
    ///
    /// Use this when the caller already owns a Tokio runtime (e.g. from
    /// `#[tokio::main]`).  All async I/O tasks (TUN reader/writer, UDP
    /// reader/writer) will be spawned on the **same** reactor where the
    /// `AsyncFd` objects were created, avoiding cross-runtime hangs.
    pub fn new_with_handle(writer: T::Writer, handle: Handle) -> WireGuard<T, B> {
        let _guard = handle.enter();
        Self::build(writer, handle, None)
    }

    fn build(writer: T::Writer, handle: Handle, owned_runtime: Option<Runtime>) -> WireGuard<T, B> {
        let cpus = num_cpus::get();

        // handshake queue
        #[allow(unused_mut)]
        let (tx, mut rxs) = ParallelQueue::new(cpus, 128);

        // Create bounded channels for decoupled I/O writes.
        let (tun_write_tx, tun_write_rx) =
            tokio_mpsc::channel::<Vec<u8>>(Self::WRITE_CHANNEL_CAPACITY);
        let (udp_write_tx, udp_write_rx) =
            tokio_mpsc::channel::<(Vec<u8>, B::Endpoint)>(Self::WRITE_CHANNEL_CAPACITY);

        // crypto-key router — receives channel senders, never blocks on I/O
        let router: router::DeviceHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            router::DeviceHandle::new(cpus, tun_write_tx, udp_write_tx);

        // v2 pipeline buffer pool — pre-allocated buffers for zero-allocation I/O
        let pool = Arc::new(BufferPool::new());

        let wg = WireGuard {
            inner: Arc::new(WireGuardInner {
                enabled: RwLock::new(false),
                shutdown: Notify::new(),
                id: rand::random(),
                mtu: AtomicUsize::new(0),
                last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
                router,
                pending: AtomicUsize::new(0),
                #[cfg(feature = "legacy-wireguard")]
                peers: RwLock::new(handshake::device::Device::new()),
                queue: tx,
                peer_handles: RwLock::new(HashMap::new()),
                udp_write_rx: Mutex::new(Some(udp_write_rx)),
                pool,
                handle,
                _owned_runtime: owned_runtime,
            }),
        };

        // Spawn TUN write worker — drains the channel and writes to TUN
        wg.handle.spawn(tun_write_worker(tun_write_rx, writer));

        // NOTE: UDP write worker is spawned lazily via set_writer(),
        // since the UDP writer is not available at device creation time.

        // start handshake workers as async tasks (legacy WireGuard)
        #[cfg(feature = "legacy-wireguard")]
        while let Some(rx) = rxs.pop() {
            let wg2 = wg.clone();
            wg.handle.spawn(handshake_worker(wg2, rx));
        }
        #[cfg(not(feature = "legacy-wireguard"))]
        drop(rxs);

        wg
    }

    // ── up / down ────────────────────────────────────────────────────────

    pub fn up(&self, mtu: usize) {
        let mut enabled = self.enabled.write();
        self.mtu.store(mtu, Ordering::Relaxed);

        if *enabled {
            return;
        }

        self.router.up();

        // start timers for all peers
        let handles = self.peer_handles.read();
        for (_, peer_handle) in handles.iter() {
            peer_handle.up();
            peer_handle.opaque().start_timers();
        }

        *enabled = true;
    }

    pub fn down(&self) {
        let mut enabled = self.enabled.write();
        if !*enabled {
            return;
        }

        self.mtu.store(0, Ordering::Relaxed);
        self.router.down();

        let handles = self.peer_handles.read();
        for (_, peer_handle) in handles.iter() {
            peer_handle.opaque().stop_timers();
            peer_handle.down();
        }

        *enabled = false;
    }

    // ── peer management ──────────────────────────────────────────────────

    pub fn add_peer(&self, pk: PublicKey) -> bool {
        let enabled = *self.enabled.read();

        let peer_inner = PeerInner::new(rand::random(), pk.clone(), self.clone(), enabled);

        let peer_handle = self.router.new_peer(peer_inner);

        // Add to legacy handshake device (if enabled)
        #[cfg(feature = "legacy-wireguard")]
        {
            let peers = self.peers.write();
            peers.add(pk.clone(), peer_handle.clone());
        }

        // Store the handle
        self.peer_handles
            .write()
            .insert(*pk.as_bytes(), peer_handle);
        true
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        #[cfg(feature = "legacy-wireguard")]
        self.peers.write().remove(pk);
        self.peer_handles.write().remove(pk.as_bytes());
    }

    pub fn clear_peers(&self) {
        // NOTE: this doesn't properly release handshake IDs, but matches
        // the legacy implementation's approach.
        self.peer_handles.write().clear();
    }

    /// Look up a peer's router handle by public key.
    #[allow(clippy::type_complexity)]
    pub fn get_peer_handle(
        &self,
        pk: &PublicKey,
    ) -> Option<router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>> {
        self.peer_handles.read().get(pk.as_bytes()).cloned()
    }

    // ── key management ───────────────────────────────────────────────────

    #[cfg(feature = "legacy-wireguard")]
    pub fn set_key(&self, sk: Option<StaticSecret>) {
        self.peers.write().set_sk(sk);
    }

    #[cfg(feature = "legacy-wireguard")]
    pub fn set_psk(&self, pk: &PublicKey, psk: [u8; 32]) {
        self.peers.write().set_psk(pk, psk);
    }

    // ── IO ───────────────────────────────────────────────────────────────

    pub fn add_udp_reader(&self, reader: B::Reader)
    where
        B::Reader: udp::UdpReader<B::Endpoint>,
    {
        let wg = self.clone();
        self.handle.spawn(udp_worker(wg, reader));
    }

    pub fn set_writer(&self, writer: B::Writer) {
        // Spawn the UDP write worker with the channel receiver (consumed once).
        if let Some(rx) = self.udp_write_rx.lock().take() {
            self.handle.spawn(udp_write_worker(rx, writer));
        }

        // Mark the outbound path as ready so crypto workers send to the channel.
        self.router.set_outbound_ready();
    }

    pub fn add_tun_reader(&self, reader: T::Reader)
    where
        T::Reader: tun::Reader,
    {
        let wg = self.clone();
        self.handle.spawn(tun_worker(wg, reader));
    }

    /// Block until shutdown is signalled.
    ///
    /// When the device owns its runtime (created via `new()`), this blocks on
    /// the runtime.  When using an external runtime (via `new_with_handle()`),
    /// this uses `Handle::block_on`.
    pub fn wait(&self) {
        if let Some(rt) = &self._owned_runtime {
            rt.block_on(self.shutdown.notified());
        } else {
            // External runtime — use handle.block_on which enters the runtime
            // context for the blocking call.
            tokio::task::block_in_place(|| {
                self.handle.block_on(self.shutdown.notified());
            });
        }
    }

    // ── timer task ────────────────────────────────────────────────────────

    /// Spawn a Tokio task that ticks all peer timers.
    ///
    /// Uses adaptive tick intervals: `TIMERS_TICK` (100ms) when any peer has
    /// recent data activity, `TIMERS_TICK_IDLE` (1s) when all peers are idle.
    /// The task exits when `stop` is set to true.
    /// Returns a `JoinHandle` for the spawned task.
    pub fn start_timer_task(&self, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
        let wg = self.clone();
        self.handle.spawn(async move {
            let mut tick_duration = TIMERS_TICK;
            let mut interval = tokio::time::interval(tick_duration);
            loop {
                interval.tick().await;

                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let now = Instant::now();
                let handles = wg.peer_handles.read();

                let mut any_active = false;

                for (_, peer_handle) in handles.iter() {
                    let opaque = peer_handle.opaque();

                    if !opaque.timers().is_idle(now) {
                        any_active = true;
                    }

                    let actions = opaque.timers().check_timers(now);

                    if actions.retransmit_handshake {
                        if opaque.timers().is_handshake_expired() {
                            peer_handle.purge_staged_packets();
                        } else {
                            opaque.packet_send_queued_handshake_initiation(true);
                        }
                    }

                    if actions.send_keepalive {
                        peer_handle.send_keepalive();
                    }

                    if actions.send_persistent_keepalive {
                        peer_handle.send_keepalive();
                    }

                    if actions.zero_key_material {
                        peer_handle.zero_keys();
                    }

                    if actions.new_handshake {
                        opaque.packet_send_queued_handshake_initiation(false);
                    }
                }

                // Adapt tick rate: fast when peers are active, slow when idle
                let desired = if any_active {
                    TIMERS_TICK
                } else {
                    TIMERS_TICK_IDLE
                };
                if desired != tick_duration {
                    tick_duration = desired;
                    interval = tokio::time::interval(tick_duration);
                }
            }
        })
    }
}

#[cfg(all(test, feature = "legacy-wireguard"))]
mod tests {
    use super::*;
    use crate::constants::SIZE_MESSAGE_PREFIX;
    use ironguard_platform::dummy::tun as dummy_tun;
    use ironguard_platform::dummy::tun::DummyTun;
    use ironguard_platform::dummy::udp as dummy_udp;
    use ironguard_platform::dummy::udp::DummyUdp;
    use ironguard_platform::endpoint::Endpoint as _;
    use std::net::IpAddr;
    use std::thread;
    use std::time::Duration;

    type TestWireGuard = WireGuard<DummyTun, DummyUdp>;

    /// Build a minimal IPv4 packet with given src and dst.
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

    #[test]
    fn test_device_create_and_add_peer() {
        let (_, tun_writer, _, _) = dummy_tun::create_pair();
        let wg: TestWireGuard = WireGuard::new(tun_writer);

        let sk = StaticSecret::random();
        wg.set_key(Some(sk));

        let peer_pk = PublicKey::from_bytes([1u8; 32]);
        assert!(wg.add_peer(peer_pk.clone()));

        assert!(wg.get_peer_handle(&peer_pk).is_some());
    }

    #[test]
    fn test_device_up_down() {
        let (_, tun_writer, _, _) = dummy_tun::create_pair();
        let wg: TestWireGuard = WireGuard::new(tun_writer);
        wg.up(1500);
        assert_eq!(wg.mtu.load(Ordering::Relaxed), 1500);
        wg.down();
        assert_eq!(wg.mtu.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_full_wireguard_tunnel() {
        // ── Step 1: Create dummy TUN and UDP pairs ───────────────────────
        let (a_tun_readers, a_tun_writer, b_tun_readers, b_tun_writer) = dummy_tun::create_pair();
        let (a_udp_readers, a_udp_writer, _a_owner, b_udp_readers, b_udp_writer, _b_owner) =
            dummy_udp::create_pair();

        // ── Step 2: Create two WireGuard devices ────────────────────────
        let wg_a: TestWireGuard = WireGuard::new(a_tun_writer);
        let wg_b: TestWireGuard = WireGuard::new(b_tun_writer);

        // ── Step 3: Generate keypairs and set static keys ───────────────
        let sk_a = StaticSecret::random();
        let sk_b = StaticSecret::random();

        // Derive public keys
        let dalek_sk_a = x25519_dalek::StaticSecret::from(*sk_a.as_bytes());
        let dalek_pk_a = x25519_dalek::PublicKey::from(&dalek_sk_a);
        let pk_a = PublicKey::from_bytes(*dalek_pk_a.as_bytes());

        let dalek_sk_b = x25519_dalek::StaticSecret::from(*sk_b.as_bytes());
        let dalek_pk_b = x25519_dalek::PublicKey::from(&dalek_sk_b);
        let pk_b = PublicKey::from_bytes(*dalek_pk_b.as_bytes());

        wg_a.set_key(Some(sk_a));
        wg_b.set_key(Some(sk_b));

        // ── Step 4: Add peers ───────────────────────────────────────────
        wg_a.add_peer(pk_b.clone());
        wg_b.add_peer(pk_a.clone());

        // ── Step 5: Set allowed IPs ─────────────────────────────────────
        {
            let handle_a = wg_a.get_peer_handle(&pk_b).unwrap();
            handle_a.add_allowed_ip(IpAddr::V4("10.0.0.2".parse().unwrap()), 32);
            handle_a.set_endpoint(dummy_udp::DummyEndpoint::from_address(
                "127.0.0.1:51821".parse().unwrap(),
            ));
        }
        {
            let handle_b = wg_b.get_peer_handle(&pk_a).unwrap();
            handle_b.add_allowed_ip(IpAddr::V4("10.0.0.1".parse().unwrap()), 32);
            handle_b.set_endpoint(dummy_udp::DummyEndpoint::from_address(
                "127.0.0.1:51820".parse().unwrap(),
            ));
        }

        // ── Step 6: Set UDP writers ─────────────────────────────────────
        wg_a.set_writer(a_udp_writer);
        wg_b.set_writer(b_udp_writer);

        // ── Step 7: Add UDP readers ─────────────────────────────────────
        for reader in a_udp_readers {
            wg_a.add_udp_reader(reader);
        }
        for reader in b_udp_readers {
            wg_b.add_udp_reader(reader);
        }

        // ── Step 8: Add TUN readers ─────────────────────────────────────
        for reader in a_tun_readers {
            wg_a.add_tun_reader(reader);
        }
        for reader in b_tun_readers {
            wg_b.add_tun_reader(reader);
        }

        // ── Step 9: Bring both devices up ───────────────────────────────
        wg_a.up(1500);
        wg_b.up(1500);

        // ── Step 10: Start timer threads ────────────────────────────────
        let stop_a = Arc::new(AtomicBool::new(false));
        let stop_b = Arc::new(AtomicBool::new(false));
        let _timer_a = wg_a.start_timer_task(stop_a.clone());
        let _timer_b = wg_b.start_timer_task(stop_b.clone());

        // ── Step 11: Perform handshake ──────────────────────────────────
        // Manually initiate handshake from A to B
        {
            let peers = wg_a.peers.read();
            let init_msg = peers.begin(&pk_b).expect("A should begin handshake to B");
            // Send init message via A's UDP writer to B's UDP reader
            let handle_a = wg_a.get_peer_handle(&pk_b).unwrap();
            let send_result = handle_a.send_raw(&init_msg[..]);
            assert!(
                send_result.is_ok(),
                "send_raw should succeed: {:?}",
                send_result.err()
            );
        }

        // Wait for the handshake to complete by polling B's rx_bytes.
        // The handshake worker on B will process the initiation, send a response,
        // and A's handshake worker will process the response, completing the handshake.
        let handle_b = wg_b.get_peer_handle(&pk_a).unwrap();
        let handle_a = wg_a.get_peer_handle(&pk_b).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            // B should have received the init message (rx_bytes > 0)
            let b_rx = handle_b.opaque().rx_bytes.load(Ordering::Relaxed);
            // After the handshake, add_keypair sends a keepalive which goes through
            // Callbacks::send, incrementing tx_bytes.
            let a_handshake_done = handle_b.opaque().walltime_last_handshake.lock().is_some();

            if b_rx > 0 && a_handshake_done {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        let b_rx = handle_b.opaque().rx_bytes.load(Ordering::Relaxed);
        assert!(
            b_rx > 0,
            "B should have received bytes from A (rx_bytes={})",
            b_rx
        );

        // Verify last handshake timestamp was set on B
        let walltime = handle_b.opaque().walltime_last_handshake.lock();
        assert!(walltime.is_some(), "B should record handshake walltime");
        drop(walltime);

        // ── Step 12: Send a data packet from A to B ─────────────────────
        let test_packet = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], 32);

        let mut msg = vec![0u8; SIZE_MESSAGE_PREFIX + test_packet.len()];
        msg[SIZE_MESSAGE_PREFIX..].copy_from_slice(&test_packet);

        let send_result = wg_a.router.send(msg);
        assert!(
            send_result.is_ok(),
            "A should route the packet to B: {:?}",
            send_result.err()
        );

        // Wait for the data packet to be processed
        let deadline = Instant::now() + Duration::from_secs(5);
        let b_rx_before = handle_b.opaque().rx_bytes.load(Ordering::Relaxed);
        while Instant::now() < deadline {
            let b_rx_now = handle_b.opaque().rx_bytes.load(Ordering::Relaxed);
            if b_rx_now > b_rx_before {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        let b_rx_after = handle_b.opaque().rx_bytes.load(Ordering::Relaxed);
        assert!(
            b_rx_after > b_rx_before,
            "B should have received the data packet (rx before={}, after={})",
            b_rx_before,
            b_rx_after,
        );

        // Verify A has tx stats (from keepalive after handshake + data packet)
        let a_tx = handle_a.opaque().tx_bytes.load(Ordering::Relaxed);
        assert!(
            a_tx > 0,
            "A should have transmitted bytes (tx_bytes={})",
            a_tx
        );

        // ── Cleanup ─────────────────────────────────────────────────────
        stop_a.store(true, Ordering::Relaxed);
        stop_b.store(true, Ordering::Relaxed);
        wg_a.down();
        wg_b.down();
    }
}
