use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use spin::RwLock;
use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::handshake;
use crate::peer::PeerInner;
use crate::queue::ParallelQueue;
use crate::router;
use crate::timers::TIMERS_TICK;
use crate::types::{PublicKey, StaticSecret};
use crate::workers::{handshake_worker, tun_worker, udp_worker, HandshakeJob};

use ironguard_platform::tun;
use ironguard_platform::udp;

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

    // handshake device + peer map
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
        HashMap<
            [u8; 32],
            router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,
        >,
    >,

    // Tokio runtime — owned by the device, used for spawning async tasks
    pub runtime: Runtime,
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
    pub fn new(writer: T::Writer) -> WireGuard<T, B> {
        let cpus = num_cpus::get();

        // Create a Tokio runtime for the device first, so that
        // DeviceHandle::new() can capture the runtime handle for its
        // worker threads.
        let runtime = Runtime::new().expect("failed to create Tokio runtime");
        let _guard = runtime.enter();

        // handshake queue
        let (tx, mut rxs) = ParallelQueue::new(cpus, 128);

        // crypto-key router
        let router: router::DeviceHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            router::DeviceHandle::new(cpus, writer);

        let wg = WireGuard {
            inner: Arc::new(WireGuardInner {
                enabled: RwLock::new(false),
                shutdown: Notify::new(),
                id: rand::random(),
                mtu: AtomicUsize::new(0),
                last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
                router,
                pending: AtomicUsize::new(0),
                peers: RwLock::new(handshake::device::Device::new()),
                queue: tx,
                peer_handles: RwLock::new(HashMap::new()),
                runtime,
            }),
        };

        // start handshake workers as async tasks
        while let Some(rx) = rxs.pop() {
            let wg2 = wg.clone();
            wg.runtime.spawn(handshake_worker(wg2, rx));
        }

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

        let peer_inner = PeerInner::new(
            rand::random(),
            pk.clone(),
            self.clone(),
            enabled,
        );

        let peer_handle = self.router.new_peer(peer_inner);

        // Add to handshake device
        let peers = self.peers.write();
        peers.add(pk.clone(), peer_handle.clone());

        // Store the handle
        self.peer_handles.write().insert(*pk.as_bytes(), peer_handle);
        true
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
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
    ) -> Option<
        router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,
    > {
        self.peer_handles.read().get(pk.as_bytes()).cloned()
    }

    // ── key management ───────────────────────────────────────────────────

    pub fn set_key(&self, sk: Option<StaticSecret>) {
        self.peers.write().set_sk(sk);
    }

    pub fn set_psk(&self, pk: &PublicKey, psk: [u8; 32]) {
        self.peers.write().set_psk(pk, psk);
    }

    // ── IO ───────────────────────────────────────────────────────────────

    pub fn add_udp_reader(&self, reader: B::Reader)
    where
        B::Reader: udp::UdpReader<B::Endpoint>,
    {
        let wg = self.clone();
        self.runtime.spawn(udp_worker(wg, reader));
    }

    pub fn set_writer(&self, writer: B::Writer) {
        self.router.set_outbound_writer(writer);
    }

    pub fn add_tun_reader(&self, reader: T::Reader)
    where
        T::Reader: tun::Reader,
    {
        let wg = self.clone();
        self.runtime.spawn(tun_worker(wg, reader));
    }

    /// Block until shutdown is signalled.
    pub fn wait(&self) {
        self.runtime.block_on(self.shutdown.notified());
    }

    // ── timer task ────────────────────────────────────────────────────────

    /// Spawn a Tokio task that ticks all peer timers every `TIMERS_TICK`.
    /// The task exits when `stop` is set to true.
    /// Returns a `JoinHandle` for the spawned task.
    pub fn start_timer_task(
        &self,
        stop: Arc<AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let wg = self.clone();
        self.runtime.spawn(async move {
            let mut interval = tokio::time::interval(TIMERS_TICK);
            loop {
                interval.tick().await;

                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let now = Instant::now();
                let handles = wg.peer_handles.read();

                for (_, peer_handle) in handles.iter() {
                    let opaque = peer_handle.opaque();
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
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SIZE_MESSAGE_PREFIX;
    use ironguard_platform::dummy::tun as dummy_tun;
    use ironguard_platform::dummy::tun::DummyTun;
    use ironguard_platform::dummy::udp as dummy_udp;
    use ironguard_platform::dummy::udp::DummyUdp;
    use ironguard_platform::endpoint::Endpoint as _;
    use std::thread;
    use std::net::IpAddr;
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
        let (a_tun_readers, a_tun_writer, b_tun_readers, b_tun_writer) =
            dummy_tun::create_pair();
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
            assert!(send_result.is_ok(), "send_raw should succeed: {:?}", send_result.err());
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
        assert!(b_rx > 0, "B should have received bytes from A (rx_bytes={})", b_rx);

        // Verify last handshake timestamp was set on B
        let walltime = handle_b.opaque().walltime_last_handshake.lock();
        assert!(walltime.is_some(), "B should record handshake walltime");
        drop(walltime);

        // ── Step 12: Send a data packet from A to B ─────────────────────
        let test_packet = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], 32);

        let mut msg = vec![0u8; SIZE_MESSAGE_PREFIX + test_packet.len()];
        msg[SIZE_MESSAGE_PREFIX..].copy_from_slice(&test_packet);

        let send_result = wg_a.router.send(msg);
        assert!(send_result.is_ok(), "A should route the packet to B: {:?}", send_result.err());

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
        assert!(a_tx > 0, "A should have transmitted bytes (tx_bytes={})", a_tx);

        // ── Cleanup ─────────────────────────────────────────────────────
        stop_a.store(true, Ordering::Relaxed);
        stop_b.store(true, Ordering::Relaxed);
        wg_a.down();
        wg_b.down();
    }
}
