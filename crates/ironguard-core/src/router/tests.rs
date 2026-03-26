use std::ops::Deref;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::constants::SIZE_MESSAGE_PREFIX;
use crate::types::{CachedAeadKey, Key, KeyPair};
use crate::workers::{tun_write_worker, udp_write_worker};

use super::device::DeviceHandle;
use super::messages_v2;
use super::types::Callbacks;

use ironguard_platform::dummy::tun as dummy_tun;
use ironguard_platform::dummy::udp as dummy_udp;

type TestRouter = DeviceHandle<
    dummy_udp::DummyEndpoint,
    TestCallbacks,
    dummy_tun::DummyTunWriter,
    dummy_udp::DummyUdpWriter,
>;

const TIMEOUT: Duration = Duration::from_millis(1000);

/// Channel capacity used for test write workers.
const TEST_CHANNEL_CAP: usize = 256;

// --- Event tracking infrastructure ---

struct EventTracker<E> {
    rx: Mutex<Receiver<E>>,
    tx: Mutex<Sender<E>>,
}

impl<E> EventTracker<E> {
    fn new() -> Self {
        let (tx, rx) = channel();
        EventTracker {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
        }
    }

    fn log(&self, e: E) {
        self.tx.lock().unwrap().send(e).unwrap();
    }

    fn wait(&self, timeout: Duration) -> Option<E> {
        match self.rx.lock().unwrap().recv_timeout(timeout) {
            Ok(v) => Some(v),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => panic!("Disconnect"),
        }
    }

    fn now(&self) -> Option<E> {
        self.wait(Duration::from_millis(0))
    }
}

struct Inner {
    send: EventTracker<(usize, bool)>,
    recv: EventTracker<(usize, bool)>,
    need_key: EventTracker<()>,
    key_confirmed: EventTracker<()>,
}

#[derive(Clone)]
struct Opaque {
    inner: Arc<Inner>,
}

impl Deref for Opaque {
    type Target = Inner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Opaque {
    fn new() -> Opaque {
        Opaque {
            inner: Arc::new(Inner {
                send: EventTracker::new(),
                recv: EventTracker::new(),
                need_key: EventTracker::new(),
                key_confirmed: EventTracker::new(),
            }),
        }
    }
}

struct TestCallbacks;

impl Callbacks for TestCallbacks {
    type Opaque = Opaque;

    fn send(t: &Self::Opaque, size: usize, sent: bool, _keypair: &Arc<KeyPair>, _counter: u64) {
        t.send.log((size, sent));
    }

    fn recv(t: &Self::Opaque, size: usize, sent: bool, _keypair: &Arc<KeyPair>) {
        t.recv.log((size, sent));
    }

    fn need_key(t: &Self::Opaque) {
        t.need_key.log(());
    }

    fn key_confirmed(t: &Self::Opaque) {
        t.key_confirmed.log(());
    }
}

/// Assert that no events are pending on any tracker.
macro_rules! no_events {
    ($opq:expr) => {{
        assert_eq!($opq.send.now(), None, "unexpected send event");
        assert_eq!($opq.recv.now(), None, "unexpected recv event");
        assert_eq!($opq.need_key.now(), None, "unexpected need_key event");
        assert_eq!(
            $opq.key_confirmed.now(),
            None,
            "unexpected key_confirmed event"
        );
    }};
}

// --- Helpers ---

fn dummy_keypair(initiator: bool) -> KeyPair {
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

/// Prepend SIZE_MESSAGE_PREFIX zero bytes (for in-place header construction).
fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0u8; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..].copy_from_slice(msg);
    o
}

/// Build a minimal IPv4 packet with given src, dst, and body size.
fn make_ipv4_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, body_size: usize) -> Vec<u8> {
    let total_len = 20 + body_size;
    let mut pkt = vec![0u8; total_len];
    // version (4) + IHL (5)
    pkt[0] = 0x45;
    // total length
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    // src at [12..16]
    pkt[12..16].copy_from_slice(&src.octets());
    // dst at [16..20]
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt
}

/// Build a minimal IPv6 packet with given src, dst, and body size.
fn make_ipv6_packet(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr, body_size: usize) -> Vec<u8> {
    let total_len = 40 + body_size;
    let mut pkt = vec![0u8; total_len];
    // version (6)
    pkt[0] = 0x60;
    // payload length
    pkt[4] = (body_size >> 8) as u8;
    pkt[5] = body_size as u8;
    // src at [8..24]
    pkt[8..24].copy_from_slice(&src.octets());
    // dst at [24..40]
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt
}

/// Create a test router with channels and spawned write workers.
/// Returns the router. The TUN and UDP writers are consumed by write worker tasks.
fn make_test_router(
    tun_writer: dummy_tun::DummyTunWriter,
    udp_writer: dummy_udp::DummyUdpWriter,
) -> TestRouter {
    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TEST_CHANNEL_CAP);
    let (udp_tx, udp_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, dummy_udp::DummyEndpoint)>(TEST_CHANNEL_CAP);

    let router: TestRouter = DeviceHandle::new(1, tun_tx, udp_tx);

    // Spawn write workers on the current Tokio runtime.
    tokio::spawn(tun_write_worker(tun_rx, tun_writer));
    tokio::spawn(udp_write_worker(udp_rx, udp_writer));

    // Mark outbound as ready (writer is now available via the channel).
    router.set_outbound_ready();

    router
}

/// Create a test router that does NOT need outbound writes (no UDP writer spawned).
/// A dummy UDP pair is created internally; the writer goes to a write worker that
/// sends into the void.
fn make_test_router_no_outbound(tun_writer: dummy_tun::DummyTunWriter) -> TestRouter {
    let (_, udp_writer, _, _, _, _) = dummy_udp::create_pair();
    make_test_router(tun_writer, udp_writer)
}

// --- Tests ---

#[tokio::test]
async fn test_outbound_routing() {
    // Create a router with a dummy TUN and void UDP
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router = make_test_router_no_outbound(tun_writer);

    // Add peer with allowed IPs
    let opaque = Opaque::new();
    let peer = router.new_peer(opaque.clone());
    peer.add_allowed_ip("10.0.0.0".parse().unwrap(), 24);

    // Set a keypair
    peer.add_keypair(dummy_keypair(true));

    // Build and send a packet to 10.0.0.5
    let ip_pkt = make_ipv4_packet(
        "127.0.0.1".parse().unwrap(),
        "10.0.0.5".parse().unwrap(),
        100,
    );
    let msg = pad(&ip_pkt);
    let res = router.send(msg);
    assert!(res.is_ok(), "routing should succeed for 10.0.0.5/24");

    // Verify send callback fires
    let evt = opaque.send.wait(TIMEOUT);
    assert!(evt.is_some(), "send event should fire");
}

#[tokio::test]
async fn test_no_route_fails() {
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router = make_test_router_no_outbound(tun_writer);

    // No peers added - routing should fail
    let ip_pkt = make_ipv4_packet(
        "127.0.0.1".parse().unwrap(),
        "10.0.0.5".parse().unwrap(),
        100,
    );
    let res = router.send(pad(&ip_pkt));
    assert!(res.is_err(), "should fail with NoCryptoKeyRoute");
}

#[tokio::test]
async fn test_no_key_triggers_need_key() {
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router = make_test_router_no_outbound(tun_writer);

    let opaque = Opaque::new();
    let peer = router.new_peer(opaque.clone());
    peer.add_allowed_ip("10.0.0.0".parse().unwrap(), 24);

    // No keypair set - send should trigger need_key
    let ip_pkt = make_ipv4_packet(
        "127.0.0.1".parse().unwrap(),
        "10.0.0.5".parse().unwrap(),
        100,
    );
    let res = router.send(pad(&ip_pkt));
    assert!(res.is_ok(), "routing should succeed even without key");

    assert_eq!(
        opaque.need_key.wait(TIMEOUT),
        Some(()),
        "need_key should be called when no encryption key"
    );
}

#[tokio::test]
async fn test_bidirectional() {
    // Create two routers connected via dummy UDP pair
    let (_, tun_writer1, _, _) = dummy_tun::create_pair();
    let (_, tun_writer2, _, _) = dummy_tun::create_pair();

    let (udp_readers1, udp_writer1, _, udp_readers2, udp_writer2, _) = dummy_udp::create_pair();

    let router1 = make_test_router(tun_writer1, udp_writer1);
    let router2 = make_test_router(tun_writer2, udp_writer2);

    let opaque1 = Opaque::new();
    let opaque2 = Opaque::new();

    let peer1 = router1.new_peer(opaque1.clone());
    let peer2 = router2.new_peer(opaque2.clone());

    // peer1 has responder keypair, peer2 is initiator
    peer1.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);
    peer1.add_keypair(dummy_keypair(false));

    peer2.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer2.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:9999".parse().unwrap(),
    ));

    // Add initiator keypair to peer2 - this triggers keepalive for confirmation
    peer2.add_keypair(dummy_keypair(true));

    // peer2 should send a keepalive to confirm the key
    let send_evt = opaque2.send.wait(TIMEOUT);
    assert!(send_evt.is_some(), "peer2 should send confirmation packet");

    // Read the encrypted packet from udp_readers1 (peer2 -> peer1)
    let reader1 = &udp_readers1[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader1.read(&mut buf).await.unwrap();
    buf.truncate(len);

    // Pass to router1 for decryption
    router1
        .recv(from, buf)
        .expect("router1 should process the packet");

    // peer1 should fire recv and key_confirmed events
    assert!(
        opaque1.recv.wait(TIMEOUT).is_some(),
        "peer1 should receive the packet"
    );
    assert_eq!(
        opaque1.key_confirmed.wait(TIMEOUT),
        Some(()),
        "peer1 should confirm the key"
    );

    // Now peer1 has an endpoint (learned from the incoming packet)
    assert!(
        peer1.get_endpoint().is_some(),
        "peer1 should have learned endpoint"
    );

    // Send a real packet from peer1 -> peer2
    let ip_pkt = make_ipv4_packet(
        "192.168.2.10".parse().unwrap(),
        "192.168.1.20".parse().unwrap(),
        50,
    );
    router1
        .send(pad(&ip_pkt))
        .expect("peer1 -> peer2 should route");

    // Check send event
    assert!(
        opaque1.send.wait(TIMEOUT).is_some(),
        "peer1 send event should fire"
    );

    // Read encrypted packet on udp_readers2
    let reader2 = &udp_readers2[0];
    let mut buf2 = vec![0u8; 4096];
    let (len2, from2) = reader2.read(&mut buf2).await.unwrap();
    buf2.truncate(len2);

    // Pass to router2
    router2.recv(from2, buf2).expect("router2 should process");

    // peer2 should fire recv
    assert!(
        opaque2.recv.wait(TIMEOUT).is_some(),
        "peer2 should receive decrypted packet"
    );

    // no stray events
    no_events!(opaque1);
    no_events!(opaque2);
}

#[tokio::test]
async fn test_replay_rejected() {
    // Create two routers connected via dummy UDP pair
    let (_, tun_writer1, _, _) = dummy_tun::create_pair();
    let (_, tun_writer2, _, _) = dummy_tun::create_pair();

    let (udp_readers1, udp_writer1, _, _, udp_writer2, _) = dummy_udp::create_pair();

    let router1 = make_test_router(tun_writer1, udp_writer1);
    let router2 = make_test_router(tun_writer2, udp_writer2);

    let opaque1 = Opaque::new();
    let opaque2 = Opaque::new();

    let peer1 = router1.new_peer(opaque1.clone());
    let peer2 = router2.new_peer(opaque2.clone());

    peer1.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);
    peer1.add_keypair(dummy_keypair(false));

    peer2.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer2.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:9999".parse().unwrap(),
    ));
    peer2.add_keypair(dummy_keypair(true));

    // Wait for keepalive send
    opaque2.send.wait(TIMEOUT);

    // Read the encrypted keepalive
    let reader1 = &udp_readers1[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader1.read(&mut buf).await.unwrap();
    buf.truncate(len);

    // Save a copy for replay
    let replay_buf = buf.clone();
    let replay_from = from.clone();

    // First receive should succeed
    router1.recv(from, buf).expect("first recv should succeed");
    assert!(opaque1.recv.wait(TIMEOUT).is_some());

    // Drain key_confirmed
    let _ = opaque1.key_confirmed.wait(TIMEOUT);

    // Replay the same packet - should be processed but replay protection drops it
    // (no recv callback should fire for the replay)
    router1
        .recv(replay_from, replay_buf)
        .expect("recv should not error");

    // The packet goes through the pipeline but replay check drops it
    // so no recv event should fire
    // Give a short timeout - no event expected
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        opaque1.recv.now(),
        None,
        "replayed packet should not generate recv event"
    );
}

#[tokio::test]
async fn test_outbound_ipv6() {
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router = make_test_router_no_outbound(tun_writer);

    let opaque = Opaque::new();
    let peer = router.new_peer(opaque.clone());
    peer.add_allowed_ip("2001:db8::".parse().unwrap(), 32);
    peer.add_keypair(dummy_keypair(true));

    let ip_pkt = make_ipv6_packet("::1".parse().unwrap(), "2001:db8::1".parse().unwrap(), 100);
    let res = router.send(pad(&ip_pkt));
    assert!(res.is_ok(), "IPv6 routing should succeed");

    assert!(
        opaque.send.wait(TIMEOUT).is_some(),
        "send event should fire for IPv6"
    );
}

#[tokio::test]
async fn test_keepalive_on_key_add() {
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router = make_test_router_no_outbound(tun_writer);

    let opaque = Opaque::new();
    let peer = router.new_peer(opaque.clone());
    peer.add_allowed_ip("10.0.0.0".parse().unwrap(), 24);
    peer.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:9999".parse().unwrap(),
    ));

    // Adding an initiator keypair with no staged packets should send keepalive
    peer.add_keypair(dummy_keypair(true));

    let evt = opaque.send.wait(TIMEOUT);
    assert!(evt.is_some(), "keepalive should be sent to confirm key");

    let (size, _sent) = evt.unwrap();
    // keepalive wire message: v2 header(16) + tag(16) = 32
    let keepalive_size = messages_v2::HEADER_SIZE + 16;
    assert_eq!(size, keepalive_size, "keepalive should be header + tag");
}

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::udp::UdpReader;

/// Full bidirectional pipeline test: two routers exchange 100 packets in each
/// direction via dummy backends, verifying the v2 encrypt/decrypt path works
/// end-to-end with the decoupled channel-based I/O pipeline.
#[tokio::test]
async fn test_v2_full_pipeline_bidirectional() {
    const PACKET_COUNT: usize = 100;
    const BODY_SIZE: usize = 100;

    // -- Set up two routers connected via dummy UDP pair --
    let (_, tun_writer1, _, _) = dummy_tun::create_pair();
    let (_, tun_writer2, _, _) = dummy_tun::create_pair();

    let (udp_readers1, udp_writer1, _, udp_readers2, udp_writer2, _) = dummy_udp::create_pair();

    let router1 = make_test_router(tun_writer1, udp_writer1);
    let router2 = make_test_router(tun_writer2, udp_writer2);

    let opaque1 = Opaque::new();
    let opaque2 = Opaque::new();

    let peer1 = router1.new_peer(opaque1.clone());
    let peer2 = router2.new_peer(opaque2.clone());

    // peer1 (responder) accepts traffic from 192.168.1.0/24
    peer1.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);
    peer1.add_keypair(dummy_keypair(false));

    // peer2 (initiator) accepts traffic from 192.168.2.0/24
    peer2.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer2.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:9999".parse().unwrap(),
    ));
    peer2.add_keypair(dummy_keypair(true));

    // -- Exchange keepalive to confirm the key on both sides --

    // peer2 (initiator) sends keepalive automatically
    let send_evt = opaque2.send.wait(TIMEOUT);
    assert!(
        send_evt.is_some(),
        "peer2 should send confirmation keepalive"
    );

    // Read keepalive from udp_readers1 and pass to router1 for decryption
    let reader1 = &udp_readers1[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader1.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router1
        .recv(from, buf)
        .expect("router1 should process keepalive");

    // Verify peer1 received and confirmed the key
    assert!(
        opaque1.recv.wait(TIMEOUT).is_some(),
        "peer1 should receive keepalive"
    );
    assert_eq!(
        opaque1.key_confirmed.wait(TIMEOUT),
        Some(()),
        "peer1 should confirm key"
    );

    // peer1 should now have an endpoint learned from the incoming packet
    assert!(
        peer1.get_endpoint().is_some(),
        "peer1 should have learned endpoint"
    );

    // -- Send PACKET_COUNT packets from peer1 -> peer2 --
    let reader2 = &udp_readers2[0];

    for i in 0..PACKET_COUNT {
        let ip_pkt = make_ipv4_packet(
            "192.168.2.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
            BODY_SIZE,
        );
        router1
            .send(pad(&ip_pkt))
            .unwrap_or_else(|e| panic!("peer1->peer2 send #{i} failed: {e}"));

        // Wait for send callback on router1 side
        assert!(
            opaque1.send.wait(TIMEOUT).is_some(),
            "peer1 send event #{i} should fire"
        );

        // Read encrypted packet from router1's output, pass to router2
        let mut buf2 = vec![0u8; 4096];
        let (len2, from2) = reader2.read(&mut buf2).await.unwrap();
        buf2.truncate(len2);
        router2
            .recv(from2, buf2)
            .unwrap_or_else(|e| panic!("router2 recv #{i} failed: {e}"));

        // Verify peer2 decrypted successfully
        assert!(
            opaque2.recv.wait(TIMEOUT).is_some(),
            "peer2 recv event #{i} should fire"
        );
    }

    // -- Send PACKET_COUNT packets from peer2 -> peer1 --
    for i in 0..PACKET_COUNT {
        let ip_pkt = make_ipv4_packet(
            "192.168.1.20".parse().unwrap(),
            "192.168.2.10".parse().unwrap(),
            BODY_SIZE,
        );
        router2
            .send(pad(&ip_pkt))
            .unwrap_or_else(|e| panic!("peer2->peer1 send #{i} failed: {e}"));

        assert!(
            opaque2.send.wait(TIMEOUT).is_some(),
            "peer2 send event #{i} should fire"
        );

        let mut buf1 = vec![0u8; 4096];
        let (len1, from1) = reader1.read(&mut buf1).await.unwrap();
        buf1.truncate(len1);
        router1
            .recv(from1, buf1)
            .unwrap_or_else(|e| panic!("router1 recv #{i} failed: {e}"));

        assert!(
            opaque1.recv.wait(TIMEOUT).is_some(),
            "peer1 recv event #{i} should fire"
        );
    }

    // Verify no stray events remain
    assert_eq!(opaque1.send.now(), None, "unexpected send event on peer1");
    assert_eq!(opaque1.recv.now(), None, "unexpected recv event on peer1");
    assert_eq!(opaque2.send.now(), None, "unexpected send event on peer2");
    assert_eq!(opaque2.recv.now(), None, "unexpected recv event on peer2");
}

// --- Forwarding helpers ---

/// Create a keypair with custom key bytes and receiver IDs.
/// This lets us set up multiple independent encrypted links without
/// receiver-ID collisions.
fn custom_keypair(
    initiator: bool,
    send_bytes: [u8; 32],
    recv_bytes: [u8; 32],
    send_id: u32,
    recv_id: u32,
) -> KeyPair {
    let k_send = Key {
        cached_aead: CachedAeadKey::new(&send_bytes),
        key: send_bytes,
        id: send_id,
    };
    let k_recv = Key {
        cached_aead: CachedAeadKey::new(&recv_bytes),
        key: recv_bytes,
        id: recv_id,
    };
    KeyPair {
        birth: Instant::now(),
        initiator,
        send: k_send,
        recv: k_recv,
    }
}

/// Build keypairs for a link between two routers.
/// Returns (initiator_keypair, responder_keypair) with matching key material.
fn make_link_keypairs(
    key_a: [u8; 32],
    key_b: [u8; 32],
    id_a: u32,
    id_b: u32,
) -> (KeyPair, KeyPair) {
    // Initiator: send=key_a/id_a, recv=key_b/id_b
    let initiator = custom_keypair(true, key_a, key_b, id_a, id_b);
    // Responder: send=key_b/id_b, recv=key_a/id_a (mirror of initiator)
    let responder = custom_keypair(false, key_b, key_a, id_b, id_a);
    (initiator, responder)
}

use ironguard_platform::tun::Reader as _;

// --- Forwarding tests ---

/// Test that an intermediate node (B) forwards transit traffic to the
/// correct next-hop peer (C) instead of delivering it to TUN.
///
/// Topology: A --[link_ab]--> B --[forward]--> C
///
/// A sends a packet with dst=192.168.3.1. B has forwarding enabled with
/// local_addresses=[192.168.2.1]. B's forwarding table maps 192.168.3.0/24
/// to peer_b_to_c. The packet should arrive at C, and B should NOT write
/// to its TUN.
#[tokio::test]
async fn test_forwarding_to_next_hop() {
    // -- Key material for two independent links --
    // Link A<->B: keys 0x53/0x52, IDs 0x0001/0x0002
    let (kp_ab_init, kp_ab_resp) = make_link_keypairs([0x53; 32], [0x52; 32], 0x0001, 0x0002);
    // Link B<->C: keys 0x61/0x62, IDs 0x0003/0x0004
    let (kp_bc_init, kp_bc_resp) = make_link_keypairs([0x61; 32], [0x62; 32], 0x0003, 0x0004);

    // -- UDP pairs --
    // Pair 1: A -> B
    // writer_a (index 1) goes to router A; readers_a (index 3) is where
    // the test reads A's outbound (tx_a -> rx_a).
    let (_, udp_ab_writer, _, udp_ab_readers, _, _) = dummy_udp::create_pair();

    // Pair 2: B -> C
    // writer_b (index 4) goes to router B; readers_b (index 0) is where
    // the test reads B's outbound (tx_b -> rx_b).
    let (udp_bc_readers, _, _, _, udp_bc_writer, _) = dummy_udp::create_pair();

    // -- TUN pairs --
    // For B we need to observe that TUN does NOT receive the forwarded packet.
    let (_, tun_b_writer, tun_b_readers, _) = dummy_tun::create_pair();
    // For C we need to observe that TUN DOES receive the forwarded packet.
    let (_, tun_c_writer, tun_c_readers, _) = dummy_tun::create_pair();
    // A doesn't need TUN observation.
    let (_, tun_a_writer, _, _) = dummy_tun::create_pair();

    // -- Create routers --
    let router_a = make_test_router(tun_a_writer, udp_ab_writer);
    let router_b = make_test_router(tun_b_writer, udp_bc_writer);
    let router_c = make_test_router(tun_c_writer, dummy_udp::DummyUdpWriter::new_sink());

    // -- Router A: peer toward B --
    let opaque_a = Opaque::new();
    let peer_a_to_b = router_a.new_peer(opaque_a.clone());
    // A routes 192.168.2.0/24 and 192.168.3.0/24 toward B
    peer_a_to_b.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer_a_to_b.add_allowed_ip("192.168.3.0".parse().unwrap(), 24);
    peer_a_to_b.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:1001".parse().unwrap(),
    ));

    // -- Router B: peer from A, peer toward C --
    let opaque_b_from_a = Opaque::new();
    let peer_b_from_a = router_b.new_peer(opaque_b_from_a.clone());
    // B accepts traffic sourced from A's 192.168.1.0/24
    peer_b_from_a.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    let opaque_b_to_c = Opaque::new();
    let peer_b_to_c = router_b.new_peer(opaque_b_to_c.clone());
    // B routes 192.168.3.0/24 toward C (for outbound)
    peer_b_to_c.add_allowed_ip("192.168.3.0".parse().unwrap(), 24);
    peer_b_to_c.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:1002".parse().unwrap(),
    ));

    // -- Router C: peer from B --
    let opaque_c = Opaque::new();
    let peer_c_from_b = router_c.new_peer(opaque_c.clone());
    // C accepts traffic sourced from 192.168.1.0/24 (forwarded from A through B)
    peer_c_from_b.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    // -- Configure B's forwarding --
    router_b.set_forwarding_enabled(true);
    router_b.add_local_address("192.168.2.1".parse().unwrap());
    router_b.add_forwarding_route("192.168.3.0".parse().unwrap(), 24, &peer_b_to_c);

    // -- Install keypairs --

    // Link A<->B: peer_a_to_b is initiator, peer_b_from_a is responder
    peer_b_from_a.add_keypair(kp_ab_resp);
    peer_a_to_b.add_keypair(kp_ab_init);

    // A sends keepalive (initiator auto-sends on keypair add)
    let send_evt = opaque_a.send.wait(TIMEOUT);
    assert!(send_evt.is_some(), "A should send keepalive to B");

    // Read keepalive from A, pass to B
    let reader_ab = &udp_ab_readers[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process A's keepalive");

    assert!(
        opaque_b_from_a.recv.wait(TIMEOUT).is_some(),
        "B should receive A's keepalive"
    );
    assert_eq!(
        opaque_b_from_a.key_confirmed.wait(TIMEOUT),
        Some(()),
        "B should confirm A's key"
    );

    // Link B<->C: peer_b_to_c is initiator, peer_c_from_b is responder
    peer_c_from_b.add_keypair(kp_bc_resp);
    peer_b_to_c.add_keypair(kp_bc_init);

    // B sends keepalive to C (initiator auto-sends)
    let send_evt = opaque_b_to_c.send.wait(TIMEOUT);
    assert!(send_evt.is_some(), "B should send keepalive to C");

    // Read keepalive from B, pass to C
    let reader_bc = &udp_bc_readers[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_bc.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_c
        .recv(from, buf)
        .expect("C should process B's keepalive");

    assert!(
        opaque_c.recv.wait(TIMEOUT).is_some(),
        "C should receive B's keepalive"
    );
    assert_eq!(
        opaque_c.key_confirmed.wait(TIMEOUT),
        Some(()),
        "C should confirm B's key"
    );

    // -- Send a packet from A destined for C's network --
    let ip_pkt = make_ipv4_packet(
        "192.168.1.10".parse().unwrap(),
        "192.168.3.1".parse().unwrap(),
        50,
    );
    router_a
        .send(pad(&ip_pkt))
        .expect("A should route toward B");

    // A's send callback fires
    assert!(
        opaque_a.send.wait(TIMEOUT).is_some(),
        "A send event should fire"
    );

    // Read encrypted packet from A, pass to B
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process A's data packet");

    // B receives and processes the packet (recv callback fires)
    assert!(
        opaque_b_from_a.recv.wait(TIMEOUT).is_some(),
        "B should fire recv for A's packet"
    );

    // B forwards: peer_b_to_c.send() triggers send callback
    assert!(
        opaque_b_to_c.send.wait(TIMEOUT).is_some(),
        "B should send forwarded packet toward C"
    );

    // Read forwarded encrypted packet from B, pass to C
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_bc.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_c
        .recv(from, buf)
        .expect("C should process B's forwarded packet");

    // C receives the packet (recv callback fires) and writes to TUN
    assert!(
        opaque_c.recv.wait(TIMEOUT).is_some(),
        "C should fire recv for forwarded packet"
    );

    // Verify C's TUN received the decrypted packet
    let tun_reader_c = &tun_c_readers[0];
    let mut tun_buf = vec![0u8; 4096];
    let tun_len = tun_reader_c.read(&mut tun_buf, 0).await.unwrap();
    assert!(tun_len > 0, "C's TUN should receive the decrypted packet");
    // Verify the destination IP in the delivered packet
    assert_eq!(tun_buf[16], 192);
    assert_eq!(tun_buf[17], 168);
    assert_eq!(tun_buf[18], 3);
    assert_eq!(tun_buf[19], 1);

    // Verify B's TUN did NOT receive the packet (forwarded, not local)
    std::thread::sleep(Duration::from_millis(100));
    let tun_reader_b = &tun_b_readers[0];
    // Try to read with a very short timeout -- nothing should be there.
    // We use tokio::time::timeout since the TUN reader blocks.
    let tun_b_result = tokio::time::timeout(
        Duration::from_millis(200),
        tun_reader_b.read(&mut vec![0u8; 4096], 0),
    )
    .await;
    assert!(
        tun_b_result.is_err(),
        "B's TUN should NOT receive the forwarded packet"
    );
}

/// Test that when forwarding is enabled, packets destined for a local
/// address are still delivered to TUN (not forwarded).
///
/// Same topology as above, but the packet dst=192.168.2.1 matches B's
/// local_addresses, so B should write to TUN.
#[tokio::test]
async fn test_local_delivery_when_forwarding_enabled() {
    // -- Key material for link A<->B --
    let (kp_ab_init, kp_ab_resp) = make_link_keypairs([0x53; 32], [0x52; 32], 0x0001, 0x0002);

    // -- UDP pair A -> B --
    // writer_a (index 1) goes to router A; readers_a (index 3) is where
    // the test reads A's outbound (tx_a -> rx_a).
    let (_, udp_ab_writer, _, udp_ab_readers, _, _) = dummy_udp::create_pair();

    // -- TUN for B (we observe it) --
    let (_, tun_b_writer, tun_b_readers, _) = dummy_tun::create_pair();

    // A doesn't need TUN observation
    let (_, tun_a_writer, _, _) = dummy_tun::create_pair();

    // -- Create routers --
    // B gets a sink UDP writer since we don't need outbound in this test
    let router_a = make_test_router(tun_a_writer, udp_ab_writer);
    let router_b = make_test_router(tun_b_writer, dummy_udp::DummyUdpWriter::new_sink());

    // -- Router A: peer toward B --
    let opaque_a = Opaque::new();
    let peer_a_to_b = router_a.new_peer(opaque_a.clone());
    peer_a_to_b.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer_a_to_b.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:1001".parse().unwrap(),
    ));

    // -- Router B: peer from A --
    let opaque_b = Opaque::new();
    let peer_b_from_a = router_b.new_peer(opaque_b.clone());
    peer_b_from_a.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    // -- Configure B's forwarding (enabled, but packet is local) --
    router_b.set_forwarding_enabled(true);
    router_b.add_local_address("192.168.2.1".parse().unwrap());

    // -- Install keypairs and exchange keepalive --
    peer_b_from_a.add_keypair(kp_ab_resp);
    peer_a_to_b.add_keypair(kp_ab_init);

    // A sends keepalive
    assert!(
        opaque_a.send.wait(TIMEOUT).is_some(),
        "A should send keepalive"
    );

    let reader_ab = &udp_ab_readers[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process keepalive");

    assert!(
        opaque_b.recv.wait(TIMEOUT).is_some(),
        "B should receive keepalive"
    );
    assert_eq!(
        opaque_b.key_confirmed.wait(TIMEOUT),
        Some(()),
        "B should confirm key"
    );

    // -- Send a packet from A with dst matching B's local address --
    let ip_pkt = make_ipv4_packet(
        "192.168.1.10".parse().unwrap(),
        "192.168.2.1".parse().unwrap(),
        50,
    );
    router_a
        .send(pad(&ip_pkt))
        .expect("A should route toward B");

    assert!(
        opaque_a.send.wait(TIMEOUT).is_some(),
        "A send event should fire"
    );

    // Read encrypted packet from A, pass to B
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process data packet");

    // B receives the packet (recv callback fires)
    assert!(
        opaque_b.recv.wait(TIMEOUT).is_some(),
        "B should fire recv callback"
    );

    // B should deliver to TUN (dst matches local address)
    let tun_reader_b = &tun_b_readers[0];
    let mut tun_buf = vec![0u8; 4096];
    let tun_result = tokio::time::timeout(TIMEOUT, tun_reader_b.read(&mut tun_buf, 0)).await;
    assert!(
        tun_result.is_ok(),
        "B's TUN should receive the packet (local delivery)"
    );
    let tun_len = tun_result.unwrap().unwrap();
    assert!(tun_len > 0, "B's TUN should have data");
    // Verify it's the right packet
    assert_eq!(tun_buf[16], 192);
    assert_eq!(tun_buf[17], 168);
    assert_eq!(tun_buf[18], 2);
    assert_eq!(tun_buf[19], 1);
}

/// Test that when forwarding is DISABLED, packets are always delivered
/// to TUN regardless of destination address.
#[tokio::test]
async fn test_forwarding_disabled_delivers_to_tun() {
    // -- Key material for link A<->B --
    let (kp_ab_init, kp_ab_resp) = make_link_keypairs([0x53; 32], [0x52; 32], 0x0001, 0x0002);

    // -- UDP pair A -> B --
    // writer_a (index 1) goes to router A; readers_a (index 3) is where
    // the test reads A's outbound (tx_a -> rx_a).
    let (_, udp_ab_writer, _, udp_ab_readers, _, _) = dummy_udp::create_pair();

    // -- TUN for B (we observe it) --
    let (_, tun_b_writer, tun_b_readers, _) = dummy_tun::create_pair();

    // A doesn't need TUN observation
    let (_, tun_a_writer, _, _) = dummy_tun::create_pair();

    // -- Create routers --
    let router_a = make_test_router(tun_a_writer, udp_ab_writer);
    let router_b = make_test_router(tun_b_writer, dummy_udp::DummyUdpWriter::new_sink());

    // -- Router A: peer toward B --
    let opaque_a = Opaque::new();
    let peer_a_to_b = router_a.new_peer(opaque_a.clone());
    peer_a_to_b.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);
    peer_a_to_b.add_allowed_ip("192.168.3.0".parse().unwrap(), 24);
    peer_a_to_b.set_endpoint(dummy_udp::DummyEndpoint::from_address(
        "127.0.0.1:1001".parse().unwrap(),
    ));

    // -- Router B: peer from A --
    let opaque_b = Opaque::new();
    let peer_b_from_a = router_b.new_peer(opaque_b.clone());
    peer_b_from_a.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    // B has local_addresses set but forwarding is DISABLED (default)
    router_b.add_local_address("192.168.2.1".parse().unwrap());
    // forwarding_enabled is false by default -- do NOT call set_forwarding_enabled

    // -- Install keypairs and exchange keepalive --
    peer_b_from_a.add_keypair(kp_ab_resp);
    peer_a_to_b.add_keypair(kp_ab_init);

    assert!(
        opaque_a.send.wait(TIMEOUT).is_some(),
        "A should send keepalive"
    );

    let reader_ab = &udp_ab_readers[0];
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process keepalive");

    assert!(
        opaque_b.recv.wait(TIMEOUT).is_some(),
        "B should receive keepalive"
    );
    assert_eq!(
        opaque_b.key_confirmed.wait(TIMEOUT),
        Some(()),
        "B should confirm key"
    );

    // -- Send a packet from A with dst=192.168.3.1 (NOT B's local address) --
    // With forwarding disabled, this should still go to TUN.
    let ip_pkt = make_ipv4_packet(
        "192.168.1.10".parse().unwrap(),
        "192.168.3.1".parse().unwrap(),
        50,
    );
    router_a
        .send(pad(&ip_pkt))
        .expect("A should route toward B");

    assert!(
        opaque_a.send.wait(TIMEOUT).is_some(),
        "A send event should fire"
    );

    // Read encrypted packet from A, pass to B
    let mut buf = vec![0u8; 4096];
    let (len, from) = reader_ab.read(&mut buf).await.unwrap();
    buf.truncate(len);
    router_b
        .recv(from, buf)
        .expect("B should process data packet");

    // B receives the packet (recv callback fires)
    assert!(
        opaque_b.recv.wait(TIMEOUT).is_some(),
        "B should fire recv callback"
    );

    // B should deliver to TUN (forwarding disabled, normal behavior)
    let tun_reader_b = &tun_b_readers[0];
    let mut tun_buf = vec![0u8; 4096];
    let tun_result = tokio::time::timeout(TIMEOUT, tun_reader_b.read(&mut tun_buf, 0)).await;
    assert!(
        tun_result.is_ok(),
        "B's TUN should receive the packet (forwarding disabled)"
    );
    let tun_len = tun_result.unwrap().unwrap();
    assert!(tun_len > 0, "B's TUN should have data");
    // Verify destination IP is 192.168.3.1
    assert_eq!(tun_buf[16], 192);
    assert_eq!(tun_buf[17], 168);
    assert_eq!(tun_buf[18], 3);
    assert_eq!(tun_buf[19], 1);
}
