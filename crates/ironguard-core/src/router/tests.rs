use std::ops::Deref;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::constants::SIZE_MESSAGE_PREFIX;
use crate::types::{Key, KeyPair};

use super::device::DeviceHandle;
use super::messages::TransportHeader;
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
    let k1 = Key {
        key: [0x53u8; 32],
        id: 0x646e6573,
    };
    let k2 = Key {
        key: [0x52u8; 32],
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

// --- Tests ---

#[tokio::test]
async fn test_outbound_routing() {
    // Create a router with a dummy TUN and void UDP
    let (_, tun_writer, _, _) = dummy_tun::create_pair();
    let router: TestRouter = DeviceHandle::new(1, tun_writer);

    // Create a void UDP writer (sends into the void)
    let (_, udp_writer, _, _, _, _) = dummy_udp::create_pair();
    router.set_outbound_writer(udp_writer);

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
    let router: TestRouter = DeviceHandle::new(1, tun_writer);

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
    let router: TestRouter = DeviceHandle::new(1, tun_writer);

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

    let router1: TestRouter = DeviceHandle::new(1, tun_writer1);
    let router2: TestRouter = DeviceHandle::new(1, tun_writer2);

    // Connect via UDP pair
    let (udp_readers1, udp_writer1, _, udp_readers2, udp_writer2, _) = dummy_udp::create_pair();
    router1.set_outbound_writer(udp_writer1);
    router2.set_outbound_writer(udp_writer2);

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

    let router1: TestRouter = DeviceHandle::new(1, tun_writer1);
    let router2: TestRouter = DeviceHandle::new(1, tun_writer2);

    let (udp_readers1, udp_writer1, _, _, udp_writer2, _) = dummy_udp::create_pair();
    router1.set_outbound_writer(udp_writer1);
    router2.set_outbound_writer(udp_writer2);

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
    let router: TestRouter = DeviceHandle::new(1, tun_writer);

    let (_, udp_writer, _, _, _, _) = dummy_udp::create_pair();
    router.set_outbound_writer(udp_writer);

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
    let router: TestRouter = DeviceHandle::new(1, tun_writer);

    let (_, udp_writer, _, _, _, _) = dummy_udp::create_pair();
    router.set_outbound_writer(udp_writer);

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
    // keepalive wire message: header(16) + tag(16) = 32
    let keepalive_size = std::mem::size_of::<TransportHeader>() + 16;
    assert_eq!(size, keepalive_size, "keepalive should be header + tag");
}

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::udp::UdpReader;
