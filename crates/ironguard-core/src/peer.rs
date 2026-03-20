use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::constants::*;
use crate::router;
use crate::timers::Timers;
use crate::types::{KeyPair, PublicKey};
use crate::workers::HandshakeJob;

use ironguard_platform::tun;
use ironguard_platform::udp;

/// Time horizon used to initialise timestamps in the past.
const TIME_HORIZON: std::time::Duration = std::time::Duration::from_secs(3600);

/// The WireGuard-layer peer state.  One instance per configured peer.
///
/// This type is stored as `C::Opaque` inside the router and as the value in
/// the handshake `Device<PeerHandle>` map.  It carries:
///
/// - A back-reference to the parent `WireGuard` device (via `Arc`)
/// - The peer's static public key
/// - Stats (rx_bytes, tx_bytes)
/// - Timer state (`Timers`)
/// - Handshake bookkeeping (rate-limiting, queued flag)
pub struct PeerInner<T: tun::Tun, B: udp::Udp> {
    // internal id (for logging)
    pub id: u64,

    // back-reference to the device
    pub wg: crate::device::WireGuard<T, B>,

    // peer's static public key
    pub pk: PublicKey,

    // handshake state
    pub walltime_last_handshake: Mutex<Option<SystemTime>>,
    pub last_handshake_sent: Mutex<Instant>,
    pub handshake_queued: AtomicBool,

    // stats
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,

    // timer model
    pub timers: RwLock<Timers>,
}

impl<T: tun::Tun, B: udp::Udp> PeerInner<T, B> {
    pub fn new(
        id: u64,
        pk: PublicKey,
        wg: crate::device::WireGuard<T, B>,
        enabled: bool,
    ) -> Self {
        Self {
            id,
            wg,
            pk,
            walltime_last_handshake: Mutex::new(None),
            last_handshake_sent: Mutex::new(Instant::now() - TIME_HORIZON),
            handshake_queued: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            timers: RwLock::new(Timers::new(enabled)),
        }
    }

    #[inline(always)]
    pub fn timers(&self) -> RwLockReadGuard<'_, Timers> {
        self.timers.read()
    }

    #[inline(always)]
    pub fn timers_mut(&self) -> RwLockWriteGuard<'_, Timers> {
        self.timers.write()
    }

    pub fn get_keepalive_interval(&self) -> u64 {
        self.timers().keepalive_interval()
    }

    pub fn stop_timers(&self) {
        self.timers_mut().stop();
    }

    pub fn start_timers(&self) {
        self.timers_mut().start();
    }

    // ── timer event forwarding ───────────────────────────────────────────

    pub fn timers_data_sent(&self) {
        self.timers().timers_data_sent();
    }

    pub fn timers_data_received(&self) {
        self.timers().timers_data_received();
    }

    pub fn timers_any_authenticated_packet_sent(&self) {
        self.timers().timers_any_authenticated_packet_sent();
    }

    pub fn timers_any_authenticated_packet_received(&self) {
        self.timers().timers_any_authenticated_packet_received();
    }

    pub fn timers_handshake_complete(&self) {
        self.timers().timers_handshake_complete();
        *self.walltime_last_handshake.lock() = Some(SystemTime::now());
    }

    pub fn timers_session_derived(&self) {
        self.timers().timers_session_derived();
    }

    pub fn timers_any_authenticated_packet_traversal(&self) {
        self.timers().timers_any_authenticated_packet_traversal();
    }

    pub fn sent_handshake_initiation(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers().sent_handshake_initiation();
    }

    pub fn sent_handshake_response(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers().sent_handshake_response();
    }

    pub fn set_persistent_keepalive_interval(&self, secs: u64) {
        self.timers_mut().set_keepalive_interval(secs);
    }

    // ── handshake initiation ─────────────────────────────────────────────

    /// Queue a handshake request for the parallel workers (rate-limited).
    pub fn packet_send_handshake_initiation(&self) {
        // rate limit
        {
            let mut lhs = self.last_handshake_sent.lock();
            if lhs.elapsed() < REKEY_TIMEOUT {
                return;
            }
            *lhs = Instant::now();
        }

        if !self.handshake_queued.swap(true, Ordering::SeqCst) {
            self.wg.pending.fetch_add(1, Ordering::SeqCst);
            self.wg.queue.send(HandshakeJob::New(self.pk.clone()));
        }
    }

    /// Variant used by the retransmit timer: resets attempts if not a retry.
    pub fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timers().timers_handshake_complete(); // reset attempts to 0
        }
        self.packet_send_handshake_initiation();
    }
}

impl<T: tun::Tun, B: udp::Udp> fmt::Display for PeerInner<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer(id = {})", self.id)
    }
}

// ── router::Callbacks implementation ─────────────────────────────────────

/// The size of an empty encrypted transport message (header + tag, no payload).
fn message_data_len(payload_len: usize) -> usize {
    // TransportHeader(16) + payload + poly1305 tag(16)
    16 + payload_len + 16
}

impl<T: tun::Tun, B: udp::Udp> router::Callbacks for PeerInner<T, B> {
    type Opaque = Self;

    fn send(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64) {
        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_sent();
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);

        if size > message_data_len(0) && sent {
            peer.timers_data_sent();
        }

        // keep-key-fresh: rekey if counter or time thresholds exceeded
        let should_rekey = counter > REKEY_AFTER_MESSAGES
            || (keypair.initiator && Instant::now() - keypair.birth > REKEY_AFTER_TIME);
        if should_rekey {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    fn recv(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>) {
        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_received();
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);

        if size > 0 && sent {
            peer.timers_data_received();
        }

        // last-minute handshake: initiate rekey if key is about to expire
        let near_expiry =
            Instant::now() - keypair.birth > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
        if near_expiry
            && !peer
                .timers()
                .sent_lastminute_handshake()
                .swap(true, Ordering::Acquire)
        {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    fn need_key(peer: &Self::Opaque) {
        peer.packet_send_queued_handshake_initiation(false);
    }

    fn key_confirmed(peer: &Self::Opaque) {
        peer.timers_handshake_complete();
    }
}
