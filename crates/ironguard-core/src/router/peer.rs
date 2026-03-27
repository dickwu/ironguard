use crate::constants::{REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX};
use crate::types::KeyPair;
use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use super::anti_replay::AntiReplay;
use super::constants::MAX_QUEUED_PACKETS;
use super::device::{DecryptionState, Device, EncryptionState};
use super::queue::Queue;
use super::receive::ReceiveJob;
use super::send::SendJob;
use super::types::{Callbacks, RouterError};
use super::worker::JobUnion;

use core::mem;
use core::ops::Deref;
use core::sync::atomic::AtomicBool;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arraydeque::{ArrayDeque, Wrapping};
use spin::Mutex;

/// Key rotation state: next (unconfirmed), current (encryption), previous (decryption).
pub struct KeyWheel {
    pub(super) next: Option<Arc<KeyPair>>,
    pub(super) current: Option<Arc<KeyPair>>,
    pub(super) previous: Option<Arc<KeyPair>>,
    pub(super) retired: Vec<u32>,
}

/// Interior state of a peer in the router.
pub struct PeerInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    pub(super) device: Device<E, C, T, B>,
    pub(super) opaque: C::Opaque,
    pub(super) outbound: Queue<SendJob<E, C, T, B>>,
    pub(super) inbound: Queue<ReceiveJob<E, C, T, B>>,
    pub(super) staged_packets: Mutex<ArrayDeque<Vec<u8>, MAX_QUEUED_PACKETS, Wrapping>>,
    pub(super) keys: Mutex<KeyWheel>,
    pub(super) enc_key: Mutex<Option<EncryptionState>>,
    pub(super) endpoint: Mutex<Option<E>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Deref
    for PeerInner<E, C, T, B>
{
    type Target = C::Opaque;
    fn deref(&self) -> &Self::Target {
        &self.opaque
    }
}

/// An Arc-wrapped reference to a peer's router state.
pub struct Peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    inner: Arc<PeerInner<E, C, T, B>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone for Peer<E, C, T, B> {
    fn clone(&self) -> Self {
        Peer {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> PartialEq
    for Peer<E, C, T, B>
{
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Eq for Peer<E, C, T, B> {}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Deref for Peer<E, C, T, B> {
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A handle that owns the peer and removes it from the device when dropped.
///
/// Clone is shallow (Arc-based).  Cleanup only runs when the *last*
/// PeerHandle is dropped.
pub struct PeerHandle<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    peer: Peer<E, C, T, B>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone
    for PeerHandle<E, C, T, B>
{
    fn clone(&self) -> Self {
        PeerHandle {
            peer: self.peer.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Deref
    for PeerHandle<E, C, T, B>
{
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> fmt::Display
    for PeerHandle<E, C, T, B>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerHandle")
    }
}

impl EncryptionState {
    fn new(keypair: &Arc<KeyPair>) -> EncryptionState {
        EncryptionState {
            nonce: 0,
            keypair: keypair.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> DecryptionState<E, C, T, B> {
    fn new(peer: Peer<E, C, T, B>, keypair: &Arc<KeyPair>) -> DecryptionState<E, C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
            peer,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Drop
    for PeerHandle<E, C, T, B>
{
    fn drop(&mut self) {
        // Only clean up when this is the last PeerHandle (the inner Arc has
        // one extra strong ref from the Peer inside this handle, so we
        // check for 2: one for the Peer inside `self.peer`, and one more
        // means another PeerHandle still exists).
        //
        // NOTE: PeerHandle wraps Peer which wraps Arc<PeerInner>.
        // The Peer's Arc strong count = number of Peer clones.
        // We only want to clean up when we are the *last* PeerHandle.
        if Arc::strong_count(&self.peer.inner) > 1 {
            return;
        }

        let peer = &self.peer;

        // remove from cryptkey router and forwarding table
        peer.device.table.remove(peer);
        peer.device.forwarding_table.remove(peer);

        // release ids from the receiver map
        let mut keys = peer.keys.lock();
        let mut release = Vec::with_capacity(3);

        if let Some(k) = keys.next.as_ref() {
            release.push(k.recv.id);
        }
        if let Some(k) = keys.current.as_ref() {
            release.push(k.recv.id);
        }
        if let Some(k) = keys.previous.as_ref() {
            release.push(k.recv.id);
        }

        if !release.is_empty() {
            let mut recv = peer.device.recv.write();
            for id in &release {
                recv.remove(id);
            }
        }

        // null key-material
        keys.next = None;
        keys.current = None;
        keys.previous = None;

        *peer.enc_key.lock() = None;
        *peer.endpoint.lock() = None;
    }
}

/// Create a new peer and return a PeerHandle.
pub fn new_peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>>(
    device: Device<E, C, T, B>,
    opaque: C::Opaque,
) -> PeerHandle<E, C, T, B> {
    let peer = Peer {
        inner: Arc::new(PeerInner {
            opaque,
            device,
            inbound: Queue::new(),
            outbound: Queue::new(),
            enc_key: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            keys: spin::Mutex::new(KeyWheel {
                next: None,
                current: None,
                previous: None,
                retired: vec![],
            }),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
        }),
    };

    PeerHandle { peer }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> PeerInner<E, C, T, B> {
    /// Send a raw message to the peer (used for handshake messages).
    /// Dispatches to the UDP write channel (non-blocking).
    pub fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError> {
        match self.endpoint.lock().clone() {
            Some(ep) => {
                if *self.device.outbound_enabled.read()
                    && self
                        .device
                        .outbound_ready
                        .load(core::sync::atomic::Ordering::Acquire)
                {
                    // Offset 0: handshake messages are wire-ready (no prefix).
                    self.device
                        .udp_write_tx
                        .try_send((msg.to_vec(), 0, ep))
                        .map_err(|_| RouterError::SendError)
                } else {
                    Ok(())
                }
            }
            None => Err(RouterError::NoEndpoint),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Peer<E, C, T, B> {
    /// Encrypt and send a message to the peer.
    pub(super) fn send(&self, msg: Vec<u8>, stage: bool) {
        let (job, need_key) = {
            let mut enc_key = self.enc_key.lock();
            match enc_key.as_mut() {
                None => {
                    if stage {
                        self.staged_packets.lock().push_back(msg);
                    }
                    (None, true)
                }
                Some(state) => {
                    // avoid integer overflow in nonce
                    if state.nonce >= REJECT_AFTER_MESSAGES - 1 {
                        *enc_key = None;
                        if stage {
                            self.staged_packets.lock().push_back(msg);
                        }
                        (None, true)
                    } else {
                        let job =
                            SendJob::new(msg, state.nonce, state.keypair.clone(), self.clone());
                        if self.outbound.push(job.clone()) {
                            state.nonce += 1;
                            (Some(job), false)
                        } else {
                            (None, false)
                        }
                    }
                }
            }
        };

        if need_key {
            C::need_key(&self.opaque);
        }

        if let Some(job) = job {
            self.device.work.send(JobUnion::Outbound(job));
        }
    }

    /// Transmit all staged packets. Returns true if any were sent.
    fn send_staged(&self) -> bool {
        let mut sent = false;
        let mut staged = self.staged_packets.lock();
        loop {
            match staged.pop_front() {
                Some(msg) => {
                    sent = true;
                    self.send(msg, false);
                }
                None => break sent,
            }
        }
    }

    /// Confirm a key by rotating the key wheel.
    pub(super) fn confirm_key(&self, keypair: &Arc<KeyPair>) {
        {
            let mut keys = self.keys.lock();
            let next = match keys.next.as_ref() {
                Some(next) => next,
                None => return,
            };
            if !Arc::ptr_eq(next, keypair) {
                return;
            }

            let ekey = Some(EncryptionState::new(next));

            // rotate key-wheel
            let mut swap = None;
            mem::swap(&mut keys.next, &mut swap);
            mem::swap(&mut keys.current, &mut swap);
            mem::swap(&mut keys.previous, &mut swap);

            C::key_confirmed(&self.opaque);

            *self.enc_key.lock() = ekey;
        }

        self.send_staged();
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> PeerHandle<E, C, T, B> {
    /// Return a reference to the inner `Peer` (for use by the device layer
    /// when populating the forwarding table).
    pub(super) fn peer(&self) -> &Peer<E, C, T, B> {
        &self.peer
    }

    /// Set the endpoint of the peer.
    pub fn set_endpoint(&self, endpoint: E) {
        *self.peer.endpoint.lock() = Some(endpoint);
    }

    pub fn opaque(&self) -> &C::Opaque {
        &self.opaque
    }

    /// Returns the current endpoint of the peer.
    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        self.peer.endpoint.lock().as_ref().map(|e| e.to_address())
    }

    /// Zero all key-material related to the peer.
    pub fn zero_keys(&self) {
        let mut release: Vec<u32> = Vec::with_capacity(3);
        let mut keys = self.peer.keys.lock();

        if let Some(k) = keys.next.take() {
            release.push(k.local_id());
        }
        if let Some(k) = keys.current.take() {
            release.push(k.local_id());
        }
        if let Some(k) = keys.previous.take() {
            release.push(k.local_id());
        }
        keys.retired.extend(&release[..]);

        {
            let mut recv = self.peer.device.recv.write();
            for id in release {
                recv.remove(&id);
            }
        }

        *self.peer.enc_key.lock() = None;
    }

    pub fn down(&self) {
        self.zero_keys();
    }

    pub fn up(&self) {}

    /// Add a new keypair to the peer. Returns a vector of retired receiver IDs.
    pub fn add_keypair(&self, new: KeyPair) -> Vec<u32> {
        let initiator = new.initiator;
        let release = {
            let new = Arc::new(new);
            let mut keys = self.peer.keys.lock();
            let mut release = std::mem::take(&mut keys.retired);

            if new.initiator {
                *self.peer.enc_key.lock() = Some(EncryptionState::new(&new));
                keys.previous = keys.current.as_ref().cloned();
                keys.current = Some(new.clone());
            } else {
                keys.previous = keys.next.as_ref().cloned();
                keys.next = Some(new.clone());
            }

            {
                let mut recv = self.peer.device.recv.write();
                if let Some(k) = &keys.previous {
                    recv.remove(&k.local_id());
                    release.push(k.local_id());
                }
                debug_assert!(!recv.contains_key(&new.recv.id));
                recv.insert(
                    new.recv.id,
                    Arc::new(DecryptionState::new(self.peer.clone(), &new)),
                );
            }
            release
        };

        if initiator {
            debug_assert!(self.peer.enc_key.lock().is_some());
            if !self.peer.send_staged() {
                self.send_keepalive();
            }
        }

        debug_assert!(release.len() <= 3);
        release
    }

    pub fn send_keepalive(&self) {
        self.peer.send(vec![0u8; SIZE_MESSAGE_PREFIX], false);
    }

    /// Map a subnet to the peer.
    pub fn add_allowed_ip(&self, ip: IpAddr, masklen: u32) {
        self.peer
            .device
            .table
            .insert(ip, masklen, self.peer.clone());
    }

    /// List subnets mapped to the peer.
    pub fn list_allowed_ips(&self) -> Vec<(IpAddr, u32)> {
        self.peer.device.table.list(&self.peer)
    }

    /// Remove all subnets for this peer.
    pub fn remove_allowed_ips(&self) {
        self.peer.device.table.remove(&self.peer);
    }

    pub fn clear_src(&self) {
        if let Some(e) = (*self.peer.endpoint.lock()).as_mut() {
            e.clear_src();
        }
    }

    pub fn purge_staged_packets(&self) {
        self.peer.staged_packets.lock().clear();
    }
}
