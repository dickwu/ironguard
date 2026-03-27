use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use spin::{Mutex, RwLock};
use tokio::sync::mpsc as tokio_mpsc;

use crate::constants::SIZE_MESSAGE_PREFIX;
use crate::types::KeyPair;
use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use super::anti_replay::AntiReplay;
use super::constants::PARALLEL_QUEUE_SIZE;
use super::messages_v2::{FrameHeader, HEADER_SIZE};
use super::peer::{Peer, PeerHandle, new_peer};
use super::queue::ParallelQueue;
use super::receive::ReceiveJob;
use super::route::RoutingTable;
use super::types::{Callbacks, RouterError};
use super::worker::{JobUnion, worker};

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    // type markers (actual writers live in dedicated write worker tasks)
    pub(super) _tun_writer: PhantomData<T>,
    pub(super) _udp_writer: PhantomData<B>,

    // outbound state: enabled flag and "writer has been configured" flag
    pub(super) outbound_enabled: RwLock<bool>,
    pub(super) outbound_ready: AtomicBool,

    // bounded channel for TUN writes (buffer, IP-data offset)
    pub(super) tun_write_tx: tokio_mpsc::Sender<(Vec<u8>, usize)>,

    // bounded channel for UDP writes (buffer, wire-data offset, endpoint)
    pub(super) udp_write_tx: tokio_mpsc::Sender<(Vec<u8>, usize, E)>,

    // routing
    #[allow(clippy::type_complexity)]
    pub(super) recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>,
    pub(super) table: RoutingTable<Peer<E, C, T, B>>,

    // mesh forwarding
    pub forwarding_enabled: AtomicBool,
    pub local_addresses: RwLock<Vec<IpAddr>>,
    pub forwarding_table: RoutingTable<Peer<E, C, T, B>>,

    // work queue
    pub(super) work: ParallelQueue<JobUnion<E, C, T, B>>,
}

pub struct EncryptionState {
    pub(super) keypair: Arc<KeyPair>,
    pub(super) nonce: u64,
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    pub(super) keypair: Arc<KeyPair>,
    pub(super) confirmed: AtomicBool,
    pub(super) protector: Mutex<AntiReplay>,
    pub(super) peer: Peer<E, C, T, B>,
}

pub struct Device<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    inner: Arc<DeviceInner<E, C, T, B>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone for Device<E, C, T, B> {
    fn clone(&self) -> Self {
        Device {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> PartialEq
    for Device<E, C, T, B>
{
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Eq for Device<E, C, T, B> {}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Deref for Device<E, C, T, B> {
    type Target = DeviceInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Top-level handle for the router device. Spawns worker threads and
/// tears them down on drop.
pub struct DeviceHandle<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    state: Device<E, C, T, B>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Drop
    for DeviceHandle<E, C, T, B>
{
    fn drop(&mut self) {
        // close worker queue
        self.state.work.close();

        // join all worker threads
        while let Some(handle) = self.handles.pop() {
            handle.thread().unpark();
            handle.join().unwrap();
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> DeviceHandle<E, C, T, B> {
    pub fn new(
        num_workers: usize,
        tun_write_tx: tokio_mpsc::Sender<(Vec<u8>, usize)>,
        udp_write_tx: tokio_mpsc::Sender<(Vec<u8>, usize, E)>,
    ) -> DeviceHandle<E, C, T, B> {
        let (work, mut consumers) = ParallelQueue::new(num_workers, PARALLEL_QUEUE_SIZE);

        let device = Device {
            inner: Arc::new(DeviceInner {
                work,
                _tun_writer: PhantomData,
                _udp_writer: PhantomData,
                outbound_enabled: RwLock::new(true),
                outbound_ready: AtomicBool::new(false),
                tun_write_tx,
                udp_write_tx,
                recv: RwLock::new(HashMap::new()),
                table: RoutingTable::new(),
                forwarding_enabled: AtomicBool::new(false),
                local_addresses: RwLock::new(Vec::new()),
                forwarding_table: RoutingTable::new(),
            }),
        };

        let mut threads = Vec::with_capacity(num_workers);
        while let Some(rx) = consumers.pop() {
            threads.push(thread::spawn(move || worker(rx)));
        }
        debug_assert!(num_workers > 0, "zero worker threads");
        debug_assert_eq!(threads.len(), num_workers);

        DeviceHandle {
            state: device,
            handles: threads,
        }
    }

    pub fn send_raw(&self, msg: &[u8], dst: &mut E) -> Result<(), RouterError> {
        if *self.state.outbound_enabled.read() && self.state.outbound_ready.load(Ordering::Acquire)
        {
            // Offset 0: the entire buffer is wire data (handshake messages).
            let _ = self
                .state
                .udp_write_tx
                .try_send((msg.to_vec(), 0, dst.clone()));
        }
        Ok(())
    }

    /// Relay a raw encrypted packet to the given address without decryption.
    ///
    /// Used by the opaque relay path: when a packet's receiver ID matches
    /// an entry in the relay table, the packet is forwarded as-is to the
    /// target address. No cryptographic processing is performed.
    pub fn relay_raw(&self, msg: Vec<u8>, target: std::net::SocketAddr) {
        if *self.state.outbound_enabled.read() && self.state.outbound_ready.load(Ordering::Acquire)
        {
            let ep = E::from_address(target);
            let _ = self.state.udp_write_tx.try_send((msg, 0, ep));
        }
    }

    /// Brings the router down (prevents outbound transmission).
    pub fn down(&self) {
        *self.state.outbound_enabled.write() = false;
    }

    /// Brings the router up (enables outbound transmission).
    pub fn up(&self) {
        *self.state.outbound_enabled.write() = true;
    }

    /// Adds a new peer to the device.
    pub fn new_peer(&self, opaque: C::Opaque) -> PeerHandle<E, C, T, B> {
        new_peer(self.state.clone(), opaque)
    }

    /// Cryptkey routes and sends a plaintext message (IP packet).
    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        debug_assert!(msg.len() > SIZE_MESSAGE_PREFIX);

        // ignore header prefix (for in-place transport message construction)
        let packet = &msg[SIZE_MESSAGE_PREFIX..];

        // lookup peer based on IP packet destination address
        let peer = self
            .state
            .table
            .get_route(packet)
            .ok_or(RouterError::NoCryptoKeyRoute)?;

        // schedule for encryption and transmission to peer
        peer.send(msg, true);
        Ok(())
    }

    /// Receive an encrypted transport message.
    pub fn recv(&self, src: E, msg: Vec<u8>) -> Result<(), RouterError> {
        // parse v2 frame header
        if msg.len() < HEADER_SIZE {
            return Err(RouterError::MalformedTransportMessage);
        }

        let header = FrameHeader::from_bytes(&msg).ok_or(RouterError::MalformedTransportMessage)?;

        let receiver_id = header.receiver_id();

        // lookup peer based on receiver id
        let dec = self.state.recv.read();
        let dec = dec
            .get(&receiver_id)
            .ok_or(RouterError::UnknownReceiverId)?;

        // create inbound job
        let job = ReceiveJob::new(msg, dec.clone(), src);

        // 1. add to sequential queue (drop if full)
        // 2. then add to parallel work queue
        if dec.peer.inbound.push(job.clone()) {
            self.state.work.send(JobUnion::Inbound(job));
        }
        Ok(())
    }

    /// Mark that an outbound writer has been configured.
    /// The actual writer is owned by the UDP write worker task.
    pub fn set_outbound_ready(&self) {
        self.state.outbound_ready.store(true, Ordering::Release);
    }

    /// Add a local VPN address. Packets destined for a local address are
    /// delivered to TUN; all others may be forwarded to another peer when
    /// forwarding is enabled.
    pub fn add_local_address(&self, addr: IpAddr) {
        self.state.local_addresses.write().push(addr);
    }

    /// Enable or disable L3 forwarding through this device. When enabled,
    /// inbound packets whose destination does not match a local address are
    /// re-encrypted and sent to the next-hop peer found in the forwarding
    /// table.
    pub fn set_forwarding_enabled(&self, enabled: bool) {
        self.state
            .forwarding_enabled
            .store(enabled, Ordering::Release);
    }

    /// Insert a route into the forwarding table. The forwarding table is
    /// separate from the main crypto-key routing table and is consulted
    /// only when forwarding is enabled for transit traffic.
    pub fn add_forwarding_route(&self, ip: IpAddr, masklen: u32, peer: &PeerHandle<E, C, T, B>) {
        self.state
            .forwarding_table
            .insert(ip, masklen, peer.peer().clone());
    }
}
