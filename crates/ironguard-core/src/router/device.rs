use std::collections::HashMap;
use std::marker::PhantomData;
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
use super::messages::{TYPE_TRANSPORT, TransportHeader};
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

    // bounded channel for TUN writes (decrypted packets)
    pub(super) tun_write_tx: tokio_mpsc::Sender<Vec<u8>>,

    // bounded channel for UDP writes (encrypted packets + endpoint)
    pub(super) udp_write_tx: tokio_mpsc::Sender<(Vec<u8>, E)>,

    // routing
    #[allow(clippy::type_complexity)]
    pub(super) recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>,
    pub(super) table: RoutingTable<Peer<E, C, T, B>>,

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
        tun_write_tx: tokio_mpsc::Sender<Vec<u8>>,
        udp_write_tx: tokio_mpsc::Sender<(Vec<u8>, E)>,
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
            let _ = self
                .state
                .udp_write_tx
                .try_send((msg.to_vec(), dst.clone()));
        }
        Ok(())
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
        // parse transport header
        if msg.len() < std::mem::size_of::<TransportHeader>() {
            return Err(RouterError::MalformedTransportMessage);
        }

        let header = unsafe { &*(msg.as_ptr() as *const TransportHeader) };

        debug_assert!(
            header.message_type() == TYPE_TRANSPORT,
            "this should be checked by the message type multiplexer"
        );

        let receiver_id = header.receiver();

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
}
