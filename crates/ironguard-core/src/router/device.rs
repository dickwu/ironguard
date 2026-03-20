use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use spin::{Mutex, RwLock};
use tokio::runtime::Handle;

use crate::constants::SIZE_MESSAGE_PREFIX;
use crate::types::KeyPair;
use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use super::anti_replay::AntiReplay;
use super::constants::PARALLEL_QUEUE_SIZE;
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::{new_peer, Peer, PeerHandle};
use super::queue::ParallelQueue;
use super::receive::ReceiveJob;
use super::route::RoutingTable;
use super::types::{Callbacks, RouterError};
use super::worker::{worker, JobUnion};

/// Block on an async IO future from either an async task or a plain OS thread.
/// Uses `block_in_place` when called from within a Tokio runtime context
/// (e.g. from an async handshake worker), or `block_on` when called from a
/// plain OS thread (e.g. router crypto worker).
pub(super) fn block_on_io<F: std::future::Future>(handle: &Handle, fut: F) -> F::Output {
    match Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => handle.block_on(fut),
    }
}

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    // inbound writer (TUN)
    pub(super) inbound: T,

    // outbound writer (Bind)
    pub(super) outbound: RwLock<(bool, Option<B>)>,

    // routing
    #[allow(clippy::type_complexity)]
    pub(super) recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>,
    pub(super) table: RoutingTable<Peer<E, C, T, B>>,

    // work queue
    pub(super) work: ParallelQueue<JobUnion<E, C, T, B>>,

    // Tokio runtime handle for blocking on async IO from worker threads
    pub(super) rt_handle: Handle,
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

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone
    for Device<E, C, T, B>
{
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

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Eq
    for Device<E, C, T, B>
{
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Deref
    for Device<E, C, T, B>
{
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
    pub fn new(num_workers: usize, tun: T) -> DeviceHandle<E, C, T, B> {
        let (work, mut consumers) = ParallelQueue::new(num_workers, PARALLEL_QUEUE_SIZE);

        // Capture the current Tokio runtime handle so router worker threads
        // can block on async IO calls. Callers must ensure a Tokio runtime
        // context is active (e.g. via `runtime.enter()` or `#[tokio::test]`).
        let rt_handle = Handle::current();

        let device = Device {
            inner: Arc::new(DeviceInner {
                work,
                inbound: tun,
                outbound: RwLock::new((true, None)),
                recv: RwLock::new(HashMap::new()),
                table: RoutingTable::new(),
                rt_handle,
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
        let bind = self.state.outbound.read();
        if bind.0 {
            if let Some(bind) = bind.1.as_ref() {
                let fut = bind.write(msg, dst);
                return block_on_io(&self.state.rt_handle, fut)
                    .map_err(|_| RouterError::SendError);
            }
        }
        Ok(())
    }


    /// Brings the router down (prevents outbound transmission).
    pub fn down(&self) {
        self.state.outbound.write().0 = false;
    }

    /// Brings the router up (enables outbound transmission).
    pub fn up(&self) {
        self.state.outbound.write().0 = true;
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

        let header = unsafe {
            &*(msg.as_ptr() as *const TransportHeader)
        };

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

    /// Set outbound writer.
    pub fn set_outbound_writer(&self, new: B) {
        self.state.outbound.write().1 = Some(new);
    }
}
