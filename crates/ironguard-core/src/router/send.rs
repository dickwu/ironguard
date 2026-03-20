use crate::constants::{REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX};
use crate::types::KeyPair;

use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::Peer;
use super::queue::{ParallelJob, Queue, SequentialJob};
use super::types::Callbacks;

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use std::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use spin::Mutex;

const SIZE_TAG: usize = 16;
const HEADER_SIZE: usize = std::mem::size_of::<TransportHeader>();

/// Offset where the transport header is written in the buffer.
/// The header sits just before the IP packet data at SIZE_MESSAGE_PREFIX.
const HEADER_OFFSET: usize = SIZE_MESSAGE_PREFIX - HEADER_SIZE;

struct Inner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    ready: AtomicBool,
    buffer: Mutex<Vec<u8>>,
    counter: u64,
    keypair: Arc<KeyPair>,
    peer: Peer<E, C, T, B>,
}

pub struct SendJob<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>>(
    Arc<Inner<E, C, T, B>>,
);

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone
    for SendJob<E, C, T, B>
{
    fn clone(&self) -> SendJob<E, C, T, B> {
        SendJob(self.0.clone())
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> SendJob<E, C, T, B> {
    pub fn new(
        buffer: Vec<u8>,
        counter: u64,
        keypair: Arc<KeyPair>,
        peer: Peer<E, C, T, B>,
    ) -> SendJob<E, C, T, B> {
        SendJob(Arc::new(Inner {
            buffer: Mutex::new(buffer),
            counter,
            keypair,
            peer,
            ready: AtomicBool::new(false),
        }))
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> ParallelJob
    for SendJob<E, C, T, B>
{
    fn queue(&self) -> &Queue<Self> {
        &self.0.peer.outbound
    }

    fn parallel_work(&self) {
        debug_assert!(!self.is_ready(), "doing parallel work on completed job");

        {
            let job = &*self.0;
            let mut msg = job.buffer.lock();

            // make space for the tag at the end
            msg.extend([0u8; SIZE_TAG].iter());

            debug_assert!(
                job.counter < REJECT_AFTER_MESSAGES,
                "should be checked when assigning counters"
            );

            // Write transport header at HEADER_OFFSET (just before the IP packet)
            let header = unsafe {
                &mut *(msg.as_mut_ptr().add(HEADER_OFFSET) as *mut TransportHeader)
            };
            header.set_type(TYPE_TRANSPORT);
            header.set_receiver(job.keypair.send.id);
            header.set_counter(job.counter);

            // Encrypt IP packet data (starts at SIZE_MESSAGE_PREFIX, ends before tag)
            let end = msg.len() - SIZE_TAG;
            let plaintext = &mut msg[SIZE_MESSAGE_PREFIX..end];

            // create nonce
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&job.counter.to_le_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let key = LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &job.keypair.send.key[..]).unwrap(),
            );
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), plaintext)
                .unwrap();

            // Write tag at the end
            let tag_start = msg.len() - SIZE_TAG;
            msg[tag_start..].copy_from_slice(tag.as_ref());
        }

        self.0.ready.store(true, Ordering::Release);
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> SequentialJob
    for SendJob<E, C, T, B>
{
    fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    fn sequential_work(self) {
        debug_assert!(self.is_ready(), "doing sequential work on an incomplete job");

        let job = &self.0;
        let msg = job.buffer.lock();

        // Send from HEADER_OFFSET to end (header + ciphertext + tag)
        let wire_msg = &msg[HEADER_OFFSET..];
        let xmit = job.peer.send_raw(wire_msg).is_ok();

        // Report the wire message size
        C::send(&job.peer.opaque, wire_msg.len(), xmit, &job.keypair, job.counter);
    }
}
