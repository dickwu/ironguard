use crate::constants::{REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX};
use crate::types::KeyPair;

use super::messages_v2::{FrameHeader, HEADER_SIZE};
use super::peer::Peer;
use super::queue::{ParallelJob, Queue, SequentialJob};
use super::types::Callbacks;

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ring::aead::{Aad, Nonce};
use spin::Mutex;

const SIZE_TAG: usize = 16;

/// Offset where the v2 frame header is written in the buffer.
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

            // Extend the buffer for the AEAD tag. In production, tun_worker
            // pre-allocates CAPACITY_MESSAGE_POSTFIX (16) extra bytes so the
            // fast path avoids zeroing. For test code or other callers that
            // don't pre-size, fall back to resize.
            let tag_end = msg.len() + SIZE_TAG;
            if tag_end <= msg.capacity() {
                // SAFETY: tag_end <= capacity. The 16 bytes will be
                // overwritten by copy_from_slice below before any read.
                unsafe { msg.set_len(tag_end) };
            } else {
                msg.resize(tag_end, 0);
            }

            debug_assert!(
                job.counter < REJECT_AFTER_MESSAGES,
                "should be checked when assigning counters"
            );

            // Construct v2 frame header and write it at HEADER_OFFSET
            let frame = FrameHeader::new_data(job.keypair.send.id, job.counter);
            msg[HEADER_OFFSET..HEADER_OFFSET + HEADER_SIZE].copy_from_slice(frame.as_bytes());

            // Encrypt IP packet data (starts at SIZE_MESSAGE_PREFIX, ends before tag)
            let end = msg.len() - SIZE_TAG;
            let plaintext = &mut msg[SIZE_MESSAGE_PREFIX..end];

            // create nonce
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&job.counter.to_le_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            // Use the cached pre-expanded AES-256-GCM key to avoid per-packet
            // key schedule overhead (~200ns saved per packet).
            let key = &job.keypair.send.cached_aead.aead;
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::from(frame.as_aad()), plaintext)
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
        debug_assert!(
            self.is_ready(),
            "doing sequential work on an incomplete job"
        );

        let job = &self.0;
        let mut guard = job.buffer.lock();

        if guard.len() <= HEADER_OFFSET {
            drop(guard);
            C::send(&job.peer.opaque, 0, false, &job.keypair, job.counter);
            return;
        }

        // Take ownership of the buffer to avoid a per-packet heap allocation
        // from wire_msg.to_vec(). The Mutex retains an empty Vec (no-op drop).
        let owned = std::mem::take(&mut *guard);
        drop(guard);

        // Wire data starts at HEADER_OFFSET (v2 header + ciphertext + AEAD tag).
        // Pass the offset to the UDP write worker instead of draining, avoiding
        // a per-packet memmove of ~1500 bytes.
        let wire_len = owned.len() - HEADER_OFFSET;

        // Dispatch to the UDP write channel (non-blocking).
        let xmit = {
            let endpoint = job.peer.endpoint.lock().clone();
            match endpoint {
                Some(ep) => {
                    let enabled = *job.peer.device.outbound_enabled.read();
                    let ready = job
                        .peer
                        .device
                        .outbound_ready
                        .load(core::sync::atomic::Ordering::Acquire);
                    if enabled && ready {
                        let result =
                            job.peer
                                .device
                                .udp_write_tx
                                .try_send((owned, HEADER_OFFSET, ep));
                        result.is_ok()
                    } else {
                        tracing::debug!(
                            enabled = enabled,
                            ready = ready,
                            "send_job: outbound not enabled/ready"
                        );
                        false
                    }
                }
                None => {
                    tracing::debug!("send_job: no endpoint set for peer");
                    false
                }
            }
        };

        C::send(&job.peer.opaque, wire_len, xmit, &job.keypair, job.counter);
    }
}
