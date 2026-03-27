use crate::constants::{REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX};

use super::device::DecryptionState;
use super::ip::{extract_dest_ip, inner_length};
use super::messages_v2::{FrameHeader, HEADER_SIZE, TYPE_DATA, TYPE_KEEPALIVE};
use super::queue::{ParallelJob, Queue, SequentialJob};
use super::types::Callbacks;

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun;
use ironguard_platform::udp;

use core::sync::atomic::{AtomicBool, Ordering};
use ring::aead::{Aad, Nonce};
use spin::Mutex;
use std::sync::Arc;

const SIZE_TAG: usize = 16;

struct Inner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> {
    ready: AtomicBool,
    buffer: Mutex<(Option<E>, Vec<u8>)>,
    state: Arc<DecryptionState<E, C, T, B>>,
}

pub struct ReceiveJob<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>>(
    Arc<Inner<E, C, T, B>>,
);

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> Clone
    for ReceiveJob<E, C, T, B>
{
    fn clone(&self) -> ReceiveJob<E, C, T, B> {
        ReceiveJob(self.0.clone())
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> ReceiveJob<E, C, T, B> {
    pub fn new(
        buffer: Vec<u8>,
        state: Arc<DecryptionState<E, C, T, B>>,
        endpoint: E,
    ) -> ReceiveJob<E, C, T, B> {
        ReceiveJob(Arc::new(Inner {
            ready: AtomicBool::new(false),
            buffer: Mutex::new((Some(endpoint), buffer)),
            state,
        }))
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> ParallelJob
    for ReceiveJob<E, C, T, B>
{
    fn queue(&self) -> &Queue<Self> {
        &self.0.state.peer.inbound
    }

    fn parallel_work(&self) {
        debug_assert!(!self.is_ready(), "doing parallel work on completed job");

        // decrypt
        {
            let job = &self.0;
            let peer = &job.state.peer;
            let mut msg = job.buffer.lock();

            let ok = (|| {
                if msg.1.len() < HEADER_SIZE + SIZE_TAG {
                    tracing::debug!(len = msg.1.len(), "recv_job: too short for header+tag");
                    return false;
                }

                // parse v2 frame header (copy to local to release the immutable borrow)
                let header = match FrameHeader::from_bytes(&msg.1) {
                    Some(h) => *h,
                    None => {
                        tracing::debug!("recv_job: failed to parse frame header");
                        return false;
                    }
                };

                // verify message type (accept both DATA and KEEPALIVE frames)
                let mt = header.msg_type();
                if mt != TYPE_DATA && mt != TYPE_KEEPALIVE {
                    tracing::debug!(msg_type = mt, "recv_job: not a transport frame type");
                    return false;
                }

                let counter = header.counter();

                // Copy the AAD bytes before taking a mutable borrow on the buffer
                let aad_bytes: [u8; HEADER_SIZE] = *header.as_bytes();

                // create nonce
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                // Use the cached pre-expanded AES-256-GCM key to avoid per-packet
                // key schedule overhead (~200ns saved per packet).
                let key = &job.state.keypair.recv.cached_aead.aead;

                let packet = &mut msg.1[HEADER_SIZE..];
                match key.open_in_place(nonce, Aad::from(&aad_bytes[..]), packet) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::debug!(
                            counter = counter,
                            recv_id = header.receiver_id(),
                            buf_len = msg.1.len(),
                            "recv_job: AES-GCM decryption FAILED"
                        );
                        return false;
                    }
                }

                // check that counter is not after reject
                if counter >= REJECT_AFTER_MESSAGES {
                    return false;
                }

                // check crypto-key router (allowed IPs for source)
                // keepalive packets (only tag, no payload) are always allowed
                let route_ok =
                    packet.len() == SIZE_TAG || peer.device.table.check_route(peer, packet);
                if !route_ok {
                    tracing::debug!(packet_len = packet.len(), "recv_job: route check failed");
                }
                route_ok
            })();

            if !ok {
                msg.1.truncate(0);
            }
        }

        // mark ready
        self.0.ready.store(true, Ordering::Release);
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::UdpWriter<E>> SequentialJob
    for ReceiveJob<E, C, T, B>
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
        let peer = &job.state.peer;
        let mut msg = job.buffer.lock();
        let endpoint = msg.0.take();

        // parse v2 frame header
        if msg.1.len() < HEADER_SIZE {
            // authentication failure (truncated to 0)
            return;
        }

        let header = match FrameHeader::from_bytes(&msg.1) {
            Some(h) => h,
            None => return,
        };

        // check for replay
        if !job.state.protector.lock().update(header.counter()) {
            return;
        }

        // check for key confirmation
        if !job.state.confirmed.swap(true, Ordering::SeqCst) {
            peer.confirm_key(&job.state.keypair);
        }

        // update endpoint
        *peer.endpoint.lock() = endpoint;

        // check if should be written to TUN
        let packet = &msg.1[HEADER_SIZE..];
        // Capture received message size before modifying the buffer.
        let received_len = msg.1.len();
        if let Some(inner) = inner_length(packet) {
            if inner + SIZE_TAG <= packet.len() {
                // Per-peer ACL: if set, only allow packets to permitted destinations.
                if let Some(ref acl) = *peer.acl_destinations.read() {
                    let ip_data = &packet[..inner];
                    if acl.get_route(ip_data).is_none() {
                        C::recv(&peer.opaque, received_len, true, &job.state.keypair);
                        return;
                    }
                }
                // If forwarding is enabled, check whether the destination
                // should be forwarded to another peer instead of delivered
                // locally via TUN.
                if peer.device.forwarding_enabled.load(Ordering::Relaxed) {
                    let ip_data = &packet[..inner];
                    let dest_ip = extract_dest_ip(ip_data);
                    let is_local =
                        dest_ip.is_none_or(|ip| peer.device.local_addresses.read().contains(&ip));

                    if !is_local {
                        // Look up forwarding table for next-hop peer
                        if let Some(egress_peer) = peer.device.forwarding_table.get_route(ip_data) {
                            // Build a fresh buffer with SIZE_MESSAGE_PREFIX
                            // headroom for re-encryption by the egress peer's
                            // send path.
                            let mut fwd_buf = vec![0u8; SIZE_MESSAGE_PREFIX + inner];
                            fwd_buf[SIZE_MESSAGE_PREFIX..].copy_from_slice(&ip_data[..inner]);
                            egress_peer.send(fwd_buf, false);
                        }
                        // Forwarded or no route -- do not write to TUN.
                        // Trigger callback and return.
                        C::recv(&peer.opaque, msg.1.len(), true, &job.state.keypair);
                        return;
                    }
                }

                // Truncate trailing AEAD tag and padding, then pass the
                // buffer with an offset to the TUN write worker. This avoids
                // the drain(..HEADER_SIZE) memmove (~1404 bytes per packet).
                let inner_end = HEADER_SIZE + inner;
                msg.1.truncate(inner_end);
                let buf = std::mem::take(&mut msg.1);
                let _ = peer.device.tun_write_tx.try_send((buf, HEADER_SIZE));
            }
        }

        // trigger callback (use captured length since buffer may have been taken)
        C::recv(&peer.opaque, received_len, true, &job.state.keypair);
    }
}
