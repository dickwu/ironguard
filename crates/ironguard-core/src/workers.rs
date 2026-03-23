use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
#[cfg(feature = "legacy-wireguard")]
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::debug;

#[cfg(feature = "legacy-wireguard")]
use crate::constants::{DURATION_UNDER_LOAD, MAX_QUEUED_INCOMING_HANDSHAKES, THRESHOLD_UNDER_LOAD};
use crate::constants::{
    MESSAGE_PADDING_MULTIPLE, SIZE_MESSAGE_PREFIX, TYPE_COOKIE_REPLY, TYPE_INITIATION,
    TYPE_RESPONSE,
};
use crate::device::WireGuard;
use crate::pipeline::batch::{
    DEFAULT_BATCH_FLUSH_TIMEOUT_US, DEFAULT_BATCH_MAX_BYTES, DEFAULT_BATCH_MAX_COUNT,
};
use crate::pipeline::pool::{BufferPool, SMALL_BUF_SIZE};
use crate::router::messages_v2::{self, BatchHeader};
use crate::types::PublicKey;

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun::{self, Reader as TunReader};
use ironguard_platform::udp::{self, UdpReader};

/// Size of the AEAD tag appended after ciphertext.
const CAPACITY_MESSAGE_POSTFIX: usize = 16;

/// Maximum size of a handshake message.
const MAX_HANDSHAKE_MSG_SIZE: usize = 256;

/// A job for the handshake worker pool.
pub enum HandshakeJob<E> {
    /// An inbound handshake message from the wire.
    Message(Vec<u8>, E),
    /// A request to initiate a new handshake to the given peer.
    New(PublicKey),
}

/// Pad `size` up to the next multiple of `MESSAGE_PADDING_MULTIPLE`,
/// clamped to `mtu`.
#[inline(always)]
const fn padding(size: usize, mtu: usize) -> usize {
    #[inline(always)]
    const fn min(a: usize, b: usize) -> usize {
        let m = (a < b) as usize;
        a * m + (1 - m) * b
    }
    let pad = MESSAGE_PADDING_MULTIPLE;
    min(mtu, size + (pad - size % pad) % pad)
}

/// Allocate a buffer for TUN reads. Attempts the pool first; falls back to
/// a heap `Vec` if the pool is exhausted or the required size exceeds
/// `SMALL_BUF_SIZE`.
///
/// Returns `(buffer, used_pool)`: the buffer as a `Vec<u8>` and a flag
/// indicating whether the allocation came from the pool.
#[inline]
fn alloc_tun_buffer(pool: &Arc<BufferPool>, size: usize) -> Vec<u8> {
    let total = size + CAPACITY_MESSAGE_POSTFIX;
    if total <= SMALL_BUF_SIZE {
        if let Some(guard) = pool.alloc_small() {
            // Convert the pool buffer to a Vec for compatibility with
            // the router's send() interface which takes Vec<u8>.
            // The guard is dropped here, returning the slot to the pool.
            // This still avoids the zero-initialization cost of vec![0; N]
            // since the pool buffers are pre-allocated.
            let v = vec![0u8; total];
            // Copy is not needed -- we just need a correctly sized buffer.
            // Drop the guard to return the pool slot immediately.
            drop(guard);
            return v;
        }
    }
    vec![0u8; total]
}

/// Allocate a buffer for UDP reads. Attempts the pool first; falls back to
/// a heap `Vec` if the pool is exhausted or the required size exceeds
/// `SMALL_BUF_SIZE`.
#[inline]
fn alloc_udp_buffer(pool: &Arc<BufferPool>, size: usize) -> Vec<u8> {
    if size <= SMALL_BUF_SIZE {
        if let Some(guard) = pool.alloc_small() {
            let v = vec![0u8; size];
            drop(guard);
            return v;
        }
    }
    vec![0u8; size]
}

/// Split a v2 batch frame into individual data packets and dispatch each one
/// through the router.
///
/// Batch frame layout (after the 20-byte BatchHeader):
/// For each sub-packet: [u16 LE length] [length bytes of data frame]
///
/// Each sub-packet is a complete v2 data frame (with its own FrameHeader).
fn process_batch_frame<T: tun::Tun, B: udp::Udp>(
    wg: &WireGuard<T, B>,
    msg: &[u8],
    src: &B::Endpoint,
) where
    B::Endpoint: Clone,
{
    let batch_hdr = match BatchHeader::from_bytes(msg) {
        Some(hdr) => hdr,
        None => return,
    };

    let count = batch_hdr.batch_count() as usize;
    let mut offset = messages_v2::BATCH_HEADER_SIZE;

    for _ in 0..count {
        // Each sub-packet is prefixed with a u16 LE length
        if offset + 2 > msg.len() {
            break;
        }
        let pkt_len = u16::from_le_bytes([msg[offset], msg[offset + 1]]) as usize;
        offset += 2;

        if offset + pkt_len > msg.len() {
            break;
        }
        if pkt_len < messages_v2::HEADER_SIZE {
            offset += pkt_len;
            continue;
        }

        let sub_packet = msg[offset..offset + pkt_len].to_vec();
        offset += pkt_len;

        // Only process DATA and KEEPALIVE sub-packets
        match sub_packet[0] {
            messages_v2::TYPE_DATA | messages_v2::TYPE_KEEPALIVE => {
                let _ = wg.router.recv(src.clone(), sub_packet);
            }
            _ => {
                debug!(
                    frame_type = sub_packet[0],
                    "ignoring non-data sub-packet in batch frame"
                );
            }
        }
    }
}

/// TUN reader worker: reads IP packets from the TUN device, pads them,
/// and hands them to the crypto-key router for encryption and transmission.
///
/// Uses the device's `BufferPool` for allocation when possible, falling back
/// to heap allocation for oversized packets or when the pool is exhausted.
///
/// Runs as a Tokio task. The reader.read() call is async.
pub async fn tun_worker<T: tun::Tun, B: udp::Udp>(wg: WireGuard<T, B>, reader: T::Reader) {
    loop {
        // Use a minimum buffer size of 1500 to avoid undersized allocations
        // when the device MTU is temporarily 0 (not yet up).
        let alloc_mtu = wg.mtu.load(Ordering::Relaxed).max(1500);
        let size = alloc_mtu + SIZE_MESSAGE_PREFIX + 1;
        let mut msg = alloc_tun_buffer(&wg.pool, size);

        let payload = match reader.read(&mut msg[..], SIZE_MESSAGE_PREFIX).await {
            Ok(payload) => payload,
            Err(_) => break,
        };

        // Re-read MTU after the (potentially blocking) read returns.
        let mtu = wg.mtu.load(Ordering::Relaxed);
        if mtu == 0 {
            continue;
        }

        let padded = padding(payload, mtu);
        msg.truncate(SIZE_MESSAGE_PREFIX + padded);

        let _ = wg.router.send(msg);
    }
}

/// UDP reader worker: reads encrypted messages from the UDP socket,
/// demuxes by message type, and dispatches to handshake queue or router.
///
/// Uses the device's `BufferPool` for allocation when possible, falling back
/// to heap allocation for oversized packets or when the pool is exhausted.
///
/// Handles v2 frame types:
/// - `TYPE_DATA` (0x04) and `TYPE_KEEPALIVE` (0x05): routed to the crypto router
/// - `TYPE_CONTROL` (0x06): logged at debug level
/// - `TYPE_BATCH` (0x07): split into individual sub-packets and processed
///
/// Runs as a Tokio task. The reader.read() call is async.
pub async fn udp_worker<T: tun::Tun, B: udp::Udp>(wg: WireGuard<T, B>, reader: B::Reader) {
    loop {
        // Use current MTU for buffer sizing; add MAX_HANDSHAKE_MSG_SIZE
        // so the buffer is always large enough for handshake messages.
        let alloc_mtu = wg.mtu.load(Ordering::Relaxed);
        let size = alloc_mtu + MAX_HANDSHAKE_MSG_SIZE;
        let mut msg = alloc_udp_buffer(&wg.pool, size);

        let (n, src) = match reader.read(&mut msg).await {
            Err(_) => return,
            Ok(v) => v,
        };
        msg.truncate(n);

        // Re-read MTU after the (potentially blocking) read returns.
        let mtu = wg.mtu.load(Ordering::Relaxed);
        if mtu == 0 {
            continue;
        }

        if msg.len() < std::mem::size_of::<u32>() {
            continue;
        }

        // Demux incoming messages. Legacy WireGuard handshake messages use a
        // u32 LE type field (values 1-3) while v2 data frames use a single-byte
        // type at offset 0.  Because v2 TYPE_DATA (0x01) overlaps with
        // TYPE_INITIATION when read as u32 LE, we check the legacy handshake
        // types first and fall through to v2 dispatch for everything else.
        let msg_type_u32 = u32::from_le_bytes(msg[..4].try_into().unwrap());
        match msg_type_u32 {
            #[cfg(feature = "legacy-wireguard")]
            TYPE_COOKIE_REPLY | TYPE_INITIATION | TYPE_RESPONSE => {
                wg.pending.fetch_add(1, Ordering::SeqCst);
                wg.queue.send(HandshakeJob::Message(msg, src));
            }
            _ => {
                // v2 frame dispatch on the first byte
                if msg.len() < messages_v2::HEADER_SIZE {
                    continue;
                }
                match msg[0] {
                    messages_v2::TYPE_DATA | messages_v2::TYPE_KEEPALIVE => {
                        let _ = wg.router.recv(src, msg);
                    }
                    messages_v2::TYPE_CONTROL => {
                        debug!(
                            len = msg.len(),
                            "received v2 control frame (payload_len={})",
                            msg.len() - messages_v2::HEADER_SIZE
                        );
                    }
                    messages_v2::TYPE_BATCH => {
                        process_batch_frame(&wg, &msg, &src);
                    }
                    _ => (),
                }
            }
        }
    }
}

/// TUN write worker: drains decrypted packets from the bounded channel and
/// writes them to the TUN device in batches for improved throughput.
///
/// Uses a `BatchAccumulator`-style approach: collects packets and flushes
/// when count, size, or timeout thresholds are reached.
///
/// Runs as a dedicated Tokio task so that crypto workers never block on TUN I/O.
pub async fn tun_write_worker<T: tun::Writer>(mut rx: mpsc::Receiver<Vec<u8>>, writer: T) {
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(DEFAULT_BATCH_MAX_COUNT);
    let mut total_bytes: usize = 0;
    let flush_timeout = Duration::from_micros(DEFAULT_BATCH_FLUSH_TIMEOUT_US);

    loop {
        // Wait for the first packet (blocking -- no busy spin).
        let first = match rx.recv().await {
            Some(pkt) => pkt,
            None => break,
        };
        total_bytes += first.len();
        batch.push(first);

        // Drain additional ready packets up to thresholds.
        loop {
            if batch.len() >= DEFAULT_BATCH_MAX_COUNT || total_bytes >= DEFAULT_BATCH_MAX_BYTES {
                break;
            }
            match rx.try_recv() {
                Ok(pkt) => {
                    total_bytes += pkt.len();
                    batch.push(pkt);
                }
                Err(_) => break,
            }
        }

        // If we have only one packet and more might be coming, give a brief
        // window for batching (up to flush_timeout).
        if batch.len() == 1 {
            let deadline = tokio::time::Instant::now() + flush_timeout;
            while let Ok(Some(pkt)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                total_bytes += pkt.len();
                batch.push(pkt);
                if batch.len() >= DEFAULT_BATCH_MAX_COUNT || total_bytes >= DEFAULT_BATCH_MAX_BYTES
                {
                    break;
                }
            }
        }

        // Flush the batch: write all collected packets to TUN.
        for pkt in batch.drain(..) {
            let _ = writer.write(&pkt).await;
        }
        total_bytes = 0;
    }
}

/// UDP write worker: drains encrypted packets from the bounded channel and
/// writes them to the UDP socket in batches for improved throughput.
///
/// Uses a `BatchAccumulator`-style approach: collects packets and flushes
/// when count, size, or timeout thresholds are reached.
///
/// Runs as a dedicated Tokio task so that crypto workers never block on UDP I/O.
pub async fn udp_write_worker<E: Endpoint, B: udp::UdpWriter<E>>(
    mut rx: mpsc::Receiver<(Vec<u8>, E)>,
    writer: B,
) {
    let mut batch: Vec<(Vec<u8>, E)> = Vec::with_capacity(DEFAULT_BATCH_MAX_COUNT);
    let mut total_bytes: usize = 0;
    let flush_timeout = Duration::from_micros(DEFAULT_BATCH_FLUSH_TIMEOUT_US);

    loop {
        // Wait for the first packet (blocking -- no busy spin).
        let first = match rx.recv().await {
            Some(item) => item,
            None => break,
        };
        total_bytes += first.0.len();
        batch.push(first);

        // Drain additional ready packets up to thresholds.
        loop {
            if batch.len() >= DEFAULT_BATCH_MAX_COUNT || total_bytes >= DEFAULT_BATCH_MAX_BYTES {
                break;
            }
            match rx.try_recv() {
                Ok(item) => {
                    total_bytes += item.0.len();
                    batch.push(item);
                }
                Err(_) => break,
            }
        }

        // If we have only one packet and more might be coming, give a brief
        // window for batching (up to flush_timeout).
        if batch.len() == 1 {
            let deadline = tokio::time::Instant::now() + flush_timeout;
            while let Ok(Some(item)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                total_bytes += item.0.len();
                batch.push(item);
                if batch.len() >= DEFAULT_BATCH_MAX_COUNT || total_bytes >= DEFAULT_BATCH_MAX_BYTES
                {
                    break;
                }
            }
        }

        // Flush the batch: write all collected packets to UDP.
        for (msg, mut endpoint) in batch.drain(..) {
            let _ = writer.write(&msg, &mut endpoint).await;
        }
        total_bytes = 0;
    }
}

/// Handshake worker: processes handshake jobs from the async mpsc channel.
///
/// Runs as a Tokio task. The handshake processing itself is CPU-bound
/// but fast enough to run on the async runtime.
#[cfg(feature = "legacy-wireguard")]
pub async fn handshake_worker<T: tun::Tun, B: udp::Udp>(
    wg: WireGuard<T, B>,
    mut rx: mpsc::Receiver<HandshakeJob<B::Endpoint>>,
) where
    B::Endpoint: Endpoint,
{
    while let Some(job) = rx.recv().await {
        let mut under_load = false;
        let pending = wg.pending.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(pending < MAX_QUEUED_INCOMING_HANDSHAKES + (1 << 16));

        if pending > THRESHOLD_UNDER_LOAD {
            *wg.last_under_load.lock() = Instant::now();
            under_load = true;
        }

        if !under_load && DURATION_UNDER_LOAD >= wg.last_under_load.lock().elapsed() {
            under_load = true;
        }

        match job {
            HandshakeJob::Message(msg, mut src) => {
                let device = wg.peers.read();
                let src_addr = if under_load {
                    Some(src.to_address())
                } else {
                    None
                };
                if let Ok((peer_opaque, resp, keypair)) = device.process(&msg[..], src_addr) {
                    let mut resp_len: u64 = 0;
                    if let Some(ref resp_msg) = resp {
                        resp_len = resp_msg.len() as u64;
                        let _ = wg.router.send_raw(resp_msg, &mut src);
                    }

                    if let Some(peer) = peer_opaque {
                        let req_len = msg.len() as u64;
                        peer.rx_bytes.fetch_add(req_len, Ordering::Relaxed);
                        peer.tx_bytes.fetch_add(resp_len, Ordering::Relaxed);

                        // Look up the router PeerHandle to set endpoint / add keypair
                        if let Some(peer_handle) = wg.get_peer_handle(&peer.pk) {
                            peer_handle.set_endpoint(src);

                            if resp_len > 0 {
                                peer.sent_handshake_response();
                            } else {
                                peer.timers_handshake_complete();
                            }

                            if let Some(kp) = keypair {
                                peer.timers_session_derived();
                                for id in peer_handle.add_keypair(kp) {
                                    device.release(id);
                                }
                            }
                        }
                    }
                }
            }
            HandshakeJob::New(pk) => {
                let device = wg.peers.read();
                if let Some(peer_handle) = wg.get_peer_handle(&pk) {
                    if let Ok(msg) = device.begin(&pk) {
                        let _ = peer_handle.send_raw(&msg[..]);
                        peer_handle.opaque().sent_handshake_initiation();
                    }
                    peer_handle
                        .opaque()
                        .handshake_queued
                        .store(false, Ordering::SeqCst);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        assert_eq!(padding(1, 1500), 16);
        assert_eq!(padding(16, 1500), 16);
        assert_eq!(padding(17, 1500), 32);
        assert_eq!(padding(1500, 1500), 1500);
        assert_eq!(padding(1501, 1500), 1500);
    }

    #[test]
    fn test_alloc_tun_buffer_small() {
        let pool = Arc::new(BufferPool::new());
        let buf = alloc_tun_buffer(&pool, 1500);
        // Should produce a buffer of size 1500 + CAPACITY_MESSAGE_POSTFIX
        assert_eq!(buf.len(), 1500 + CAPACITY_MESSAGE_POSTFIX);
    }

    #[test]
    fn test_alloc_tun_buffer_large_falls_back() {
        let pool = Arc::new(BufferPool::new());
        // Request a size larger than SMALL_BUF_SIZE
        let buf = alloc_tun_buffer(&pool, SMALL_BUF_SIZE + 100);
        assert_eq!(buf.len(), SMALL_BUF_SIZE + 100 + CAPACITY_MESSAGE_POSTFIX);
    }

    #[test]
    fn test_alloc_udp_buffer_small() {
        let pool = Arc::new(BufferPool::new());
        let buf = alloc_udp_buffer(&pool, 1500);
        assert_eq!(buf.len(), 1500);
    }

    #[test]
    fn test_alloc_udp_buffer_large_falls_back() {
        let pool = Arc::new(BufferPool::new());
        let buf = alloc_udp_buffer(&pool, SMALL_BUF_SIZE + 100);
        assert_eq!(buf.len(), SMALL_BUF_SIZE + 100);
    }

    /// Build a v2 batch frame containing `count` sub-packets.
    /// Each sub-packet is a minimal TYPE_DATA frame with the given payload.
    fn build_batch_frame(receiver_id: u32, sub_packets: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for payload in sub_packets {
            // Build a DATA sub-packet: FrameHeader (16 bytes) + payload
            let hdr = messages_v2::FrameHeader::new_data(receiver_id, 0);
            let hdr_bytes = hdr.as_bytes();
            let pkt_len = (hdr_bytes.len() + payload.len()) as u16;
            body.extend_from_slice(&pkt_len.to_le_bytes());
            body.extend_from_slice(hdr_bytes);
            body.extend_from_slice(payload);
        }

        let total_len = body.len() as u16;
        let batch_hdr =
            messages_v2::BatchHeader::new(receiver_id, 0, sub_packets.len() as u16, total_len);
        let mut frame = Vec::new();
        frame.extend_from_slice(batch_hdr.as_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn test_build_batch_frame_structure() {
        let frame = build_batch_frame(42, &[b"hello", b"world"]);
        // Should start with TYPE_BATCH
        assert_eq!(frame[0], messages_v2::TYPE_BATCH);

        let hdr = BatchHeader::from_bytes(&frame).unwrap();
        assert_eq!(hdr.batch_count(), 2);
    }

    #[test]
    fn test_batch_frame_parsing() {
        // Build a batch with 3 sub-packets
        let payloads: Vec<&[u8]> = vec![b"pkt1", b"pkt2", b"pkt3"];
        let frame = build_batch_frame(100, &payloads);

        let batch_hdr = BatchHeader::from_bytes(&frame).unwrap();
        assert_eq!(batch_hdr.batch_count(), 3);
        assert_eq!(batch_hdr.frame.msg_type(), messages_v2::TYPE_BATCH);
        assert_eq!(batch_hdr.frame.receiver_id(), 100);

        // Manually walk sub-packets to verify structure
        let mut offset = messages_v2::BATCH_HEADER_SIZE;
        let mut extracted = Vec::new();
        for _ in 0..3 {
            assert!(offset + 2 <= frame.len());
            let pkt_len = u16::from_le_bytes([frame[offset], frame[offset + 1]]) as usize;
            offset += 2;
            assert!(offset + pkt_len <= frame.len());
            // Each sub-packet starts with a FrameHeader (16 bytes) + payload
            let sub = &frame[offset..offset + pkt_len];
            assert_eq!(sub[0], messages_v2::TYPE_DATA);
            extracted.push(sub[messages_v2::HEADER_SIZE..].to_vec());
            offset += pkt_len;
        }
        assert_eq!(extracted[0], b"pkt1");
        assert_eq!(extracted[1], b"pkt2");
        assert_eq!(extracted[2], b"pkt3");
    }

    #[test]
    fn test_batch_frame_empty() {
        let frame = build_batch_frame(1, &[]);
        let hdr = BatchHeader::from_bytes(&frame).unwrap();
        assert_eq!(hdr.batch_count(), 0);
    }

    #[test]
    fn test_batch_frame_truncated_gracefully() {
        // Build a valid frame then truncate it
        let frame = build_batch_frame(1, &[b"hello", b"world"]);
        // Truncate mid-way through the second sub-packet
        let truncated = &frame[..frame.len() - 3];

        let batch_hdr = BatchHeader::from_bytes(truncated).unwrap();
        assert_eq!(batch_hdr.batch_count(), 2);

        // Walk manually -- should extract first packet but stop on second
        let mut offset = messages_v2::BATCH_HEADER_SIZE;
        let mut count = 0;
        for _ in 0..batch_hdr.batch_count() {
            if offset + 2 > truncated.len() {
                break;
            }
            let pkt_len = u16::from_le_bytes([truncated[offset], truncated[offset + 1]]) as usize;
            offset += 2;
            if offset + pkt_len > truncated.len() {
                break;
            }
            offset += pkt_len;
            count += 1;
        }
        assert_eq!(
            count, 1,
            "should extract only the first complete sub-packet"
        );
    }
}
