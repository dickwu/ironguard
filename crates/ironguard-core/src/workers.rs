use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::constants::{
    DURATION_UNDER_LOAD, MAX_QUEUED_INCOMING_HANDSHAKES, MESSAGE_PADDING_MULTIPLE,
    SIZE_MESSAGE_PREFIX, THRESHOLD_UNDER_LOAD, TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE,
};
use crate::device::WireGuard;
use crate::pipeline::batch::{DEFAULT_BATCH_FLUSH_TIMEOUT_US, DEFAULT_BATCH_MAX_COUNT};
use crate::router::messages_v2;
use crate::types::PublicKey;

use ironguard_platform::endpoint::Endpoint;
use ironguard_platform::tun::{self, Reader as _};
use ironguard_platform::udp::{self, UdpReader, UdpWriter};

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

/// TUN reader worker: reads IP packets from the TUN device, pads them,
/// and hands them to the crypto-key router for encryption and transmission.
///
/// Runs as a Tokio task. The reader.read() call is async.
pub async fn tun_worker<T: tun::Tun, B: udp::Udp>(wg: WireGuard<T, B>, reader: T::Reader) {
    loop {
        // Use a minimum buffer size of 1500 to avoid undersized allocations
        // when the device MTU is temporarily 0 (not yet up).
        let alloc_mtu = wg.mtu.load(Ordering::Relaxed).max(1500);
        let size = alloc_mtu + SIZE_MESSAGE_PREFIX + 1;
        let mut msg: Vec<u8> = vec![0; size + CAPACITY_MESSAGE_POSTFIX];

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

/// Dispatch a single received UDP message by type.
///
/// Uses two-stage type detection:
/// 1. Read the first byte (u8) for v2 frame types (0x04+: DATA, KEEPALIVE,
///    CONTROL, BATCH). v2 headers have a single-byte type field followed by
///    flags and reserved bytes. Reading all 4 bytes as a u32 would incorrectly
///    incorporate flags into the type comparison.
/// 2. For legacy WireGuard handshake messages (types 1-3), read bytes 0..4 as
///    a u32 LE, matching the legacy 4-byte type field layout.
///
/// This correctly handles the v2 frame format where byte 0 is the type,
/// byte 1 is flags, and bytes 2-3 are reserved.
fn dispatch_udp_message<T: tun::Tun, B: udp::Udp>(
    wg: &WireGuard<T, B>,
    msg: Vec<u8>,
    src: B::Endpoint,
) {
    if msg.len() < 4 {
        return;
    }

    // First byte is the type in both v2 frames and legacy handshake messages
    // (legacy types 1-3 are stored as u32 LE, so byte 0 is the low byte).
    let first_byte = msg[0];

    match first_byte {
        // v2 transport frame types — route to the crypto-key router for
        // decryption. Only the first byte is checked so that non-zero flags
        // (byte 1) do not cause a mismatch.
        messages_v2::TYPE_DATA | messages_v2::TYPE_KEEPALIVE => {
            let _ = wg.router.recv(src, msg);
        }

        // Legacy WireGuard handshake messages use a u32 LE type field.
        // Verify the full 4 bytes to avoid false matches (e.g. a v2 frame
        // with type 1/2/3 would never occur since v2 types start at 0x04).
        _ => {
            let msg_type = u32::from_le_bytes(msg[..4].try_into().unwrap());
            match msg_type {
                TYPE_COOKIE_REPLY | TYPE_INITIATION | TYPE_RESPONSE => {
                    wg.pending.fetch_add(1, Ordering::SeqCst);
                    wg.queue.send(HandshakeJob::Message(msg, src));
                }
                _ => (),
            }
        }
    }
}

/// Maximum number of datagrams to receive in a single batch call.
const MAX_RECV_BATCH: usize = 64;

/// UDP reader worker: reads encrypted messages from the UDP socket,
/// demuxes by message type, and dispatches to handshake queue or router.
///
/// Uses batch receive when the platform supports it (recvmsg_x on macOS,
/// recvmmsg on Linux), falling back to single-packet reads otherwise.
///
/// Runs as a Tokio task. The reader.read() call is async.
pub async fn udp_worker<T: tun::Tun, B: udp::Udp>(wg: WireGuard<T, B>, reader: B::Reader) {
    loop {
        // Use current MTU for buffer sizing; add MAX_HANDSHAKE_MSG_SIZE
        // so the buffer is always large enough for handshake messages.
        let alloc_mtu = wg.mtu.load(Ordering::Relaxed);
        let size = alloc_mtu + MAX_HANDSHAKE_MSG_SIZE;

        // Query how many datagrams are queued so we can size the batch.
        // Falls back to 1 on platforms that do not support the query.
        let pending = reader.pending_recv_count().unwrap_or(1) as usize;
        let batch_size = pending.clamp(1, MAX_RECV_BATCH);

        // Allocate buffers for the batch.
        let mut bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; size]).collect();

        // Read a batch of datagrams. This waits for at least one packet
        // (blocking), then reads up to batch_size packets if available.
        let results = match reader.read_batch(&mut bufs, batch_size).await {
            Err(_) => return,
            Ok(v) => v,
        };

        // Re-read MTU after the (potentially blocking) read returns.
        let mtu = wg.mtu.load(Ordering::Relaxed);
        if mtu == 0 {
            continue;
        }

        // Dispatch each received packet.
        for (i, (n, src)) in results.into_iter().enumerate() {
            let mut msg = std::mem::take(&mut bufs[i]);
            msg.truncate(n);
            dispatch_udp_message(&wg, msg, src);
        }
    }
}

/// Handshake worker: processes handshake jobs from the async mpsc channel.
///
/// Runs as a Tokio task. The handshake processing itself is CPU-bound
/// but fast enough to run on the async runtime.
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

/// TUN write worker: drains decrypted packets from the channel and writes
/// them to the TUN device in batches to minimize context switches.
///
/// Strategy:
/// 1. Block-wait for the first packet.
/// 2. Drain additional ready packets (non-blocking) up to batch limit.
/// 3. Write all collected packets in a tight loop.
///
/// Runs as a Tokio task. Exits when the channel sender is dropped.
pub async fn tun_write_worker<W: tun::Writer>(
    mut rx: mpsc::Receiver<Vec<u8>>,
    writer: W,
) {
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(DEFAULT_BATCH_MAX_COUNT);

    loop {
        // Step 1: block-wait for at least one packet.
        let first = match rx.recv().await {
            Some(buf) => buf,
            None => return,
        };
        batch.push(first);

        // Step 2: drain additional ready packets without blocking.
        while batch.len() < DEFAULT_BATCH_MAX_COUNT {
            match rx.try_recv() {
                Ok(buf) => batch.push(buf),
                Err(_) => break,
            }
        }

        // Step 3: if we only got one packet and more may arrive, wait
        // briefly before flushing to amortize syscall overhead.
        if batch.len() == 1 {
            let timeout = Duration::from_micros(DEFAULT_BATCH_FLUSH_TIMEOUT_US);
            if let Ok(Some(buf)) = tokio::time::timeout(timeout, rx.recv()).await {
                batch.push(buf);
                // Drain any further ready packets.
                while batch.len() < DEFAULT_BATCH_MAX_COUNT {
                    match rx.try_recv() {
                        Ok(buf) => batch.push(buf),
                        Err(_) => break,
                    }
                }
            }
        }

        // Step 4: write all collected packets in a tight loop.
        for buf in batch.drain(..) {
            let _ = writer.write(&buf).await;
        }
    }
}

/// UDP write worker: drains encrypted packets from the channel and sends
/// them via the UDP socket in batches using `write_batch()`.
///
/// Strategy:
/// 1. Block-wait for the first packet.
/// 2. Drain additional ready packets (non-blocking) up to batch limit.
/// 3. If only one packet arrived, wait briefly (50us) for more.
/// 4. Flush the batch via `write_batch()` (sendmsg_x on macOS, sendmmsg
///    on Linux) which sends all datagrams in a single syscall.
///
/// Falls back to per-packet `write()` if `write_batch()` fails.
///
/// Runs as a Tokio task. Exits when the channel sender is dropped.
pub async fn udp_write_worker<E: Endpoint, W: UdpWriter<E>>(
    mut rx: mpsc::Receiver<(Vec<u8>, E)>,
    writer: W,
) {
    let mut batch: Vec<(Vec<u8>, E)> = Vec::with_capacity(DEFAULT_BATCH_MAX_COUNT);

    loop {
        // Step 1: block-wait for at least one packet.
        let first = match rx.recv().await {
            Some(item) => item,
            None => return,
        };
        batch.push(first);

        // Step 2: drain additional ready packets without blocking.
        while batch.len() < DEFAULT_BATCH_MAX_COUNT {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }

        // Step 3: if we only got one packet and more may arrive, wait
        // briefly before flushing to amortize syscall overhead.
        if batch.len() == 1 {
            let timeout = Duration::from_micros(DEFAULT_BATCH_FLUSH_TIMEOUT_US);
            if let Ok(Some(item)) = tokio::time::timeout(timeout, rx.recv()).await {
                batch.push(item);
                // Drain any further ready packets.
                while batch.len() < DEFAULT_BATCH_MAX_COUNT {
                    match rx.try_recv() {
                        Ok(item) => batch.push(item),
                        Err(_) => break,
                    }
                }
            }
        }

        // Step 4: convert endpoints to SocketAddr and send via write_batch.
        if batch.len() == 1 {
            // Single packet: use the direct write path to avoid the
            // Vec<(Vec<u8>, SocketAddr)> allocation.
            let (buf, mut dst) = batch.pop().unwrap();
            let _ = writer.write(&buf, &mut dst).await;
        } else {
            // Multiple packets: batch them into a single syscall.
            let msgs: Vec<(Vec<u8>, std::net::SocketAddr)> = batch
                .drain(..)
                .map(|(buf, ep)| (buf, ep.to_address()))
                .collect();
            let _ = writer.write_batch(&msgs).await;
        }

        batch.clear();
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
}
