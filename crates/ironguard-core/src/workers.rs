use std::sync::atomic::Ordering;
#[cfg(feature = "legacy-wireguard")]
use std::time::Instant;

use tokio::sync::mpsc;

#[cfg(feature = "legacy-wireguard")]
use crate::constants::{DURATION_UNDER_LOAD, MAX_QUEUED_INCOMING_HANDSHAKES, THRESHOLD_UNDER_LOAD};
use crate::constants::{
    MESSAGE_PADDING_MULTIPLE, SIZE_MESSAGE_PREFIX, TYPE_COOKIE_REPLY, TYPE_INITIATION,
    TYPE_RESPONSE,
};
use crate::device::WireGuard;
use crate::router::messages_v2;
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

/// UDP reader worker: reads encrypted messages from the UDP socket,
/// demuxes by message type, and dispatches to handshake queue or router.
///
/// Runs as a Tokio task. The reader.read() call is async.
pub async fn udp_worker<T: tun::Tun, B: udp::Udp>(wg: WireGuard<T, B>, reader: B::Reader) {
    loop {
        // Use current MTU for buffer sizing; add MAX_HANDSHAKE_MSG_SIZE
        // so the buffer is always large enough for handshake messages.
        let alloc_mtu = wg.mtu.load(Ordering::Relaxed);
        let size = alloc_mtu + MAX_HANDSHAKE_MSG_SIZE;
        let mut msg: Vec<u8> = vec![0; size];

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
                        // v2 control frames — stub, not yet implemented
                    }
                    messages_v2::TYPE_BATCH => {
                        // v2 batch frames — stub, not yet implemented
                    }
                    _ => (),
                }
            }
        }
    }
}

/// TUN write worker: drains decrypted packets from the bounded channel and
/// writes them to the TUN device. Runs as a dedicated Tokio task so that
/// crypto workers never block on TUN I/O.
pub async fn tun_write_worker<T: tun::Writer>(mut rx: mpsc::Receiver<Vec<u8>>, writer: T) {
    while let Some(packet) = rx.recv().await {
        let _ = writer.write(&packet).await;
    }
}

/// UDP write worker: drains encrypted packets from the bounded channel and
/// writes them to the UDP socket. Runs as a dedicated Tokio task so that
/// crypto workers never block on UDP I/O.
pub async fn udp_write_worker<E: Endpoint, B: udp::UdpWriter<E>>(
    mut rx: mpsc::Receiver<(Vec<u8>, E)>,
    writer: B,
) {
    while let Some((msg, mut endpoint)) = rx.recv().await {
        let _ = writer.write(&msg, &mut endpoint).await;
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
}
