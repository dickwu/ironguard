// Handshake device — manages all peers and processes handshake messages.
//
// Device<O> is the top-level object used by the WireGuard layer.  It is generic
// over an "opaque" type O that lets the caller associate arbitrary data (e.g. a
// router peer handle) with each handshake peer.
//
// Message processing:
// * `begin(pk)` — creates an initiation message for peer `pk`.
// * `process(msg, src)` — dispatches on the message type and returns an Output.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use rand::Rng;

use crate::{Key, KeyPair, PublicKey, StaticSecret};
use crate::handshake::macs::{self, HandshakeError};
use crate::handshake::messages::{
    CookieReply, MacsFooter,
    TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE,
};
use crate::handshake::noise;
use crate::handshake::peer::{Peer, PeerState};
use crate::handshake::ratelimiter::RateLimiter;

/// Output of `Device::process()`:
///   (peer_opaque, bytes_to_send, keypair_if_complete)
///
/// Uses cloned `O` instead of a reference because the peer map is behind a
/// `RwLock` and we cannot safely return a reference that outlives the lock guard.
pub type Output<O> = (Option<O>, Option<Vec<u8>>, Option<KeyPair>);

const MAX_PEERS: usize = 1 << 20;

// ── serialization helpers ────────────────────────────────────────────────────

/// Interpret a `#[repr(C, packed)]` struct as a byte slice.
///
/// # Safety
/// The caller guarantees that `T` has no padding bytes that would be
/// uninitialised, and that the value is fully initialised.
unsafe fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            val as *const T as *const u8,
            std::mem::size_of::<T>(),
        )
    }
}

/// Try to interpret a byte slice as a `#[repr(C, packed)]` struct.
fn parse_msg<T: Copy + Default>(bytes: &[u8]) -> Result<T, HandshakeError> {
    if bytes.len() < std::mem::size_of::<T>() {
        return Err(HandshakeError::InvalidMessageFormat);
    }
    let mut val = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut val as *mut T as *mut u8,
            std::mem::size_of::<T>(),
        );
    }
    Ok(val)
}

// ── public key derivation ─────────────────────────────────────────────────────

/// Derive the Curve25519 public key from a static secret.
fn derive_public_key(sk: &StaticSecret) -> PublicKey {
    let dalek_sk = x25519_dalek::StaticSecret::from(*sk.as_bytes());
    let dalek_pk = x25519_dalek::PublicKey::from(&dalek_sk);
    PublicKey::from_bytes(*dalek_pk.as_bytes())
}

// ── KeyPair extraction from snow ──────────────────────────────────────────────

/// Build a KeyPair from a completed snow handshake.
///
/// We call `get_handshake_hash()` on the HandshakeState (before transitioning
/// to transport mode) and derive deterministic keys using BLAKE2s so both sides
/// produce identical material.
fn extract_keypair_from_hs(
    hs: snow::HandshakeState,
    local_id: u32,
    remote_id: u32,
    is_initiator: bool,
) -> Result<(KeyPair, snow::TransportState), HandshakeError> {
    let hs_hash = hs.get_handshake_hash().to_vec();

    let transport = hs
        .into_transport_mode()
        .map_err(|_| HandshakeError::InvalidMessageFormat)?;

    // Derive two 32-byte keys from the handshake hash.
    let key_i2r = blake2s_derive(&hs_hash, b"ironguard-i2r");
    let key_r2i = blake2s_derive(&hs_hash, b"ironguard-r2i");

    let (send_key_bytes, recv_key_bytes) = if is_initiator {
        (key_i2r, key_r2i)
    } else {
        (key_r2i, key_i2r)
    };

    let kp = KeyPair {
        birth: Instant::now(),
        initiator: is_initiator,
        send: Key {
            key: send_key_bytes,
            id: remote_id,
        },
        recv: Key {
            key: recv_key_bytes,
            id: local_id,
        },
    };

    Ok((kp, transport))
}

/// Derive a 32-byte key from input using BLAKE2s with a domain label.
fn blake2s_derive(input: &[u8], label: &[u8]) -> [u8; 32] {
    let mut params = blake2s_simd::Params::new();
    params.hash_length(32);
    let mut state = params.to_state();
    state.update(label);
    state.update(input);
    let hash = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

// ── Helper struct for pk_map access ──────────────────────────────────────────

struct PkMapRef<'a, O> {
    guard: parking_lot::RwLockReadGuard<'a, HashMap<[u8; 32], Peer<O>>>,
    key: [u8; 32],
}

impl<O> std::ops::Deref for PkMapRef<'_, O> {
    type Target = O;
    fn deref(&self) -> &O {
        &self.guard[&self.key].opaque
    }
}

// ── Device ────────────────────────────────────────────────────────────────────

pub struct Device<O> {
    /// Local static secret key.
    sk: RwLock<Option<StaticSecret>>,
    /// Local static public key (derived from sk).
    pk: RwLock<Option<PublicKey>>,
    /// MAC validator for incoming messages (derived from local pk).
    validator: RwLock<Option<macs::Validator>>,
    /// Map from receiver-ID (u32) to peer public key bytes.
    id_map: DashMap<u32, [u8; 32]>,
    /// Map from peer public key bytes to handshake peer state.
    pk_map: RwLock<HashMap<[u8; 32], Peer<O>>>,
    /// Rate limiter for source addresses.
    limiter: Mutex<RateLimiter>,
}

impl<O: Clone> Device<O> {
    pub fn new() -> Self {
        Self {
            sk: RwLock::new(None),
            pk: RwLock::new(None),
            validator: RwLock::new(None),
            id_map: DashMap::new(),
            pk_map: RwLock::new(HashMap::new()),
            limiter: Mutex::new(RateLimiter::new()),
        }
    }

    // ── key management ────────────────────────────────────────────────────────

    /// Set the local static secret key.  Returns the old public key (if any).
    pub fn set_sk(&self, sk: Option<StaticSecret>) -> Option<PublicKey> {
        let new_pk = sk.as_ref().map(derive_public_key);

        // Reset all in-flight handshakes.
        {
            let pk_map = self.pk_map.read();
            for peer in pk_map.values() {
                if let Some(id) = peer.reset_state() {
                    self.id_map.remove(&id);
                }
            }
        }

        let old_pk = self.pk.write().take();
        *self.sk.write() = sk;
        *self.pk.write() = new_pk.clone();
        *self.validator.write() = new_pk.as_ref().map(macs::Validator::new);

        old_pk
    }

    // ── peer management ───────────────────────────────────────────────────────

    pub fn add(&self, pk: PublicKey, opaque: O) {
        let mut map = self.pk_map.write();
        if map.len() >= MAX_PEERS {
            return;
        }
        map.entry(*pk.as_bytes()).or_insert_with(|| Peer::new(pk, opaque));
    }

    pub fn remove(&self, pk: &PublicKey) {
        let mut map = self.pk_map.write();
        if let Some(peer) = map.remove(pk.as_bytes()) {
            if let Some(id) = peer.reset_state() {
                self.id_map.remove(&id);
            }
        }
    }

    pub fn get(&self, pk: &PublicKey) -> Option<impl std::ops::Deref<Target = O> + '_> {
        let guard = self.pk_map.read();
        if guard.contains_key(pk.as_bytes()) {
            Some(PkMapRef { guard, key: *pk.as_bytes() })
        } else {
            None
        }
    }

    pub fn set_psk(&self, pk: &PublicKey, psk: [u8; 32]) {
        if let Some(peer) = self.pk_map.write().get_mut(pk.as_bytes()) {
            peer.psk = psk;
        }
    }

    pub fn release(&self, id: u32) {
        self.id_map.remove(&id);
    }

    // ── handshake operations ──────────────────────────────────────────────────

    /// Begin a new handshake to peer `pk`.  Returns the serialised initiation
    /// message bytes ready to be sent on the wire.
    pub fn begin(&self, pk: &PublicKey) -> Result<Vec<u8>, HandshakeError> {
        let sk_guard = self.sk.read();
        let sk = sk_guard.as_ref().ok_or(HandshakeError::UnknownPublicKey)?;

        let pk_map = self.pk_map.read();
        let peer = pk_map.get(pk.as_bytes()).ok_or(HandshakeError::UnknownPublicKey)?;

        // Build snow initiator
        let mut hs = noise::build_initiator(sk.as_bytes(), pk.as_bytes(), &peer.psk)?;

        // snow message 1
        let mut noise_buf = vec![0u8; 512];
        let n = hs
            .write_message(&[], &mut noise_buf)
            .map_err(|_| HandshakeError::InvalidMessageFormat)?;
        let noise_payload = &noise_buf[..n];

        // Allocate a local receiver ID
        let local_id = self.allocate_id(pk);

        // Build the wire message: type(4) + sender(4) + snow_payload + macs(32)
        let mut msg: Vec<u8> = Vec::with_capacity(4 + 4 + n + 32);
        msg.extend_from_slice(&TYPE_INITIATION.to_le_bytes());
        msg.extend_from_slice(&local_id.to_le_bytes());
        msg.extend_from_slice(noise_payload);

        // Generate MACs over the inner portion
        let mut macs_footer = MacsFooter::default();
        peer.macs.lock().generate(&msg, &mut macs_footer);
        msg.extend_from_slice(unsafe { as_bytes(&macs_footer) });

        // Store the snow HandshakeState in the peer
        *peer.state.lock() = PeerState::InitiationSent { hs: Box::new(hs), local_id };

        Ok(msg)
    }

    /// Process an incoming handshake message.
    ///
    /// `src` — set to `Some(addr)` when operating under load to enable MAC2
    /// validation and rate limiting.
    pub fn process(
        &self,
        msg: &[u8],
        src: Option<SocketAddr>,
    ) -> Result<Output<O>, HandshakeError> {
        if msg.len() < 4 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        let msg_type = u32::from_le_bytes(msg[..4].try_into().unwrap());

        match msg_type {
            TYPE_INITIATION => self.process_initiation(msg, src),
            TYPE_RESPONSE => self.process_response(msg, src),
            TYPE_COOKIE_REPLY => self.process_cookie_reply(msg),
            _ => Err(HandshakeError::InvalidMessageFormat),
        }
    }

    // ── internal: initiation ──────────────────────────────────────────────────

    fn process_initiation(
        &self,
        msg: &[u8],
        src: Option<SocketAddr>,
    ) -> Result<Output<O>, HandshakeError> {
        // Minimum: type(4) + sender(4) + some noise + macs(32)
        if msg.len() < 4 + 4 + 32 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        // Split off MACs footer (last 32 bytes)
        let (inner, macs_bytes) = msg.split_at(msg.len() - 32);
        let mut macs_footer = MacsFooter::default();
        macs_footer.f_mac1.copy_from_slice(&macs_bytes[..16]);
        macs_footer.f_mac2.copy_from_slice(&macs_bytes[16..]);

        // Verify MAC1 (always required)
        {
            let validator = self.validator.read();
            let v = validator.as_ref().ok_or(HandshakeError::UnknownPublicKey)?;
            v.check_mac1(inner, &macs_footer)?;

            // MAC2 / cookie / rate-limiting (only when under load)
            if let Some(ref src_addr) = src {
                if !v.check_mac2(inner, src_addr, &macs_footer) {
                    let sender_id = u32::from_le_bytes(inner[4..8].try_into().unwrap());
                    let mut reply = CookieReply::default();
                    v.create_cookie_reply(sender_id, src_addr, &macs_footer, &mut reply);
                    let reply_bytes = unsafe { as_bytes(&reply) }.to_vec();
                    return Ok((None, Some(reply_bytes), None));
                }

                if !self.limiter.lock().allow(&src_addr.ip()) {
                    return Err(HandshakeError::RateLimited);
                }
            }
        }

        // Parse: msg[4..8] = sender_id, msg[8..msg.len()-32] = snow payload
        let sender_id = u32::from_le_bytes(inner[4..8].try_into().unwrap());
        let noise_payload = &inner[8..];

        // Build snow responder (using zero PSK — both sides must match)
        let sk_guard = self.sk.read();
        let sk = sk_guard.as_ref().ok_or(HandshakeError::UnknownPublicKey)?;

        let zero_psk = [0u8; 32];
        let mut hs = noise::build_responder(sk.as_bytes(), &zero_psk)?;

        let mut payload_out = vec![0u8; noise_payload.len() + 16];
        hs.read_message(noise_payload, &mut payload_out)
            .map_err(|_| HandshakeError::DecryptionFailure)?;

        // Extract the initiator's static public key from snow
        let remote_pk_bytes: [u8; 32] = hs
            .get_remote_static()
            .ok_or(HandshakeError::UnknownPublicKey)?
            .try_into()
            .map_err(|_| HandshakeError::InvalidMessageFormat)?;
        let remote_pk = PublicKey::from_bytes(remote_pk_bytes);

        // Allocate local receiver ID
        let local_id = self.allocate_id(&remote_pk);

        // Write snow response message
        let mut resp_noise_buf = vec![0u8; 512];
        let resp_n = hs
            .write_message(&[], &mut resp_noise_buf)
            .map_err(|_| HandshakeError::InvalidMessageFormat)?;
        let resp_noise = &resp_noise_buf[..resp_n];

        // Derive transport keypair (consumes HandshakeState)
        let (keypair, _transport) =
            extract_keypair_from_hs(hs, local_id, sender_id, false)?;

        // Look up the peer — it must be pre-registered — and clone the opaque
        let opaque = {
            let pk_map = self.pk_map.read();
            let peer = pk_map
                .get(&remote_pk_bytes)
                .ok_or(HandshakeError::UnknownPublicKey)?;

            // Build response wire message and generate MACs using the peer's Generator
            // We must build the response bytes while holding the lock.
            let mut resp_msg: Vec<u8> = Vec::with_capacity(4 + 4 + 4 + resp_n + 32);
            resp_msg.extend_from_slice(&TYPE_RESPONSE.to_le_bytes());
            resp_msg.extend_from_slice(&local_id.to_le_bytes());
            resp_msg.extend_from_slice(&sender_id.to_le_bytes());
            resp_msg.extend_from_slice(resp_noise);

            let mut macs_out = MacsFooter::default();
            peer.macs.lock().generate(&resp_msg, &mut macs_out);
            resp_msg.extend_from_slice(unsafe { as_bytes(&macs_out) });

            // Store local_id in id_map
            self.id_map.insert(local_id, remote_pk_bytes);

            let opaque = peer.opaque.clone();
            // Drop the pk_map lock before returning
            (opaque, resp_msg)
        };

        Ok((Some(opaque.0), Some(opaque.1), Some(keypair)))
    }

    // ── internal: response ────────────────────────────────────────────────────

    fn process_response(
        &self,
        msg: &[u8],
        src: Option<SocketAddr>,
    ) -> Result<Output<O>, HandshakeError> {
        if msg.len() < 4 + 4 + 4 + 32 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        let (inner, macs_bytes) = msg.split_at(msg.len() - 32);
        let mut macs_footer = MacsFooter::default();
        macs_footer.f_mac1.copy_from_slice(&macs_bytes[..16]);
        macs_footer.f_mac2.copy_from_slice(&macs_bytes[16..]);

        // Verify MAC1
        {
            let validator = self.validator.read();
            let v = validator.as_ref().ok_or(HandshakeError::UnknownPublicKey)?;
            v.check_mac1(inner, &macs_footer)?;

            if let Some(ref src_addr) = src {
                if !v.check_mac2(inner, src_addr, &macs_footer) {
                    let sender_id = u32::from_le_bytes(inner[4..8].try_into().unwrap());
                    let mut reply = CookieReply::default();
                    v.create_cookie_reply(sender_id, src_addr, &macs_footer, &mut reply);
                    let reply_bytes = unsafe { as_bytes(&reply) }.to_vec();
                    return Ok((None, Some(reply_bytes), None));
                }

                if !self.limiter.lock().allow(&src_addr.ip()) {
                    return Err(HandshakeError::RateLimited);
                }
            }
        }

        // Parse: [4..8] = sender_id (responder's ID), [8..12] = receiver_id (our local_id)
        let remote_sender_id = u32::from_le_bytes(inner[4..8].try_into().unwrap());
        let receiver_id = u32::from_le_bytes(inner[8..12].try_into().unwrap());
        let noise_payload = &inner[12..];

        // Look up the peer by receiver_id
        let peer_pk_bytes = {
            let entry = self
                .id_map
                .get(&receiver_id)
                .ok_or(HandshakeError::UnknownReceiverId)?;
            *entry
        };

        // Extract the HandshakeState and clone the opaque value
        let (hs, opaque) = {
            let pk_map = self.pk_map.read();
            let peer = pk_map.get(&peer_pk_bytes).ok_or(HandshakeError::UnknownPublicKey)?;

            let hs = {
                let mut state = peer.state.lock();
                match std::mem::replace(&mut *state, PeerState::Reset) {
                    PeerState::InitiationSent { hs, local_id } => {
                        if local_id != receiver_id {
                            return Err(HandshakeError::InvalidState);
                        }
                        *hs
                    }
                    PeerState::Reset => return Err(HandshakeError::InvalidState),
                }
            };

            (hs, peer.opaque.clone())
        };

        let mut hs = hs;
        let mut payload_out = vec![0u8; noise_payload.len() + 16];
        hs.read_message(noise_payload, &mut payload_out)
            .map_err(|_| HandshakeError::DecryptionFailure)?;

        let (keypair, _transport) =
            extract_keypair_from_hs(hs, receiver_id, remote_sender_id, true)?;

        Ok((Some(opaque), None, Some(keypair)))
    }

    // ── internal: cookie reply ─────────────────────────────────────────────────

    fn process_cookie_reply(
        &self,
        msg: &[u8],
    ) -> Result<Output<O>, HandshakeError> {
        if msg.len() < std::mem::size_of::<CookieReply>() {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        let reply: CookieReply = parse_msg(msg)?;
        let receiver_id = reply.receiver();

        let peer_pk_bytes = {
            let entry = self
                .id_map
                .get(&receiver_id)
                .ok_or(HandshakeError::UnknownReceiverId)?;
            *entry
        };

        let pk_map = self.pk_map.read();
        let peer = pk_map.get(&peer_pk_bytes).ok_or(HandshakeError::UnknownPublicKey)?;

        peer.macs.lock().process(&reply)?;

        Ok((None, None, None))
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Allocate a unique u32 receiver ID for `pk` via rejection sampling.
    fn allocate_id(&self, pk: &PublicKey) -> u32 {
        loop {
            let id: u32 = rand::rng().random();
            if let dashmap::mapref::entry::Entry::Vacant(e) = self.id_map.entry(id) {
                e.insert(*pk.as_bytes());
                return id;
            }
        }
    }
}

impl<O: Clone> Default for Device<O> {
    fn default() -> Self {
        Self::new()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(opaque: u32) -> (Device<u32>, PublicKey) {
        let dev: Device<u32> = Device::new();
        let sk = StaticSecret::random();
        dev.set_sk(Some(sk));
        let pk = dev.pk.read().clone().unwrap();
        let _ = opaque;
        (dev, pk)
    }

    #[test]
    fn test_full_handshake_no_load() {
        let (dev_a, pk_a) = make_device(42);
        let (dev_b, pk_b) = make_device(99);

        dev_a.add(pk_b.clone(), 99);
        dev_b.add(pk_a.clone(), 42);

        // A begins handshake to B
        let init_msg = dev_a.begin(&pk_b).expect("begin should succeed");

        // B processes initiation
        let (opaque_b, resp_msg_opt, kp_b_opt) =
            dev_b.process(&init_msg, None).expect("process initiation");
        assert!(opaque_b.is_some(), "B should identify A");
        let resp_msg = resp_msg_opt.expect("B should send response");
        let kp_b = kp_b_opt.expect("B should derive keypair");

        // A processes response
        let (opaque_a, none_msg, kp_a_opt) =
            dev_a.process(&resp_msg, None).expect("process response");
        assert!(opaque_a.is_some(), "A should identify B");
        assert!(none_msg.is_none(), "no further message expected");
        let kp_a = kp_a_opt.expect("A should derive keypair");

        // Key symmetry: A's send key == B's recv key and vice versa
        assert_eq!(kp_a.send.key, kp_b.recv.key, "A.send.key == B.recv.key");
        assert_eq!(kp_a.recv.key, kp_b.send.key, "A.recv.key == B.send.key");
        assert_eq!(kp_a.recv.id, kp_b.send.id, "A.recv.id == B.send.id");
        assert_eq!(kp_a.send.id, kp_b.recv.id, "A.send.id == B.recv.id");
        assert!(kp_a.initiator);
        assert!(!kp_b.initiator);
    }

    #[test]
    fn test_unknown_peer_rejected() {
        let (dev_a, _pk_a) = make_device(0);
        let unknown_pk = PublicKey::from_bytes([7u8; 32]);
        let result = dev_a.begin(&unknown_pk);
        assert!(result.is_err(), "begin to unknown peer should fail");
    }

    #[test]
    fn test_no_sk_begin_rejected() {
        let dev: Device<u32> = Device::new();
        let dummy_pk = PublicKey::from_bytes([1u8; 32]);
        dev.add(dummy_pk.clone(), 0);
        let result = dev.begin(&dummy_pk);
        assert!(result.is_err(), "begin without SK should fail");
    }

    #[test]
    fn test_multiple_successive_handshakes() {
        let (dev_a, pk_a) = make_device(1);
        let (dev_b, pk_b) = make_device(2);
        dev_a.add(pk_b.clone(), 2);
        dev_b.add(pk_a.clone(), 1);

        for i in 0..3u32 {
            let init = dev_a.begin(&pk_b).expect("begin");
            let (_, resp_opt, kp_b) = dev_b.process(&init, None).expect("process init");
            let resp = resp_opt.expect("response expected");
            let kp_b = kp_b.expect("B keypair");

            let (_, _, kp_a) = dev_a.process(&resp, None).expect("process resp");
            let kp_a = kp_a.expect("A keypair");

            assert_eq!(
                kp_a.send.key, kp_b.recv.key,
                "iteration {i}: send/recv key symmetry"
            );
            assert_eq!(
                kp_a.recv.id, kp_b.send.id,
                "iteration {i}: recv/send id match"
            );
        }
    }

    #[test]
    fn test_cookie_reply_processed() {
        let (dev_a, pk_a) = make_device(0);
        let (dev_b, pk_b) = make_device(0);
        dev_a.add(pk_b.clone(), 0);
        dev_b.add(pk_a.clone(), 0);

        let init = dev_a.begin(&pk_b).expect("begin");

        // Extract sender_id and MACs from the init message
        let sender_id = u32::from_le_bytes(init[4..8].try_into().unwrap());
        let macs_offset = init.len() - 32;
        let mut macs = MacsFooter::default();
        macs.f_mac1.copy_from_slice(&init[macs_offset..macs_offset + 16]);
        macs.f_mac2.copy_from_slice(&init[macs_offset + 16..]);

        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Build a cookie reply using dev_b's validator
        let validator_guard = dev_b.validator.read();
        let validator = validator_guard.as_ref().unwrap();
        let mut reply = CookieReply::default();
        validator.create_cookie_reply(sender_id, &src, &macs, &mut reply);
        drop(validator_guard);

        let reply_bytes = unsafe { as_bytes(&reply) }.to_vec();

        // dev_a should process the cookie reply without error
        let result = dev_a.process(&reply_bytes, None);
        assert!(
            result.is_ok(),
            "cookie reply should be processed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_handshake_under_load_cookie_flow() {
        let (dev_a, pk_a) = make_device(10);
        let (dev_b, pk_b) = make_device(20);
        dev_a.add(pk_b.clone(), 20);
        dev_b.add(pk_a.clone(), 10);

        let src: SocketAddr = "10.0.0.1:51820".parse().unwrap();

        // A sends initiation
        let init_msg = dev_a.begin(&pk_b).expect("begin");

        // B processes under load -- no cookie yet, so MAC2 will fail --> cookie reply
        let (opaque, reply_opt, kp) = dev_b
            .process(&init_msg, Some(src))
            .expect("should not hard-error");
        assert!(opaque.is_none(), "no peer identified yet");
        assert!(kp.is_none(), "no keypair yet");
        let cookie_reply = reply_opt.expect("B should send a cookie reply");

        // A processes the cookie reply to store the cookie
        let result = dev_a.process(&cookie_reply, None);
        assert!(result.is_ok(), "cookie reply accepted");

        // A sends a new initiation (Generator now has a cookie --> MAC2 is set)
        let init_msg2 = dev_a.begin(&pk_b).expect("second begin");

        // B processes under load -- MAC2 should now validate
        let (opaque2, resp_opt, kp_b) = dev_b
            .process(&init_msg2, Some(src))
            .expect("process with valid MAC2");
        assert!(opaque2.is_some(), "B identifies A");
        let resp = resp_opt.expect("B sends response");
        let kp_b = kp_b.expect("B gets keypair");

        // A processes B's response
        let (opaque_a, _, kp_a) = dev_a.process(&resp, None).expect("A processes response");
        assert!(opaque_a.is_some());
        let kp_a = kp_a.expect("A gets keypair");

        // Verify key symmetry
        assert_eq!(kp_a.send.key, kp_b.recv.key);
        assert_eq!(kp_a.recv.key, kp_b.send.key);
    }
}
