// MAC/Cookie DoS mitigation for the IronGuard handshake layer.
//
// Each outgoing handshake message carries two MAC fields:
//   MAC1 — always present; BLAKE2s-MAC over the message using mac1_key
//   MAC2 — present only when the sender has a valid cookie from the responder;
//            BLAKE2s-MAC over (message || MAC1) using the cookie as the key
//
// The Validator (server-side) derives the same keys and:
//   - verifies MAC1 on every message
//   - optionally verifies MAC2 when the server is "under load"
//   - issues CookieReply messages that the client can use to obtain MAC2 material

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::Aead,
};
use parking_lot::RwLock;
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::PublicKey;
use crate::handshake::messages::{CookieReply, MacsFooter, TYPE_COOKIE_REPLY};

// ── constants ────────────────────────────────────────────────────────────────

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const SIZE_COOKIE: usize = 16;
const SIZE_SECRET: usize = 32;
const SIZE_MAC: usize = 16;
const SIZE_TAG: usize = 16;
const SIZE_XNONCE: usize = 24;

const COOKIE_UPDATE_INTERVAL: Duration = Duration::from_secs(120);

// ── error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("invalid MAC1 field")]
    InvalidMac1,
    #[error("decryption failure")]
    DecryptionFailure,
    #[error("invalid state: no last MAC1 stored")]
    InvalidState,
    #[error("unknown public key")]
    UnknownPublicKey,
    #[error("unknown receiver ID")]
    UnknownReceiverId,
    #[error("old or replayed timestamp")]
    OldTimestamp,
    #[error("handshake initiation flood")]
    InitiationFlood,
    #[error("invalid message format")]
    InvalidMessageFormat,
    #[error("rate limited")]
    RateLimited,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// BLAKE2s-256 plain hash over one or more byte slices (concatenated).
fn blake2s_hash(inputs: &[&[u8]]) -> [u8; 32] {
    let mut params = blake2s_simd::Params::new();
    params.hash_length(32);
    let mut state = params.to_state();
    for input in inputs {
        state.update(input);
    }
    let hash = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// BLAKE2s-MAC-128 keyed over one or more byte slices.
///
/// Accepts any key length (the BLAKE2s keyed-hash supports 1..32 byte keys).
fn blake2s_mac(key: &[u8], inputs: &[&[u8]]) -> [u8; SIZE_MAC] {
    let mut params = blake2s_simd::Params::new();
    params.hash_length(SIZE_MAC).key(key);
    let mut state = params.to_state();
    for input in inputs {
        state.update(input);
    }
    let hash = state.finalize();
    let mut out = [0u8; SIZE_MAC];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Encode a SocketAddr as bytes for MAC2 / cookie derivation.
fn addr_to_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut v = Vec::with_capacity(6);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_le_bytes());
            v
        }
        SocketAddr::V6(a) => {
            let mut v = Vec::with_capacity(18);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_le_bytes());
            v
        }
    }
}

// ── XChaCha20-Poly1305 wrappers ───────────────────────────────────────────────

fn xchacha20_seal(
    key: &[u8; 32],
    nonce: &[u8; SIZE_XNONCE],
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), chacha20poly1305::aead::Payload { msg: plaintext, aad: ad })
        .expect("XChaCha20Poly1305 encryption failed")
}

fn xchacha20_open(
    key: &[u8; 32],
    nonce: &[u8; SIZE_XNONCE],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), chacha20poly1305::aead::Payload { msg: ciphertext, aad: ad })
        .map_err(|_| HandshakeError::DecryptionFailure)
}

// ── Generator (client-side, one per peer) ────────────────────────────────────

struct Cookie {
    value: [u8; SIZE_COOKIE],
    birth: Instant,
}

/// Client-side MAC field generator associated with one remote peer.
pub struct Generator {
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    last_mac1: Option<[u8; SIZE_MAC]>,
    cookie: Option<Cookie>,
}

impl Generator {
    /// Create a new Generator for the given remote peer public key.
    pub fn new(pk: &PublicKey) -> Self {
        Self {
            mac1_key: blake2s_hash(&[LABEL_MAC1, pk.as_bytes()]),
            cookie_key: blake2s_hash(&[LABEL_COOKIE, pk.as_bytes()]),
            last_mac1: None,
            cookie: None,
        }
    }

    /// Fill in `macs` for a message whose Noise payload is `inner`.
    pub fn generate(&mut self, inner: &[u8], macs: &mut MacsFooter) {
        macs.f_mac1 = blake2s_mac(&self.mac1_key, &[inner]);
        macs.f_mac2 = match &self.cookie {
            Some(c) if c.birth.elapsed() <= COOKIE_UPDATE_INTERVAL => {
                blake2s_mac(&c.value, &[inner, &macs.f_mac1])
            }
            Some(_) => {
                // cookie expired — clear it and send zeroed MAC2
                self.cookie = None;
                [0u8; SIZE_MAC]
            }
            None => [0u8; SIZE_MAC],
        };
        self.last_mac1 = Some(macs.f_mac1);
    }

    /// Process a CookieReply from the server and store the resulting cookie.
    pub fn process(&mut self, reply: &CookieReply) -> Result<(), HandshakeError> {
        let mac1 = self.last_mac1.ok_or(HandshakeError::InvalidState)?;
        let nonce: [u8; SIZE_XNONCE] = reply.f_nonce;
        let plaintext = xchacha20_open(&self.cookie_key, &nonce, &mac1, &reply.f_cookie)?;
        if plaintext.len() != SIZE_COOKIE {
            return Err(HandshakeError::DecryptionFailure);
        }
        let mut value = [0u8; SIZE_COOKIE];
        value.copy_from_slice(&plaintext);
        self.cookie = Some(Cookie { value, birth: Instant::now() });
        Ok(())
    }
}

// ── Validator (server-side, one per device key) ──────────────────────────────

struct Secret {
    value: [u8; SIZE_SECRET],
    birth: Instant,
}

/// Server-side MAC validator and CookieReply creator.
pub struct Validator {
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    secret: RwLock<Secret>,
}

impl Validator {
    /// Create a new Validator for the given local device public key.
    pub fn new(pk: &PublicKey) -> Self {
        Self {
            mac1_key: blake2s_hash(&[LABEL_MAC1, pk.as_bytes()]),
            cookie_key: blake2s_hash(&[LABEL_COOKIE, pk.as_bytes()]),
            secret: RwLock::new(Secret {
                value: [0u8; SIZE_SECRET],
                // initialise with an old timestamp so the first access rotates the secret
                birth: Instant::now() - Duration::from_secs(86400),
            }),
        }
    }

    /// Verify MAC1 for an incoming message.
    pub fn check_mac1(&self, inner: &[u8], macs: &MacsFooter) -> Result<(), HandshakeError> {
        let expected = blake2s_mac(&self.mac1_key, &[inner]);
        let valid: bool = expected.ct_eq(&macs.f_mac1).into();
        if valid { Ok(()) } else { Err(HandshakeError::InvalidMac1) }
    }

    /// Verify MAC2 for an incoming message from `src`.
    ///
    /// Returns `true` if MAC2 is valid, `false` otherwise.  Always returns
    /// `false` when the server secret has expired (because the cookie is stale).
    pub fn check_mac2(&self, inner: &[u8], src: &SocketAddr, macs: &MacsFooter) -> bool {
        let src_bytes = addr_to_bytes(src);
        match self.get_tau(&src_bytes) {
            Some(tau) => {
                let expected = blake2s_mac(&tau, &[inner, &macs.f_mac1]);
                let valid: bool = expected.ct_eq(&macs.f_mac2).into();
                valid
            }
            None => false,
        }
    }

    /// Build a CookieReply for a client that failed MAC2 verification.
    pub fn create_cookie_reply(
        &self,
        receiver: u32,
        src: &SocketAddr,
        macs: &MacsFooter,
        msg: &mut CookieReply,
    ) {
        let src_bytes = addr_to_bytes(src);
        let tau = self.get_or_refresh_tau(&src_bytes);

        // fill in the message fields
        msg.set_type(TYPE_COOKIE_REPLY);
        msg.set_receiver(receiver);

        // random 24-byte nonce
        let mut nonce = [0u8; SIZE_XNONCE];
        rand::rng().fill_bytes(&mut nonce);
        msg.f_nonce = nonce;

        // seal the cookie (16-byte tau) with XChaCha20-Poly1305; AD = MAC1
        let ct = xchacha20_seal(&self.cookie_key, &nonce, &macs.f_mac1, &tau);
        debug_assert_eq!(ct.len(), SIZE_COOKIE + SIZE_TAG);
        msg.f_cookie.copy_from_slice(&ct);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Return the current cookie for `src` if the secret is still fresh.
    fn get_tau(&self, src: &[u8]) -> Option<[u8; SIZE_COOKIE]> {
        let secret = self.secret.read();
        if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
            Some(blake2s_mac(&secret.value, &[src]))
        } else {
            None
        }
    }

    /// Return the current cookie for `src`, rotating the secret if it has expired.
    fn get_or_refresh_tau(&self, src: &[u8]) -> [u8; SIZE_COOKIE] {
        // fast path: read lock, still fresh
        {
            let secret = self.secret.read();
            if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
                return blake2s_mac(&secret.value, &[src]);
            }
        }
        // slow path: write lock, rotate secret
        {
            let mut secret = self.secret.write();
            // re-check under write lock (another thread may have rotated)
            if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
                return blake2s_mac(&secret.value, &[src]);
            }
            rand::rng().fill_bytes(&mut secret.value);
            secret.birth = Instant::now();
            blake2s_mac(&secret.value, &[src])
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKey;
    use rand::RngCore;

    fn random_pk() -> PublicKey {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        PublicKey::from_bytes(bytes)
    }

    #[test]
    fn test_mac1_roundtrip() {
        let pk = random_pk();
        let validator = Validator::new(&pk);
        let mut generator = Generator::new(&pk);

        let inner = b"hello mac1 roundtrip";
        let mut macs = MacsFooter::default();
        generator.generate(inner, &mut macs);

        assert_ne!(macs.f_mac1, [0u8; SIZE_MAC], "MAC1 should be non-zero");
        validator
            .check_mac1(inner, &macs)
            .expect("MAC1 should validate");
    }

    #[test]
    fn test_invalid_mac1_rejected() {
        let pk = random_pk();
        let validator = Validator::new(&pk);
        let mut generator = Generator::new(&pk);

        let inner = b"tamper me";
        let mut macs = MacsFooter::default();
        generator.generate(inner, &mut macs);
        // corrupt MAC1
        macs.f_mac1[0] ^= 0xff;

        let result = validator.check_mac1(inner, &macs);
        assert!(result.is_err(), "corrupted MAC1 should be rejected");
    }

    #[test]
    fn test_cookie_reply_roundtrip() {
        let pk = random_pk();
        let validator = Validator::new(&pk);
        let mut generator = Generator::new(&pk);

        // 1. Generator creates MAC1 for an initial message
        let inner1 = b"first message";
        let mut macs = MacsFooter::default();
        generator.generate(inner1, &mut macs);
        validator.check_mac1(inner1, &macs).unwrap();

        // 2. Validator builds a CookieReply
        let src: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let mut reply = CookieReply::default();
        validator.create_cookie_reply(1234, &src, &macs, &mut reply);

        // 3. Generator processes the reply
        generator.process(&reply).expect("CookieReply should be accepted");

        // 4. Generator now produces a valid MAC2
        let inner2 = b"second message";
        let mut macs2 = MacsFooter::default();
        generator.generate(inner2, &mut macs2);
        assert_ne!(macs2.f_mac2, [0u8; SIZE_MAC], "MAC2 should be set after cookie");

        // 5. Validator verifies MAC2
        validator.check_mac1(inner2, &macs2).unwrap();
        assert!(
            validator.check_mac2(inner2, &src, &macs2),
            "MAC2 should verify"
        );
    }

    #[test]
    fn test_mac2_wrong_source_rejected() {
        let pk = random_pk();
        let validator = Validator::new(&pk);
        let mut generator = Generator::new(&pk);

        let inner1 = b"msg";
        let mut macs = MacsFooter::default();
        generator.generate(inner1, &mut macs);

        let src: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:51820".parse().unwrap();

        let mut reply = CookieReply::default();
        validator.create_cookie_reply(0, &src, &macs, &mut reply);
        generator.process(&reply).unwrap();

        let mut macs2 = MacsFooter::default();
        let inner2 = b"second";
        generator.generate(inner2, &mut macs2);

        // validate from the wrong address — must fail
        assert!(!validator.check_mac2(inner2, &other, &macs2));
    }
}
