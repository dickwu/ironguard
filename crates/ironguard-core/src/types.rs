use std::time::Instant;

use ring::aead::{AES_256_GCM, LessSafeKey, UnboundKey};
use zeroize::Zeroize;

/// Wrapper around `LessSafeKey` that caches the AES-256-GCM key schedule.
///
/// `LessSafeKey::new()` performs an expensive AES key expansion (~200ns).
/// By caching the expanded key in the `Key` struct, we avoid repeating this
/// work on every packet encrypt/decrypt operation.
///
/// `LessSafeKey` does not implement `Zeroize` (ring does not expose internals),
/// but the raw key bytes in the parent `Key` struct are zeroized on drop.
pub struct CachedAeadKey {
    pub aead: LessSafeKey,
}

impl CachedAeadKey {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
            .expect("AES-256-GCM key expansion should not fail for 32-byte key");
        Self {
            aead: LessSafeKey::new(unbound),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct StaticSecret([u8; 32]);

impl StaticSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// A single transport key with receiver ID. Zeroized on drop.
///
/// The `cached_aead` field holds a pre-expanded AES-256-GCM key schedule,
/// eliminating the ~200ns per-packet cost of `LessSafeKey::new()`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key {
    pub key: [u8; 32],
    #[zeroize(skip)]
    pub id: u32,
    #[zeroize(skip)]
    pub cached_aead: CachedAeadKey,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key(id={})", self.id)
    }
}

/// A pair of send/recv transport keys derived from a completed handshake.
pub struct KeyPair {
    pub birth: Instant,
    pub initiator: bool,
    pub send: Key,
    pub recv: Key,
}

impl KeyPair {
    pub fn local_id(&self) -> u32 {
        self.recv.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::{Aad, Nonce};

    #[test]
    fn test_cached_key_matches_fresh_key() {
        let key_bytes = [0x42u8; 32];

        // Fresh key (current per-packet approach)
        let fresh = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());

        // Cached key (proposed approach)
        let cached = CachedAeadKey::new(&key_bytes);

        // Encrypt same plaintext with both
        let nonce_bytes = [0u8; 12];
        let mut pt1 = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut pt2 = pt1.clone();
        let aad = b"test-aad";

        let tag1 = fresh
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(&aad[..]),
                &mut pt1,
            )
            .unwrap();
        let tag2 = cached
            .aead
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(&aad[..]),
                &mut pt2,
            )
            .unwrap();

        assert_eq!(pt1, pt2, "ciphertext must match");
        assert_eq!(tag1.as_ref(), tag2.as_ref(), "tags must match");
    }

    #[test]
    fn test_key_struct_with_cached_aead() {
        let key_bytes = [0xABu8; 32];
        let key = Key {
            key: key_bytes,
            id: 42,
            cached_aead: CachedAeadKey::new(&key_bytes),
        };
        assert_eq!(key.id, 42);
        assert_eq!(key.key, key_bytes);

        // Verify the cached AEAD can encrypt
        let mut plaintext = vec![1u8, 2, 3, 4];
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        let result = key
            .cached_aead
            .aead
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut plaintext);
        assert!(result.is_ok());
    }
}
