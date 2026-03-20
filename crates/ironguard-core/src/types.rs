use std::time::Instant;
use zeroize::Zeroize;

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
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key {
    pub key: [u8; 32],
    #[zeroize(skip)]
    pub id: u32,
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
