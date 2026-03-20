//! Post-quantum key exchange using ML-KEM-768 (FIPS 203).
//!
//! This module provides hybrid post-quantum key exchange for WireGuard's PSK slot.
//! The ML-KEM-768 shared secret is hashed with BLAKE2s to produce a 32-byte PSK
//! that is injected into the Noise_IKpsk2 handshake.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core_06::OsRng;
use zeroize::Zeroizing;

/// ML-KEM-768 encapsulation key size in bytes.
pub const EK_SIZE: usize = 1184;

/// ML-KEM-768 decapsulation key size in bytes.
pub const DK_SIZE: usize = 2400;

/// ML-KEM-768 ciphertext size in bytes.
pub const CT_SIZE: usize = 1088;

/// A post-quantum keypair for ML-KEM-768.
#[derive(Debug)]
pub struct PqKeyPair {
    pub encapsulation_key: EncapsulationKey<MlKem768Params>,
    pub decapsulation_key: DecapsulationKey<MlKem768Params>,
}

impl PqKeyPair {
    /// Generate a new ML-KEM-768 keypair.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        }
    }

    /// Serialize the decapsulation (private) key to bytes.
    pub fn dk_bytes(&self) -> Vec<u8> {
        self.decapsulation_key.as_bytes().to_vec()
    }

    /// Serialize the encapsulation (public) key to bytes.
    pub fn ek_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.as_bytes().to_vec()
    }

    /// Reconstruct a keypair from serialized decapsulation key bytes.
    ///
    /// The encapsulation key is derived from the decapsulation key.
    pub fn from_dk_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        let encoded: &Encoded<DecapsulationKey<MlKem768Params>> =
            bytes.try_into().map_err(|_| PqError::InvalidDecapsulationKey)?;
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(encoded);
        let ek = dk.encapsulation_key().clone();
        Ok(Self {
            encapsulation_key: ek,
            decapsulation_key: dk,
        })
    }
}

/// Parse an encapsulation key from raw bytes.
pub fn parse_encapsulation_key(
    bytes: &[u8],
) -> Result<EncapsulationKey<MlKem768Params>, PqError> {
    let encoded: &Encoded<EncapsulationKey<MlKem768Params>> =
        bytes.try_into().map_err(|_| PqError::InvalidEncapsulationKey)?;
    Ok(EncapsulationKey::<MlKem768Params>::from_bytes(encoded))
}

/// Encapsulate: produces (ciphertext, psk).
///
/// The ciphertext should be sent to the peer who holds the corresponding
/// decapsulation key. The PSK (32 bytes) is fed into the WireGuard
/// Noise_IKpsk2 handshake's PSK slot.
pub fn encapsulate(
    peer_ek: &EncapsulationKey<MlKem768Params>,
) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
    let (ct, ss) = peer_ek
        .encapsulate(&mut OsRng)
        .expect("ML-KEM encapsulation is infallible");

    let psk = blake2s_derive_psk(ss.as_slice());
    (ct.to_vec(), Zeroizing::new(psk))
}

/// Decapsulate: recovers the PSK from a ciphertext.
///
/// The returned 32-byte PSK matches the one produced by [`encapsulate`]
/// when called with the corresponding encapsulation key.
pub fn decapsulate(
    dk: &DecapsulationKey<MlKem768Params>,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PqError> {
    let ct = ciphertext
        .try_into()
        .map_err(|_| PqError::InvalidCiphertext)?;
    let ss = dk
        .decapsulate(ct)
        .map_err(|_| PqError::DecapsulationFailed)?;

    let psk = blake2s_derive_psk(ss.as_slice());
    Ok(Zeroizing::new(psk))
}

/// Derive a 32-byte PSK from an ML-KEM shared secret using BLAKE2s.
///
/// Uses a domain-separation label so the output is distinct from other
/// uses of the same shared secret.
fn blake2s_derive_psk(shared_secret: &[u8]) -> [u8; 32] {
    let hash = blake2s_simd::Params::new()
        .hash_length(32)
        .personal(b"ig-pqpsk")
        .hash(shared_secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Errors that can occur during post-quantum key exchange.
#[derive(Debug, thiserror::Error)]
pub enum PqError {
    /// The ciphertext bytes are not a valid ML-KEM-768 ciphertext.
    #[error("invalid ML-KEM-768 ciphertext (expected {CT_SIZE} bytes)")]
    InvalidCiphertext,

    /// ML-KEM decapsulation failed.
    #[error("ML-KEM-768 decapsulation failed")]
    DecapsulationFailed,

    /// The encapsulation key bytes are not valid.
    #[error("invalid ML-KEM-768 encapsulation key (expected {EK_SIZE} bytes)")]
    InvalidEncapsulationKey,

    /// The decapsulation key bytes are not valid.
    #[error("invalid ML-KEM-768 decapsulation key (expected {DK_SIZE} bytes)")]
    InvalidDecapsulationKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = PqKeyPair::generate();
        assert_eq!(kp.ek_bytes().len(), EK_SIZE);
        assert_eq!(kp.dk_bytes().len(), DK_SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let kp = PqKeyPair::generate();
        let (ct, psk_enc) = encapsulate(&kp.encapsulation_key);
        assert_eq!(ct.len(), CT_SIZE);

        let psk_dec = decapsulate(&kp.decapsulation_key, &ct).unwrap();
        assert_eq!(*psk_enc, *psk_dec);
    }

    #[test]
    fn test_different_keypairs_produce_different_psks() {
        let kp1 = PqKeyPair::generate();
        let kp2 = PqKeyPair::generate();
        let (_, psk1) = encapsulate(&kp1.encapsulation_key);
        let (_, psk2) = encapsulate(&kp2.encapsulation_key);
        assert_ne!(*psk1, *psk2);
    }

    #[test]
    fn test_invalid_ciphertext_rejected() {
        let kp = PqKeyPair::generate();
        let result = decapsulate(&kp.decapsulation_key, &[0u8; 100]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PqError::InvalidCiphertext));
    }

    #[test]
    fn test_keypair_serialization_roundtrip() {
        let kp = PqKeyPair::generate();
        let dk_bytes = kp.dk_bytes();
        let ek_bytes = kp.ek_bytes();

        let kp2 = PqKeyPair::from_dk_bytes(&dk_bytes).unwrap();
        assert_eq!(kp2.ek_bytes(), ek_bytes);

        // Verify the reconstructed keypair still works
        let (ct, psk_enc) = encapsulate(&kp2.encapsulation_key);
        let psk_dec = decapsulate(&kp2.decapsulation_key, &ct).unwrap();
        assert_eq!(*psk_enc, *psk_dec);
    }

    #[test]
    fn test_parse_encapsulation_key() {
        let kp = PqKeyPair::generate();
        let ek_bytes = kp.ek_bytes();

        let ek = parse_encapsulation_key(&ek_bytes).unwrap();
        let (ct, psk_enc) = encapsulate(&ek);
        let psk_dec = decapsulate(&kp.decapsulation_key, &ct).unwrap();
        assert_eq!(*psk_enc, *psk_dec);
    }

    #[test]
    fn test_parse_invalid_encapsulation_key() {
        let result = parse_encapsulation_key(&[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PqError::InvalidEncapsulationKey
        ));
    }

    #[test]
    fn test_invalid_dk_bytes_rejected() {
        let result = PqKeyPair::from_dk_bytes(&[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PqError::InvalidDecapsulationKey
        ));
    }
}
