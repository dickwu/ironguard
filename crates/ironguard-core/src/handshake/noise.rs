// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake via the `snow` crate.
//
// This module provides thin wrappers around snow to build initiator and
// responder HandshakeState objects for the WireGuard Noise variant.

pub const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

use crate::handshake::macs::HandshakeError;

/// Build an initiator HandshakeState.
///
/// # Arguments
/// * `local_sk` — 32-byte local static private key
/// * `remote_pk` — 32-byte remote static public key (must be known ahead of time for IK)
/// * `psk`       — 32-byte pre-shared key
pub fn build_initiator(
    local_sk: &[u8],
    remote_pk: &[u8],
    psk: &[u8; 32],
) -> Result<snow::HandshakeState, HandshakeError> {
    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|_| HandshakeError::InvalidMessageFormat)?;
    snow::Builder::new(params)
        .local_private_key(local_sk)
        .map_err(|_| HandshakeError::InvalidMessageFormat)?
        .remote_public_key(remote_pk)
        .map_err(|_| HandshakeError::InvalidMessageFormat)?
        .psk(2, psk)
        .map_err(|_| HandshakeError::InvalidMessageFormat)?
        .build_initiator()
        .map_err(|_| HandshakeError::InvalidMessageFormat)
}

/// Build a responder HandshakeState.
///
/// # Arguments
/// * `local_sk` — 32-byte local static private key
/// * `psk`       — 32-byte pre-shared key
pub fn build_responder(
    local_sk: &[u8],
    psk: &[u8; 32],
) -> Result<snow::HandshakeState, HandshakeError> {
    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|_| HandshakeError::InvalidMessageFormat)?;
    snow::Builder::new(params)
        .local_private_key(local_sk)
        .map_err(|_| HandshakeError::InvalidMessageFormat)?
        .psk(2, psk)
        .map_err(|_| HandshakeError::InvalidMessageFormat)?
        .build_responder()
        .map_err(|_| HandshakeError::InvalidMessageFormat)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let builder = snow::Builder::new(params);
        let kp = builder.generate_keypair().unwrap();
        (kp.private, kp.public)
    }

    #[test]
    fn test_noise_handshake_completes() {
        let (sk_i, _pk_i) = generate_keypair();
        let (sk_r, pk_r) = generate_keypair();
        let psk = [0u8; 32];

        let mut initiator = build_initiator(&sk_i, &pk_r, &psk).unwrap();
        let mut responder = build_responder(&sk_r, &psk).unwrap();

        // Initiator -> Responder (message 1)
        let mut buf = vec![0u8; 4096];
        let len = initiator.write_message(&[], &mut buf).unwrap();

        // Responder processes message 1 and sends message 2
        let mut payload = vec![0u8; 4096];
        responder.read_message(&buf[..len], &mut payload).unwrap();
        let len2 = responder.write_message(&[], &mut buf).unwrap();

        // Initiator processes message 2
        initiator.read_message(&buf[..len2], &mut payload).unwrap();

        // Both transition to transport mode
        let mut i_transport = initiator.into_transport_mode().unwrap();
        let mut r_transport = responder.into_transport_mode().unwrap();

        // Initiator encrypts a test message
        let msg = b"hello ironguard";
        let mut encrypted = vec![0u8; msg.len() + 16 + 8];
        let elen = i_transport.write_message(msg, &mut encrypted).unwrap();

        // Responder decrypts it
        let mut decrypted = vec![0u8; elen];
        let dlen = r_transport
            .read_message(&encrypted[..elen], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..dlen], msg);
    }

    #[test]
    fn test_noise_reverse_direction() {
        let (sk_i, _pk_i) = generate_keypair();
        let (sk_r, pk_r) = generate_keypair();
        let psk = [1u8; 32];

        let mut initiator = build_initiator(&sk_i, &pk_r, &psk).unwrap();
        let mut responder = build_responder(&sk_r, &psk).unwrap();

        let mut buf = vec![0u8; 4096];
        let mut payload = vec![0u8; 4096];

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut payload).unwrap();
        let len2 = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..len2], &mut payload).unwrap();

        let mut i_transport = initiator.into_transport_mode().unwrap();
        let mut r_transport = responder.into_transport_mode().unwrap();

        // Responder sends back to initiator
        let msg = b"reply from responder";
        let mut encrypted = vec![0u8; msg.len() + 16 + 8];
        let elen = r_transport.write_message(msg, &mut encrypted).unwrap();

        let mut decrypted = vec![0u8; elen];
        let dlen = i_transport
            .read_message(&encrypted[..elen], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..dlen], msg);
    }

    #[test]
    fn test_noise_key_symmetry() {
        let (sk_i, _pk_i) = generate_keypair();
        let (sk_r, pk_r) = generate_keypair();
        let psk = [42u8; 32];

        for _ in 0..2 {
            let mut initiator = build_initiator(&sk_i, &pk_r, &psk).unwrap();
            let mut responder = build_responder(&sk_r, &psk).unwrap();

            let mut buf = vec![0u8; 4096];
            let mut payload = vec![0u8; 4096];

            let len = initiator.write_message(&[], &mut buf).unwrap();
            responder.read_message(&buf[..len], &mut payload).unwrap();
            let len2 = responder.write_message(&[], &mut buf).unwrap();
            initiator.read_message(&buf[..len2], &mut payload).unwrap();

            let mut it = initiator.into_transport_mode().unwrap();
            let mut rt = responder.into_transport_mode().unwrap();

            let msg = b"symmetry check";
            let mut enc = vec![0u8; msg.len() + 24];
            let elen = it.write_message(msg, &mut enc).unwrap();
            let mut dec = vec![0u8; elen];
            let dlen = rt.read_message(&enc[..elen], &mut dec).unwrap();
            assert_eq!(&dec[..dlen], msg);
        }
    }
}
