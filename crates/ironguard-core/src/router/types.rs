use crate::types::KeyPair;
use std::sync::Arc;

/// Callbacks trait for the router to notify upper layers about events.
pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Send + Sync + 'static;

    /// Called after encrypting and sending (or attempting to send) a packet.
    fn send(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);

    /// Called after successfully decrypting and processing an inbound packet.
    fn recv(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>);

    /// Called when a packet needs to be sent but no encryption key is available.
    fn need_key(opaque: &Self::Opaque);

    /// Called when a key is confirmed by receiving a valid message encrypted with it.
    fn key_confirmed(opaque: &Self::Opaque);
}

/// Router-level errors.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("No cryptokey route configured for subnet")]
    NoCryptoKeyRoute,

    #[error("Transport header is malformed")]
    MalformedTransportMessage,

    #[error("No decryption state associated with receiver id")]
    UnknownReceiverId,

    #[error("No endpoint for peer")]
    NoEndpoint,

    #[error("Failed to send packet on bind")]
    SendError,
}
