// Internal handshake peer state.
//
// Each peer tracks:
//   - a snow HandshakeState (when an initiation has been sent but not yet
//     confirmed by a response)
//   - the TAI64N timestamp of the last accepted initiation (replay protection)
//   - the Generator used to stamp MAC1/MAC2 on outgoing messages

use parking_lot::Mutex;

use crate::PublicKey;
use crate::handshake::macs;
use crate::handshake::timestamp;

/// State machine for one initiating peer.
pub(super) enum PeerState {
    /// No handshake in flight.
    Reset,
    /// An initiation has been sent; we are waiting for the response.
    InitiationSent {
        /// snow HandshakeState after writing message 1.
        hs: Box<snow::HandshakeState>,
        /// The receiver ID we allocated for this handshake.
        local_id: u32,
    },
}

/// Internal handshake peer.  Generic over an opaque caller-owned value.
#[allow(dead_code)]
pub(super) struct Peer<O> {
    /// Caller-provided value associated with this peer (e.g. a router peer handle).
    pub opaque: O,
    /// Remote static public key.
    pub pk: PublicKey,
    /// 32-byte pre-shared key (zero by default).
    pub psk: [u8; 32],
    /// Current handshake state (protected by a mutex because Device is Send+Sync).
    pub state: Mutex<PeerState>,
    /// Timestamp of the last accepted initiation (for replay protection).
    pub last_timestamp: Mutex<Option<timestamp::TAI64N>>,
    /// MAC generator for outgoing messages addressed to this peer.
    pub macs: Mutex<macs::Generator>,
}

impl<O> Peer<O> {
    pub fn new(pk: PublicKey, opaque: O) -> Self {
        let macs = macs::Generator::new(&pk);
        Self {
            opaque,
            pk,
            psk: [0u8; 32],
            state: Mutex::new(PeerState::Reset),
            last_timestamp: Mutex::new(None),
            macs: Mutex::new(macs),
        }
    }

    /// Reset the handshake state to `Reset`, returning the previously held
    /// local ID (if any) so the caller can release it back to the pool.
    pub fn reset_state(&self) -> Option<u32> {
        let mut guard = self.state.lock();
        match std::mem::replace(&mut *guard, PeerState::Reset) {
            PeerState::InitiationSent { local_id, .. } => Some(local_id),
            PeerState::Reset => None,
        }
    }
}
