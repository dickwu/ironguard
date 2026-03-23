use std::time::{Duration, Instant};

use rand::Rng;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Protocol messages
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct RekeyInit {
    pub epoch: u32,
    pub fresh_entropy: [u8; 32],
    pub new_receiver_id: u32,
}

#[derive(Clone, Debug)]
pub struct RekeyAck {
    pub epoch: u32,
    pub fresh_entropy: [u8; 32],
    pub new_receiver_id: u32,
}

#[derive(Clone, Debug)]
pub struct MigrationProbe {
    pub data_port: u16,
    pub challenge: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct MigrationAck {
    pub challenge_response: [u8; 16],
    pub new_data_port: u16,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("unexpected state for this operation")]
    InvalidState,
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u32, got: u32 },
    #[error("QUIC datagram error: {0}")]
    QuicDatagram(String),
}

// ---------------------------------------------------------------------------
// State enums
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RekeyState {
    Idle,
    InitSent {
        epoch: u32,
        our_entropy: [u8; 32],
        our_receiver_id: u32,
        sent_at: Instant,
    },
    Active {
        epoch: u32,
    },
}

#[derive(Debug)]
pub enum MigrationState {
    Stable,
    Probing {
        challenge: [u8; 16],
        sent_at: Instant,
    },
    Migrated,
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

pub struct SessionState {
    rekey: RekeyState,
    pub migration: MigrationState,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            rekey: RekeyState::Idle,
            migration: MigrationState::Stable,
        }
    }

    /// Transition Idle -> InitSent and return the rekey init message.
    /// The next epoch is `current_epoch + 1`.
    pub fn initiate_rekey(&mut self, our_entropy: [u8; 32], our_receiver_id: u32) -> RekeyInit {
        let next_epoch = self.current_epoch() + 1;

        self.rekey = RekeyState::InitSent {
            epoch: next_epoch,
            our_entropy,
            our_receiver_id,
            sent_at: Instant::now(),
        };

        RekeyInit {
            epoch: next_epoch,
            fresh_entropy: our_entropy,
            new_receiver_id: our_receiver_id,
        }
    }

    /// Responder receives a rekey init: advance to the proposed epoch and
    /// return an ack carrying our own fresh entropy and receiver id.
    pub fn handle_rekey_init(&mut self, init: &RekeyInit) -> RekeyAck {
        let mut rng = rand::rng();
        let mut our_entropy = [0u8; 32];
        rng.fill(&mut our_entropy);
        let our_receiver_id: u32 = rng.random();

        self.rekey = RekeyState::Active { epoch: init.epoch };

        RekeyAck {
            epoch: init.epoch,
            fresh_entropy: our_entropy,
            new_receiver_id: our_receiver_id,
        }
    }

    /// Initiator receives a rekey ack: validate epoch, transition
    /// InitSent -> Active, and return (epoch, initiator_entropy,
    /// responder_entropy).
    pub fn handle_rekey_ack(
        &mut self,
        ack: &RekeyAck,
    ) -> Result<(u32, [u8; 32], [u8; 32]), SessionError> {
        let (expected_epoch, our_entropy) = match &self.rekey {
            RekeyState::InitSent {
                epoch, our_entropy, ..
            } => (*epoch, *our_entropy),
            _ => return Err(SessionError::InvalidState),
        };

        if ack.epoch != expected_epoch {
            return Err(SessionError::EpochMismatch {
                expected: expected_epoch,
                got: ack.epoch,
            });
        }

        self.rekey = RekeyState::Active {
            epoch: expected_epoch,
        };

        Ok((expected_epoch, our_entropy, ack.fresh_entropy))
    }

    /// Return the current epoch (0 if no rekey has completed).
    pub fn current_epoch(&self) -> u32 {
        match &self.rekey {
            RekeyState::Idle => 0,
            RekeyState::InitSent { epoch, .. } => epoch.saturating_sub(1),
            RekeyState::Active { epoch } => *epoch,
        }
    }

    /// Transition Stable -> Probing and return the probe message.
    pub fn initiate_migration(&mut self, data_port: u16, challenge: [u8; 16]) -> MigrationProbe {
        self.migration = MigrationState::Probing {
            challenge,
            sent_at: Instant::now(),
        };

        MigrationProbe {
            data_port,
            challenge,
        }
    }

    /// Responder echoes the challenge back as its response.
    pub fn handle_migration_probe(&self, probe: &MigrationProbe) -> MigrationAck {
        MigrationAck {
            challenge_response: probe.challenge,
            new_data_port: probe.data_port,
        }
    }

    /// Initiator validates the challenge response (constant-time comparison)
    /// and transitions Probing -> Migrated.
    pub fn handle_migration_ack(&mut self, ack: &MigrationAck) -> Result<(), SessionError> {
        let expected_challenge = match &self.migration {
            MigrationState::Probing { challenge, .. } => *challenge,
            _ => return Err(SessionError::InvalidState),
        };

        if expected_challenge.ct_eq(&ack.challenge_response).into() {
            self.migration = MigrationState::Migrated;
            Ok(())
        } else {
            Err(SessionError::ChallengeMismatch)
        }
    }

    /// If the migration probe has been outstanding longer than `timeout`,
    /// return to Stable and report `true`. Otherwise return `false`.
    pub fn migration_timeout(&mut self, timeout: Duration) -> bool {
        let timed_out = match &self.migration {
            MigrationState::Probing { sent_at, .. } => sent_at.elapsed() >= timeout,
            _ => false,
        };

        if timed_out {
            self.migration = MigrationState::Stable;
        }

        timed_out
    }
}

// ---------------------------------------------------------------------------
// Tests (TDD — written BEFORE implementation)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rekey_happy_path() {
        // Initiator side
        let mut initiator = SessionState::new();
        assert_eq!(initiator.current_epoch(), 0);

        let our_entropy = [0xAA; 32];
        let our_receiver_id = 42;
        let init_msg = initiator.initiate_rekey(our_entropy, our_receiver_id);

        assert_eq!(init_msg.epoch, 1);
        assert_eq!(init_msg.fresh_entropy, our_entropy);
        assert_eq!(init_msg.new_receiver_id, our_receiver_id);

        // Responder side
        let mut responder = SessionState::new();
        let ack_msg = responder.handle_rekey_init(&init_msg);

        assert_eq!(ack_msg.epoch, 1);
        // Responder generates its own entropy + receiver_id
        assert_ne!(ack_msg.fresh_entropy, [0u8; 32]);

        // Initiator processes ack
        let result = initiator.handle_rekey_ack(&ack_msg);
        assert!(result.is_ok());

        let (epoch, initiator_entropy, responder_entropy) = result.unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(initiator_entropy, our_entropy);
        assert_eq!(responder_entropy, ack_msg.fresh_entropy);

        // Epoch is now active
        assert_eq!(initiator.current_epoch(), 1);
    }

    #[test]
    fn test_rekey_ack_wrong_epoch_fails() {
        let mut initiator = SessionState::new();
        let our_entropy = [0xBB; 32];
        let _init_msg = initiator.initiate_rekey(our_entropy, 100);

        // Construct an ack with the wrong epoch
        let bad_ack = RekeyAck {
            epoch: 999,
            fresh_entropy: [0xCC; 32],
            new_receiver_id: 200,
        };

        let result = initiator.handle_rekey_ack(&bad_ack);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                SessionError::EpochMismatch {
                    expected: 1,
                    got: 999
                }
            ),
            "expected EpochMismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_rekey_ack_when_idle_fails() {
        let mut state = SessionState::new();
        let ack = RekeyAck {
            epoch: 1,
            fresh_entropy: [0xDD; 32],
            new_receiver_id: 50,
        };

        let result = state.handle_rekey_ack(&ack);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SessionError::InvalidState),
            "expected InvalidState"
        );
    }

    #[test]
    fn test_migration_happy_path() {
        let mut state = SessionState::new();
        let challenge = [0x11; 16];
        let data_port = 51820;

        let probe = state.initiate_migration(data_port, challenge);
        assert_eq!(probe.data_port, data_port);
        assert_eq!(probe.challenge, challenge);

        // Remote side handles probe
        let remote = SessionState::new();
        let ack = remote.handle_migration_probe(&probe);
        assert_eq!(ack.challenge_response, challenge);

        // Initiator processes ack
        let result = state.handle_migration_ack(&ack);
        assert!(result.is_ok());

        // State should be Migrated
        assert!(matches!(state.migration, MigrationState::Migrated));
    }

    #[test]
    fn test_migration_wrong_challenge_fails() {
        let mut state = SessionState::new();
        let challenge = [0x22; 16];
        let _probe = state.initiate_migration(51820, challenge);

        // Ack with wrong challenge
        let bad_ack = MigrationAck {
            challenge_response: [0xFF; 16],
            new_data_port: 51821,
        };

        let result = state.handle_migration_ack(&bad_ack);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SessionError::ChallengeMismatch),
            "expected ChallengeMismatch"
        );
    }

    #[test]
    fn test_migration_timeout_returns_to_stable() {
        let mut state = SessionState::new();
        let challenge = [0x33; 16];
        let _probe = state.initiate_migration(51820, challenge);

        // Probing state
        assert!(matches!(state.migration, MigrationState::Probing { .. }));

        // With zero timeout, it should immediately be considered timed out
        let timed_out = state.migration_timeout(Duration::from_secs(0));
        assert!(timed_out);
        assert!(matches!(state.migration, MigrationState::Stable));
    }
}
