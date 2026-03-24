//! Relay wire protocol definitions.
//!
//! Messages are JSON-encoded and sent as QUIC datagrams or
//! stream frames. The relay is a dumb forwarder -- it routes
//! messages between registered peers by their ephemeral tokens.

use serde::{Deserialize, Serialize};

/// Maximum size of a relay message payload.
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Maximum size of a relay token.
pub const MAX_TOKEN_SIZE: usize = 64;

/// Messages exchanged between relay clients and the relay server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    /// Client registers with the relay using an ephemeral token.
    /// The token is NOT the public key -- it is derived from a
    /// per-session secret to prevent identity correlation.
    #[serde(rename = "register")]
    Register {
        /// Ephemeral relay token (hex-encoded).
        token: String,
    },

    /// Server acknowledges registration.
    #[serde(rename = "registered")]
    Registered {
        /// Whether registration succeeded.
        ok: bool,
        /// Optional error reason if `ok` is false.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// Client requests forwarding a packet to another peer.
    #[serde(rename = "forward")]
    Forward {
        /// Ephemeral token of the destination peer.
        to_token: String,
        /// Encrypted payload (base64-encoded for JSON transport).
        data: String,
    },

    /// Server delivers a forwarded packet to a registered peer.
    #[serde(rename = "deliver")]
    Deliver {
        /// Ephemeral token of the sender.
        from_token: String,
        /// Encrypted payload (base64-encoded).
        data: String,
    },

    /// Health check ping.
    #[serde(rename = "ping")]
    Ping {
        /// Sequence number for RTT measurement.
        seq: u64,
    },

    /// Health check pong.
    #[serde(rename = "pong")]
    Pong {
        /// Echoed sequence number.
        seq: u64,
    },
}

impl RelayMessage {
    /// Serializes the message to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes a message from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Encodes binary data as base64 for JSON transport.
pub fn encode_payload(data: &[u8]) -> String {
    // Use hex encoding for simplicity and debuggability.
    // For production, base64 would be more compact.
    hex::encode(data)
}

/// Decodes a hex-encoded payload back to bytes.
pub fn decode_payload(encoded: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_serialization() {
        let msg = RelayMessage::Register {
            token: "abc123".into(),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Register { token } => assert_eq!(token, "abc123"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_registered_ok() {
        let msg = RelayMessage::Registered {
            ok: true,
            reason: None,
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Registered { ok, reason } => {
                assert!(ok);
                assert!(reason.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_registered_fail() {
        let msg = RelayMessage::Registered {
            ok: false,
            reason: Some("token already taken".into()),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Registered { ok, reason } => {
                assert!(!ok);
                assert_eq!(reason.unwrap(), "token already taken");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_forward_serialization() {
        let payload = encode_payload(b"encrypted-data");
        let msg = RelayMessage::Forward {
            to_token: "target-token".into(),
            data: payload.clone(),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Forward { to_token, data } => {
                assert_eq!(to_token, "target-token");
                let raw = decode_payload(&data).unwrap();
                assert_eq!(raw, b"encrypted-data");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_deliver_serialization() {
        let payload = encode_payload(b"forwarded-data");
        let msg = RelayMessage::Deliver {
            from_token: "sender-token".into(),
            data: payload,
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Deliver { from_token, data } => {
                assert_eq!(from_token, "sender-token");
                let raw = decode_payload(&data).unwrap();
                assert_eq!(raw, b"forwarded-data");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_ping_pong() {
        let ping = RelayMessage::Ping { seq: 42 };
        let bytes = ping.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Ping { seq } => assert_eq!(seq, 42),
            _ => panic!("wrong variant"),
        }

        let pong = RelayMessage::Pong { seq: 42 };
        let bytes = pong.to_bytes().unwrap();
        let decoded = RelayMessage::from_bytes(&bytes).unwrap();
        match decoded {
            RelayMessage::Pong { seq } => assert_eq!(seq, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_encode_decode_payload() {
        let data = b"hello world";
        let encoded = encode_payload(data);
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_empty_payload() {
        let encoded = encode_payload(b"");
        assert!(encoded.is_empty());
        let decoded = decode_payload(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_payload("not-hex-zzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = RelayMessage::from_bytes(b"not json");
        assert!(result.is_err());
    }
}
