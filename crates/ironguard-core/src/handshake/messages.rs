// Wire-format message types for the WireGuard handshake layer.

const SIZE_MAC: usize = 16;
const SIZE_TAG: usize = 16; // poly1305 tag
const SIZE_XNONCE: usize = 24; // xchacha20 nonce
const SIZE_COOKIE: usize = 16;
const SIZE_X25519_POINT: usize = 32; // x25519 public key
const SIZE_TIMESTAMP: usize = 12;

pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;

/// Handshake initiation inner Noise message.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct NoiseInitiation {
    pub f_type: [u8; 4],
    pub f_sender: [u8; 4],
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_static: [u8; SIZE_X25519_POINT + SIZE_TAG],
    pub f_timestamp: [u8; SIZE_TIMESTAMP + SIZE_TAG],
}

impl NoiseInitiation {
    pub fn msg_type(&self) -> u32 {
        u32::from_le_bytes(self.f_type)
    }
    pub fn sender(&self) -> u32 {
        u32::from_le_bytes(self.f_sender)
    }
    pub fn set_type(&mut self, t: u32) {
        self.f_type = t.to_le_bytes();
    }
    pub fn set_sender(&mut self, s: u32) {
        self.f_sender = s.to_le_bytes();
    }
}

impl Default for NoiseInitiation {
    fn default() -> Self {
        let mut s = Self {
            f_type: [0u8; 4],
            f_sender: [0u8; 4],
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_static: [0u8; SIZE_X25519_POINT + SIZE_TAG],
            f_timestamp: [0u8; SIZE_TIMESTAMP + SIZE_TAG],
        };
        s.set_type(TYPE_INITIATION);
        s
    }
}

/// Handshake response inner Noise message.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct NoiseResponse {
    pub f_type: [u8; 4],
    pub f_sender: [u8; 4],
    pub f_receiver: [u8; 4],
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_empty: [u8; SIZE_TAG],
}

impl NoiseResponse {
    pub fn msg_type(&self) -> u32 {
        u32::from_le_bytes(self.f_type)
    }
    pub fn sender(&self) -> u32 {
        u32::from_le_bytes(self.f_sender)
    }
    pub fn receiver(&self) -> u32 {
        u32::from_le_bytes(self.f_receiver)
    }
    pub fn set_type(&mut self, t: u32) {
        self.f_type = t.to_le_bytes();
    }
    pub fn set_sender(&mut self, s: u32) {
        self.f_sender = s.to_le_bytes();
    }
    pub fn set_receiver(&mut self, r: u32) {
        self.f_receiver = r.to_le_bytes();
    }
}

impl Default for NoiseResponse {
    fn default() -> Self {
        let mut s = Self {
            f_type: [0u8; 4],
            f_sender: [0u8; 4],
            f_receiver: [0u8; 4],
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_empty: [0u8; SIZE_TAG],
        };
        s.set_type(TYPE_RESPONSE);
        s
    }
}

/// MAC1 + MAC2 footer appended to every handshake message.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct MacsFooter {
    pub f_mac1: [u8; SIZE_MAC],
    pub f_mac2: [u8; SIZE_MAC],
}

/// Full handshake initiation message (NoiseInitiation + MacsFooter).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct Initiation {
    pub noise: NoiseInitiation,
    pub macs: MacsFooter,
}

/// Full handshake response message (NoiseResponse + MacsFooter).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct Response {
    pub noise: NoiseResponse,
    pub macs: MacsFooter,
}

/// Cookie reply message.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct CookieReply {
    pub f_type: [u8; 4],
    pub f_receiver: [u8; 4],
    pub f_nonce: [u8; SIZE_XNONCE],
    pub f_cookie: [u8; SIZE_COOKIE + SIZE_TAG],
}

impl CookieReply {
    pub fn msg_type(&self) -> u32 {
        u32::from_le_bytes(self.f_type)
    }
    pub fn receiver(&self) -> u32 {
        u32::from_le_bytes(self.f_receiver)
    }
    pub fn set_type(&mut self, t: u32) {
        self.f_type = t.to_le_bytes();
    }
    pub fn set_receiver(&mut self, r: u32) {
        self.f_receiver = r.to_le_bytes();
    }
}

impl Default for CookieReply {
    fn default() -> Self {
        let mut s = Self {
            f_type: [0u8; 4],
            f_receiver: [0u8; 4],
            f_nonce: [0u8; SIZE_XNONCE],
            f_cookie: [0u8; SIZE_COOKIE + SIZE_TAG],
        };
        s.set_type(TYPE_COOKIE_REPLY);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_sizes() {
        // TransportHeader lives in router::messages; here we verify handshake sizes.
        // WireGuard spec sizes:
        //   Initiation  = 148 bytes
        //   Response    = 92 bytes
        //   CookieReply = 64 bytes
        assert_eq!(std::mem::size_of::<Initiation>(), 148);
        assert_eq!(std::mem::size_of::<Response>(), 92);
        assert_eq!(std::mem::size_of::<CookieReply>(), 64);
    }
}
