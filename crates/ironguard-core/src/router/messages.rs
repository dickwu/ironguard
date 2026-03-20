// Wire-format message types for the WireGuard transport layer.

pub const TYPE_TRANSPORT: u32 = 4;

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct TransportHeader {
    pub f_type: [u8; 4],
    pub f_receiver: [u8; 4],
    pub f_counter: [u8; 8],
}

impl TransportHeader {
    pub fn message_type(&self) -> u32 {
        u32::from_le_bytes(self.f_type)
    }

    pub fn receiver(&self) -> u32 {
        u32::from_le_bytes(self.f_receiver)
    }

    pub fn counter(&self) -> u64 {
        u64::from_le_bytes(self.f_counter)
    }

    pub fn set_type(&mut self, t: u32) {
        self.f_type = t.to_le_bytes();
    }

    pub fn set_receiver(&mut self, r: u32) {
        self.f_receiver = r.to_le_bytes();
    }

    pub fn set_counter(&mut self, c: u64) {
        self.f_counter = c.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_header_size() {
        assert_eq!(std::mem::size_of::<TransportHeader>(), 16);
    }
}
