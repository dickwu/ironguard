// IronGuard v2 frame format
// 16-byte header: Type(8) | Flags(8) | Reserved(16) | ReceiverID(32) | Counter(64)

pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_KEEPALIVE: u8 = 0x02;
pub const TYPE_CONTROL: u8 = 0x03;
pub const TYPE_BATCH: u8 = 0x04;

pub const HEADER_SIZE: usize = 16;
pub const BATCH_HEADER_SIZE: usize = 20;

/// IronGuard v2 frame header.
///
/// 16 bytes, little-endian on the wire:
/// ```text
///  0       1       2       3       4               8               16
/// +-------+-------+-------+-------+---------------+---------------+
/// | Type  | Flags |   Reserved    |  ReceiverID   |    Counter    |
/// +-------+-------+-------+-------+---------------+---------------+
/// ```
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct FrameHeader {
    pub f_type: u8,
    pub f_flags: u8,
    pub f_reserved: [u8; 2],
    pub f_receiver: [u8; 4],
    pub f_counter: [u8; 8],
}

impl FrameHeader {
    /// Create a data frame header.
    pub fn new_data(receiver_id: u32, counter: u64) -> Self {
        Self {
            f_type: TYPE_DATA,
            f_flags: 0,
            f_reserved: [0; 2],
            f_receiver: receiver_id.to_le_bytes(),
            f_counter: counter.to_le_bytes(),
        }
    }

    /// Create a keepalive frame header.
    pub fn new_keepalive(receiver_id: u32, counter: u64) -> Self {
        Self {
            f_type: TYPE_KEEPALIVE,
            f_flags: 0,
            f_reserved: [0; 2],
            f_receiver: receiver_id.to_le_bytes(),
            f_counter: counter.to_le_bytes(),
        }
    }

    /// Create a batch frame header (use `BatchHeader::new` for the full batch header).
    pub fn new_batch(receiver_id: u32, counter: u64) -> Self {
        Self {
            f_type: TYPE_BATCH,
            f_flags: 0,
            f_reserved: [0; 2],
            f_receiver: receiver_id.to_le_bytes(),
            f_counter: counter.to_le_bytes(),
        }
    }

    pub fn msg_type(&self) -> u8 {
        self.f_type
    }

    pub fn flags(&self) -> u8 {
        self.f_flags
    }

    pub fn receiver_id(&self) -> u32 {
        u32::from_le_bytes(self.f_receiver)
    }

    pub fn counter(&self) -> u64 {
        u64::from_le_bytes(self.f_counter)
    }

    /// Reinterpret this header as a raw byte array.
    ///
    /// # Safety
    ///
    /// Safe because `FrameHeader` is `#[repr(C, packed)]` with no padding,
    /// and `HEADER_SIZE` equals `size_of::<FrameHeader>()`.
    pub fn as_bytes(&self) -> &[u8; HEADER_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; HEADER_SIZE]) }
    }

    /// Interpret a byte slice as a `FrameHeader` reference.
    ///
    /// Returns `None` if the slice is shorter than `HEADER_SIZE`.
    ///
    /// # Safety
    ///
    /// Safe because `FrameHeader` is `#[repr(C, packed)]` (alignment 1, no padding)
    /// and we verify length before casting.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        // SAFETY: FrameHeader is repr(C, packed) so alignment is 1 and there is
        // no padding. We verified the slice has at least HEADER_SIZE bytes.
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    /// Return the header bytes for use as Additional Authenticated Data (AAD).
    pub fn as_aad(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// IronGuard v2 batch header.
///
/// 20 bytes: a `FrameHeader` (type = `TYPE_BATCH`) followed by batch metadata.
/// ```text
///  0                               16      18      20
/// +-------------------------------+-------+-------+
/// |          FrameHeader          | Count | TotLen|
/// +-------------------------------+-------+-------+
/// ```
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct BatchHeader {
    pub frame: FrameHeader,
    pub f_batch_count: [u8; 2],
    pub f_total_len: [u8; 2],
}

impl BatchHeader {
    /// Create a new batch header.
    pub fn new(receiver_id: u32, counter: u64, batch_count: u16, total_len: u16) -> Self {
        Self {
            frame: FrameHeader::new_batch(receiver_id, counter),
            f_batch_count: batch_count.to_le_bytes(),
            f_total_len: total_len.to_le_bytes(),
        }
    }

    pub fn batch_count(&self) -> u16 {
        u16::from_le_bytes(self.f_batch_count)
    }

    pub fn total_len(&self) -> u16 {
        u16::from_le_bytes(self.f_total_len)
    }

    /// Reinterpret this batch header as a raw byte array.
    ///
    /// # Safety
    ///
    /// Safe because `BatchHeader` is `#[repr(C, packed)]` with no padding,
    /// and `BATCH_HEADER_SIZE` equals `size_of::<BatchHeader>()`.
    pub fn as_bytes(&self) -> &[u8; BATCH_HEADER_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; BATCH_HEADER_SIZE]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size_is_16_bytes() {
        assert_eq!(std::mem::size_of::<FrameHeader>(), 16);
    }

    #[test]
    fn test_batch_header_size_is_20_bytes() {
        assert_eq!(std::mem::size_of::<BatchHeader>(), 20);
    }

    #[test]
    fn test_header_roundtrip() {
        let hdr = FrameHeader::new_data(0xDEAD_BEEF, 42);
        let bytes = hdr.as_bytes();
        let parsed = FrameHeader::from_bytes(bytes).unwrap();
        assert_eq!(parsed.msg_type(), TYPE_DATA);
        assert_eq!(parsed.receiver_id(), 0xDEAD_BEEF);
        assert_eq!(parsed.counter(), 42);
    }

    #[test]
    fn test_keepalive_type() {
        let hdr = FrameHeader::new_keepalive(1, 0);
        assert_eq!(hdr.msg_type(), TYPE_KEEPALIVE);
    }

    #[test]
    fn test_batch_header_roundtrip() {
        let hdr = BatchHeader::new(100, 500, 64, 4096);
        assert_eq!(hdr.frame.msg_type(), TYPE_BATCH);
        assert_eq!(hdr.batch_count(), 64);
        assert_eq!(hdr.total_len(), 4096);
    }

    #[test]
    fn test_header_as_aad() {
        let hdr = FrameHeader::new_data(1, 0);
        let aad = hdr.as_aad();
        assert_eq!(aad.len(), 16);
    }

    #[test]
    fn test_from_bytes_too_short() {
        let short = [0u8; 10];
        assert!(FrameHeader::from_bytes(&short).is_none());
    }
}
