const VERSION_IP4: u8 = 4;
const VERSION_IP6: u8 = 6;

/// Extract the inner (payload) length from an IP packet header.
/// Returns None for non-IP packets or packets too short to parse.
#[inline(always)]
pub fn inner_length(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        VERSION_IP4 => {
            if packet.len() < 20 {
                return None;
            }
            // Total length is at bytes [2..4] in big-endian
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            Some(total_len)
        }
        VERSION_IP6 => {
            if packet.len() < 40 {
                return None;
            }
            // Payload length is at bytes [4..6] in big-endian, plus 40-byte header
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            Some(payload_len + 40)
        }
        _ => None,
    }
}
