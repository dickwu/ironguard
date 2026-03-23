use std::time::Duration;

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4);

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const MAX_TIMER_HANDSHAKES: usize =
    (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as usize;

pub const MAX_QUEUED_INCOMING_HANDSHAKES: usize = 4096;
pub const THRESHOLD_UNDER_LOAD: usize = MAX_QUEUED_INCOMING_HANDSHAKES / 8;
pub const DURATION_UNDER_LOAD: Duration = Duration::from_secs(1);

pub const MESSAGE_PADDING_MULTIPLE: usize = 16;

pub const SIZE_MESSAGE_PREFIX: usize = 64;

// WireGuard handshake message type identifiers.
pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;

/// Conservative TUN MTU that covers both IPv4 and IPv6 outer headers.
/// 1500 (Ethernet MTU) - 60 (IPv6 header) - 8 (UDP) - 4 (type) - 8 (nonce) = 1420
pub const TUN_MTU: usize = 1420;
