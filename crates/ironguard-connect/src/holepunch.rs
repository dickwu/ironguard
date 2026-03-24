//! Coordinated UDP hole punching.
//!
//! Sends UDP packets to a remote peer's reflexive address to create
//! a NAT pinhole, allowing return traffic through. Both sides must
//! punch simultaneously (coordinated via a signaling channel) for
//! the technique to work with Endpoint-Independent Mapping NATs.
//!
//! Success rate: >95% for EIM (easy) NATs, ~0% for EDM (hard) NATs.
//! For hard NATs, use the birthday paradox spray instead.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default timeout for a hole punch attempt.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between successive punch packets.
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);

/// Size of the punch probe packet (just a magic + nonce).
const PROBE_SIZE: usize = 12;

/// Magic bytes at the start of punch probes for identification.
const PUNCH_MAGIC: [u8; 4] = [0x49, 0x47, 0x48, 0x50]; // "IGHP"

/// Errors from hole punching operations.
#[derive(Debug, Error)]
pub enum HolepunchError {
    /// Socket creation or binding failed.
    #[error("socket error: {0}")]
    SocketError(#[from] std::io::Error),

    /// The hole punch timed out without receiving a response.
    #[error("hole punch timed out after {0:?}")]
    Timeout(Duration),

    /// The received response did not match the expected format.
    #[error("invalid probe response")]
    InvalidResponse,
}

/// Result of a successful hole punch.
#[derive(Debug)]
pub struct HolepunchResult {
    /// The UDP socket with an established NAT pinhole.
    pub socket: UdpSocket,
    /// The remote address that responded.
    pub remote_addr: SocketAddr,
    /// How long the hole punch took.
    pub elapsed: Duration,
}

/// Performs coordinated UDP hole punching.
///
/// The puncher sends probe packets to the remote address at regular
/// intervals while simultaneously listening for incoming probes.
/// A successful punch means the NAT on at least one side has created
/// a pinhole allowing bidirectional traffic.
pub struct HolePuncher {
    timeout: Duration,
}

impl HolePuncher {
    /// Creates a new hole puncher with the default 5-second timeout.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Creates a new hole puncher with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Attempts to punch a UDP hole to the remote address.
    ///
    /// Binds a local UDP socket to the specified port and alternates
    /// between sending probe packets and checking for responses.
    /// Both peers must call this simultaneously for it to work.
    ///
    /// # Arguments
    ///
    /// * `local_port` - The local port to bind to (use 0 for any).
    /// * `remote_addr` - The peer's reflexive (public) address.
    /// * `timeout` - How long to keep trying before giving up.
    ///   Pass `None` to use the default timeout.
    ///
    /// # Returns
    ///
    /// On success, returns the socket with the established pinhole
    /// and the remote address that responded.
    pub async fn punch(
        &self,
        local_port: u16,
        remote_addr: SocketAddr,
        timeout: Option<Duration>,
    ) -> Result<HolepunchResult, HolepunchError> {
        let timeout = timeout.unwrap_or(self.timeout);
        let local_addr = SocketAddr::from(([0, 0, 0, 0], local_port));

        // Run the blocking hole punch in a spawn_blocking context
        // since UDP socket operations are synchronous.
        let result = tokio::task::spawn_blocking(move || {
            punch_blocking(local_addr, remote_addr, timeout)
        })
        .await
        .map_err(|e| {
            HolepunchError::SocketError(std::io::Error::other(
                format!("punch task failed: {e}"),
            ))
        })??;

        Ok(result)
    }
}

impl Default for HolePuncher {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking implementation of the hole punch loop.
///
/// Alternates between sending probe packets and reading responses
/// with short non-blocking reads. Continues until a valid response
/// arrives or the timeout expires.
fn punch_blocking(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    timeout: Duration,
) -> Result<HolepunchResult, HolepunchError> {
    let socket = UdpSocket::bind(local_addr)?;

    // Use a short read timeout so we can interleave sends and receives
    socket.set_read_timeout(Some(PUNCH_INTERVAL))?;
    socket.set_nonblocking(false)?;

    let start = Instant::now();
    let mut send_count: u64 = 0;
    let mut recv_buf = [0u8; 256];

    tracing::debug!(
        "hole punch: local={}, remote={}, timeout={:?}",
        socket.local_addr()?,
        remote_addr,
        timeout
    );

    while start.elapsed() < timeout {
        // Send a probe packet
        let probe = build_probe(send_count);
        match socket.send_to(&probe, remote_addr) {
            Ok(_) => {
                send_count += 1;
                if send_count % 10 == 1 {
                    tracing::trace!(
                        "hole punch: sent {} probes to {}",
                        send_count,
                        remote_addr
                    );
                }
            }
            Err(e) => {
                tracing::trace!("hole punch send error (may be transient): {e}");
            }
        }

        // Try to receive a response
        match socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                if is_valid_probe(&recv_buf[..len]) {
                    let elapsed = start.elapsed();
                    tracing::info!(
                        "hole punch succeeded: received probe from {} after {:?} ({} probes sent)",
                        from,
                        elapsed,
                        send_count
                    );

                    // Switch to blocking mode for normal use
                    socket.set_read_timeout(None)?;

                    return Ok(HolepunchResult {
                        socket,
                        remote_addr: from,
                        elapsed,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No response yet, continue punching
            }
            Err(e) => {
                tracing::trace!("hole punch recv error: {e}");
            }
        }
    }

    Err(HolepunchError::Timeout(timeout))
}

/// Builds a probe packet with the magic header and a sequence number.
fn build_probe(seq: u64) -> [u8; PROBE_SIZE] {
    let mut buf = [0u8; PROBE_SIZE];
    buf[..4].copy_from_slice(&PUNCH_MAGIC);
    buf[4..12].copy_from_slice(&seq.to_le_bytes());
    buf
}

/// Validates that a received packet is a valid hole punch probe.
fn is_valid_probe(data: &[u8]) -> bool {
    data.len() >= PROBE_SIZE && data[..4] == PUNCH_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_probe() {
        let probe = build_probe(42);
        assert_eq!(&probe[..4], &PUNCH_MAGIC);
        let seq = u64::from_le_bytes(probe[4..12].try_into().unwrap());
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_is_valid_probe() {
        let probe = build_probe(1);
        assert!(is_valid_probe(&probe));

        // Too short
        assert!(!is_valid_probe(&[0x49, 0x47]));

        // Wrong magic
        assert!(!is_valid_probe(&[0x00; PROBE_SIZE]));
    }

    #[test]
    fn test_probe_sequence_numbers() {
        for seq in [0, 1, 100, u64::MAX] {
            let probe = build_probe(seq);
            assert!(is_valid_probe(&probe));
            let decoded = u64::from_le_bytes(probe[4..12].try_into().unwrap());
            assert_eq!(decoded, seq);
        }
    }

    #[test]
    fn test_holepuncher_default_timeout() {
        let puncher = HolePuncher::new();
        assert_eq!(puncher.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn test_holepuncher_custom_timeout() {
        let puncher = HolePuncher::with_timeout(Duration::from_secs(10));
        assert_eq!(puncher.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_constants() {
        assert_eq!(PROBE_SIZE, 12);
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(5));
        assert!(PUNCH_INTERVAL.as_millis() <= 200);
    }

    // Self-punch test: punch from localhost to localhost.
    // Verifies the send/recv loop works when both sides are local.
    #[tokio::test]
    async fn test_self_punch_loopback() {
        // Bind a socket to receive the probes
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        // Run the receiver in a separate thread so it doesn't block tokio
        let receiver_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            // Wait for the first probe
            let (len, from) = receiver.recv_from(&mut buf)?;
            assert!(is_valid_probe(&buf[..len]));

            // Send a probe back so the puncher sees a response
            let response = build_probe(999);
            receiver.send_to(&response, from)?;
            Ok::<SocketAddr, std::io::Error>(from)
        });

        // Give the receiver thread a moment to start listening
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Spawn the puncher targeting the receiver
        let puncher = HolePuncher::with_timeout(Duration::from_secs(3));
        let result = puncher
            .punch(0, receiver_addr, Some(Duration::from_secs(3)))
            .await;

        // Wait for the receiver thread to complete
        let receiver_result = receiver_handle.join().expect("receiver thread panicked");
        assert!(receiver_result.is_ok());

        assert!(result.is_ok());
        let punch_result = result.unwrap();
        assert_eq!(punch_result.remote_addr.ip(), receiver_addr.ip());
    }

    // Test that punch times out when nobody responds.
    #[tokio::test]
    async fn test_punch_timeout() {
        // Use an address that won't respond (TEST-NET-1)
        let remote: SocketAddr = "192.0.2.1:9999".parse().unwrap();
        let puncher = HolePuncher::with_timeout(Duration::from_millis(500));
        let result = puncher.punch(0, remote, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HolepunchError::Timeout(_)));
    }
}
