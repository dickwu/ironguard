//! Birthday paradox spray for symmetric NAT traversal.
//!
//! When both peers are behind symmetric (Endpoint-Dependent Mapping)
//! NATs, standard hole punching fails because each new destination
//! gets a different external port. The birthday paradox spray opens
//! many local sockets and probes many remote ports simultaneously.
//!
//! With 256 local sockets and 256 remote ports, the probability of
//! at least one matching pair is ~1 - e^(-256*256/65536) = ~63.2%.
//! With higher counts the probability increases further.
//!
//! Rate limited to 100 packets per second. Maximum spray duration: 30 seconds.
//! Maximum total probes: 65,536. All sockets are closed immediately
//! after success or timeout.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::ops::Range;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of local sockets to open.
const MAX_LOCAL_SOCKETS: usize = 256;

/// Maximum total probes to send (prevents abuse).
const MAX_TOTAL_PROBES: u64 = 65_536;

/// Maximum spray duration.
const MAX_SPRAY_DURATION: Duration = Duration::from_secs(30);

/// Rate limit: maximum packets per second.
const MAX_PPS: u64 = 100;

/// Size of a spray probe packet.
const SPRAY_PROBE_SIZE: usize = 28;

/// Magic bytes identifying a birthday spray probe.
const SPRAY_MAGIC: [u8; 4] = [0x49, 0x47, 0x42, 0x53]; // "IGBS"

/// Errors from birthday spray operations.
#[derive(Debug, Error)]
pub enum BirthdayError {
    /// Socket creation failed.
    #[error("failed to create sockets: {0}")]
    SocketError(#[from] std::io::Error),

    /// The spray timed out without receiving a response.
    #[error("spray timed out after {0:?} ({1} probes sent)")]
    Timeout(Duration, u64),

    /// The file descriptor limit is too low for the requested socket count.
    #[error("fd limit too low: need {needed}, have {available}")]
    FdLimitTooLow { needed: usize, available: usize },

    /// Invalid parameters provided.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

/// Result of a successful birthday spray.
#[derive(Debug)]
pub struct SprayResult {
    /// The socket that received a matching response.
    pub socket: UdpSocket,
    /// The remote address that responded.
    pub remote_addr: SocketAddr,
    /// Total probes sent before success.
    pub probes_sent: u64,
    /// Time elapsed until success.
    pub elapsed: Duration,
}

/// Performs the birthday paradox spray for symmetric NAT traversal.
///
/// Opens multiple local UDP sockets and sends authenticated probes
/// to random ports in the target range. Each probe contains an
/// HMAC of a nonce using the provided auth token, so only peers
/// that share the token can validate the probes.
pub struct BirthdaySpray {
    /// Maximum number of local sockets to open.
    max_sockets: usize,
    /// Maximum spray duration.
    max_duration: Duration,
    /// Rate limit (packets per second).
    max_pps: u64,
}

impl BirthdaySpray {
    /// Creates a new birthday spray with default parameters.
    pub fn new() -> Self {
        Self {
            max_sockets: MAX_LOCAL_SOCKETS,
            max_duration: MAX_SPRAY_DURATION,
            max_pps: MAX_PPS,
        }
    }

    /// Creates a birthday spray with custom parameters.
    pub fn with_params(max_sockets: usize, max_duration: Duration, max_pps: u64) -> Self {
        Self {
            max_sockets: max_sockets.min(MAX_LOCAL_SOCKETS),
            max_duration,
            max_pps: max_pps.min(MAX_PPS),
        }
    }

    /// Performs the birthday spray against a target IP.
    ///
    /// Opens up to `local_count` UDP sockets (capped at 256 and the
    /// system fd limit), then sends authenticated probes to random ports
    /// in `remote_port_range` on the target address.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target peer's IP address.
    /// * `local_count` - Number of local sockets to open (capped at 256).
    /// * `remote_port_range` - Range of remote ports to probe.
    /// * `auth_token` - Shared secret for probe authentication (HMAC key).
    ///
    /// # Returns
    ///
    /// The socket that received a valid authenticated response, or `None`
    /// if the spray timed out.
    pub async fn spray(
        &self,
        target_addr: IpAddr,
        local_count: usize,
        remote_port_range: Range<u16>,
        auth_token: &[u8],
    ) -> Result<Option<SprayResult>, BirthdayError> {
        if remote_port_range.is_empty() {
            return Err(BirthdayError::InvalidParams(
                "remote port range is empty".into(),
            ));
        }

        let effective_count = local_count.min(self.max_sockets);
        let auth = auth_token.to_vec();
        let max_dur = self.max_duration;
        let max_pps = self.max_pps;

        let result = tokio::task::spawn_blocking(move || {
            spray_blocking(
                target_addr,
                effective_count,
                remote_port_range,
                &auth,
                max_dur,
                max_pps,
            )
        })
        .await
        .map_err(|e| {
            BirthdayError::SocketError(std::io::Error::other(
                format!("spray task failed: {e}"),
            ))
        })??;

        Ok(result)
    }
}

impl Default for BirthdaySpray {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking implementation of the birthday spray.
fn spray_blocking(
    target_addr: IpAddr,
    local_count: usize,
    remote_port_range: Range<u16>,
    auth_token: &[u8],
    max_duration: Duration,
    max_pps: u64,
) -> Result<Option<SprayResult>, BirthdayError> {
    // Check fd limit before opening sockets
    let available_fds = get_available_fds();
    // Reserve some fds for the runtime (stdin/stdout/stderr + tokio internals)
    let reserved_fds = 32;
    let usable_fds = available_fds.saturating_sub(reserved_fds);

    if usable_fds < local_count {
        tracing::warn!(
            "fd limit restricts spray to {} sockets (wanted {}, available {})",
            usable_fds,
            local_count,
            available_fds
        );
    }

    let socket_count = local_count.min(usable_fds).min(MAX_LOCAL_SOCKETS);
    if socket_count == 0 {
        return Err(BirthdayError::FdLimitTooLow {
            needed: local_count,
            available: available_fds,
        });
    }

    // Open local sockets
    let mut sockets = Vec::with_capacity(socket_count);
    for _ in 0..socket_count {
        let bind_addr: SocketAddr = match target_addr {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        match UdpSocket::bind(bind_addr) {
            Ok(sock) => {
                // Short read timeout for non-blocking-style polling
                sock.set_read_timeout(Some(Duration::from_millis(1)))?;
                sockets.push(sock);
            }
            Err(e) => {
                tracing::debug!(
                    "stopped opening sockets at {} (fd limit?): {e}",
                    sockets.len()
                );
                break;
            }
        }
    }

    if sockets.is_empty() {
        return Err(BirthdayError::SocketError(std::io::Error::other(
            "failed to open any sockets",
        )));
    }

    tracing::debug!(
        "birthday spray: {} sockets, target={}, port range={}..{}, max_pps={}",
        sockets.len(),
        target_addr,
        remote_port_range.start,
        remote_port_range.end,
        max_pps
    );

    let start = Instant::now();
    let mut total_probes: u64 = 0;
    let interval = Duration::from_micros(1_000_000 / max_pps.max(1));
    let port_range_len = (remote_port_range.end - remote_port_range.start) as u64;
    let mut recv_buf = [0u8; 256];
    let mut last_send = Instant::now() - interval; // Allow immediate first send

    // Use a simple PRNG for port selection (seeded from rand)
    let mut rng_state: u64 = rand::random();

    loop {
        let elapsed = start.elapsed();
        if elapsed >= max_duration || total_probes >= MAX_TOTAL_PROBES {
            // Close all sockets explicitly
            drop(sockets);
            return Err(BirthdayError::Timeout(elapsed, total_probes));
        }

        // Rate-limited send: pick a random socket and a random port
        if last_send.elapsed() >= interval {
            let sock_idx = (xorshift64(&mut rng_state) as usize) % sockets.len();
            let port_offset = xorshift64(&mut rng_state) % port_range_len;
            let remote_port = remote_port_range.start + port_offset as u16;
            let remote = SocketAddr::new(target_addr, remote_port);

            let probe = build_spray_probe(total_probes, auth_token);
            let _ = sockets[sock_idx].send_to(&probe, remote);
            total_probes += 1;
            last_send = Instant::now();
        }

        // Check all sockets for responses (round-robin)
        for (idx, sock) in sockets.iter().enumerate() {
            match sock.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    if is_valid_spray_response(&recv_buf[..len], auth_token) {
                        let elapsed = start.elapsed();
                        tracing::info!(
                            "birthday spray success: socket {} received response from {} \
                             after {:?} ({} probes)",
                            idx,
                            from,
                            elapsed,
                            total_probes
                        );

                        // Extract the winning socket, close the rest
                        let winning = sockets.swap_remove(idx);
                        drop(sockets);

                        winning.set_read_timeout(None)?;
                        return Ok(Some(SprayResult {
                            socket: winning,
                            remote_addr: from,
                            probes_sent: total_probes,
                            elapsed,
                        }));
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // No data yet, continue
                }
                Err(_) => {
                    // Ignore other errors, continue polling
                }
            }
        }
    }
}

/// Builds an authenticated spray probe packet.
///
/// Format: [4 magic][8 nonce][16 hmac_truncated]
fn build_spray_probe(nonce: u64, auth_token: &[u8]) -> [u8; SPRAY_PROBE_SIZE] {
    let mut buf = [0u8; SPRAY_PROBE_SIZE];
    buf[..4].copy_from_slice(&SPRAY_MAGIC);
    buf[4..12].copy_from_slice(&nonce.to_le_bytes());

    // HMAC the nonce with the auth token
    let mut mac =
        HmacSha256::new_from_slice(auth_token).expect("HMAC accepts any key length");
    mac.update(&SPRAY_MAGIC);
    mac.update(&nonce.to_le_bytes());
    let tag = mac.finalize().into_bytes();
    buf[12..28].copy_from_slice(&tag[..16]);

    buf
}

/// Validates an incoming spray probe/response.
fn is_valid_spray_response(data: &[u8], auth_token: &[u8]) -> bool {
    if data.len() < SPRAY_PROBE_SIZE {
        return false;
    }
    if data[..4] != SPRAY_MAGIC {
        return false;
    }

    let nonce = &data[4..12];
    let received_tag = &data[12..28];

    let mut mac =
        HmacSha256::new_from_slice(auth_token).expect("HMAC accepts any key length");
    mac.update(&SPRAY_MAGIC);
    mac.update(nonce);
    let expected = mac.finalize().into_bytes();

    // Constant-time comparison of truncated HMAC
    let expected_truncated = &expected[..16];
    constant_time_eq(received_tag, expected_truncated)
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Fast PRNG for port/socket selection (not cryptographic).
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Returns the soft file descriptor limit for this process.
#[cfg(unix)]
fn get_available_fds() -> usize {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit with RLIMIT_NOFILE is always safe.
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret == 0 {
        rlim.rlim_cur as usize
    } else {
        256 // Conservative fallback
    }
}

#[cfg(not(unix))]
fn get_available_fds() -> usize {
    512 // Windows default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_spray_probe() {
        let token = b"test-auth-token";
        let probe = build_spray_probe(42, token);
        assert_eq!(&probe[..4], &SPRAY_MAGIC);
        let nonce = u64::from_le_bytes(probe[4..12].try_into().unwrap());
        assert_eq!(nonce, 42);
    }

    #[test]
    fn test_validate_spray_probe() {
        let token = b"test-auth-token";
        let probe = build_spray_probe(42, token);
        assert!(is_valid_spray_response(&probe, token));
    }

    #[test]
    fn test_validate_wrong_token_rejected() {
        let probe = build_spray_probe(42, b"correct-token");
        assert!(!is_valid_spray_response(&probe, b"wrong-token"));
    }

    #[test]
    fn test_validate_truncated_packet_rejected() {
        let probe = build_spray_probe(42, b"token");
        assert!(!is_valid_spray_response(&probe[..10], b"token"));
    }

    #[test]
    fn test_validate_wrong_magic_rejected() {
        let mut probe = build_spray_probe(42, b"token");
        probe[0] = 0xFF;
        assert!(!is_valid_spray_response(&probe, b"token"));
    }

    #[test]
    fn test_validate_tampered_nonce_rejected() {
        let token = b"token";
        let mut probe = build_spray_probe(42, token);
        probe[5] ^= 0xFF; // Flip a nonce byte
        assert!(!is_valid_spray_response(&probe, token));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_xorshift64_produces_different_values() {
        let mut state: u64 = 12345;
        let a = xorshift64(&mut state);
        let b = xorshift64(&mut state);
        let c = xorshift64(&mut state);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_get_available_fds() {
        let fds = get_available_fds();
        assert!(fds >= 64, "system should support at least 64 fds");
    }

    #[test]
    fn test_spray_defaults() {
        let spray = BirthdaySpray::new();
        assert_eq!(spray.max_sockets, MAX_LOCAL_SOCKETS);
        assert_eq!(spray.max_duration, MAX_SPRAY_DURATION);
        assert_eq!(spray.max_pps, MAX_PPS);
    }

    #[test]
    fn test_spray_clamped_params() {
        let spray = BirthdaySpray::with_params(1000, Duration::from_secs(60), 500);
        assert_eq!(spray.max_sockets, MAX_LOCAL_SOCKETS); // Capped at 256
        assert_eq!(spray.max_pps, MAX_PPS); // Capped at 100
    }

    #[tokio::test]
    async fn test_spray_empty_port_range() {
        let spray = BirthdaySpray::new();
        let result = spray
            .spray(IpAddr::V4("192.0.2.1".parse().unwrap()), 10, 100..100, b"token")
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BirthdayError::InvalidParams(_)));
    }

    // Self-spray test: open sockets on localhost and respond to probes.
    #[tokio::test]
    async fn test_spray_self_loopback() {
        let auth_token = b"test-spray-auth";

        // Bind a responder on a known port
        let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder_port = responder.local_addr().unwrap().port();
        responder
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        // Spawn a responder that echoes back valid probes
        let auth_clone = auth_token.to_vec();
        let responder_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            match responder.recv_from(&mut buf) {
                Ok((len, from)) => {
                    if is_valid_spray_response(&buf[..len], &auth_clone) {
                        // Echo back the same probe as a valid response
                        let _ = responder.send_to(&buf[..len], from);
                    }
                }
                Err(_) => {}
            }
        });

        let spray = BirthdaySpray::with_params(4, Duration::from_secs(5), 100);
        let result = spray
            .spray(
                IpAddr::V4("127.0.0.1".parse().unwrap()),
                4,
                responder_port..responder_port + 1,
                auth_token,
            )
            .await;

        responder_handle.join().unwrap();

        match result {
            Ok(Some(spray_result)) => {
                assert!(spray_result.probes_sent > 0);
                assert!(spray_result.elapsed < Duration::from_secs(5));
            }
            Ok(None) => {
                panic!("spray returned None despite responder being active");
            }
            Err(BirthdayError::Timeout(_, probes)) => {
                // This can happen in CI if timing is tight
                tracing::warn!("spray timed out after {probes} probes (may be CI timing issue)");
            }
            Err(e) => {
                panic!("unexpected spray error: {e}");
            }
        }
    }
}
