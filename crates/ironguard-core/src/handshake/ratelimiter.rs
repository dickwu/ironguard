// Per-IP token-bucket rate limiter for handshake DoS protection.
//
// Each IP address is allowed up to PACKETS_BURSTABLE packets immediately and
// then PACKETS_PER_SECOND packets per second on a sustained basis.  Stale
// entries are garbage-collected by a Tokio task that runs every GC_INTERVAL;
// the task shuts down when the table becomes empty or when the RateLimiter is
// dropped.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

// ── token-bucket parameters ──────────────────────────────────────────────────

const PACKETS_PER_SECOND: u64 = 20;
const PACKETS_BURSTABLE: u64 = 5;
/// Cost of a single packet in nanoseconds (= 1 / PACKETS_PER_SECOND seconds)
const PACKET_COST: u64 = 1_000_000_000 / PACKETS_PER_SECOND;
/// Maximum token balance — enough for PACKETS_BURSTABLE packets
const MAX_TOKENS: u64 = PACKET_COST * PACKETS_BURSTABLE;

const GC_INTERVAL: Duration = Duration::from_secs(1);

// ── entry ────────────────────────────────────────────────────────────────────

struct Entry {
    last_time: Instant,
    tokens: u64,
}

// ── inner ────────────────────────────────────────────────────────────────────

struct Inner {
    gc_running: AtomicBool,
    dropped: AtomicBool,
    table: Mutex<HashMap<IpAddr, Entry>>,
}

// ── public API ───────────────────────────────────────────────────────────────

/// Per-IP token-bucket rate limiter.
pub struct RateLimiter(Arc<Inner>);

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            gc_running: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            table: Mutex::new(HashMap::new()),
        }))
    }

    /// Returns `true` if the packet from `addr` is permitted.
    pub fn allow(&self, addr: &IpAddr) -> bool {
        let allowed = {
            let mut table = self.0.table.lock();

            if let Some(entry) = table.get_mut(addr) {
                // Existing entry: replenish tokens based on elapsed time.
                let elapsed_ns = entry.last_time.elapsed().as_nanos() as u64;
                entry.tokens = MAX_TOKENS.min(entry.tokens.saturating_add(elapsed_ns));
                entry.last_time = Instant::now();

                if entry.tokens >= PACKET_COST {
                    entry.tokens -= PACKET_COST;
                    true
                } else {
                    false
                }
            } else {
                // New entry: allow the first packet, start with burst-1 tokens remaining.
                table.insert(
                    *addr,
                    Entry {
                        last_time: Instant::now(),
                        tokens: MAX_TOKENS - PACKET_COST,
                    },
                );
                true
            }
        };

        // Lazily start the GC task.
        if !self.0.gc_running.swap(true, Ordering::Relaxed) {
            let inner = Arc::clone(&self.0);

            // Try to spawn on an existing Tokio runtime; fall back to OS thread
            // if no runtime is available (e.g. in pure unit tests).
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut interval = tokio::time::interval(GC_INTERVAL);
                    loop {
                        interval.tick().await;

                        if inner.dropped.load(Ordering::Relaxed) {
                            return;
                        }

                        let mut table = inner.table.lock();
                        table.retain(|_, e| e.last_time.elapsed() <= GC_INTERVAL);

                        if table.is_empty() {
                            inner.gc_running.store(false, Ordering::Relaxed);
                            return;
                        }
                    }
                });
            } else {
                // Fallback for contexts without a Tokio runtime
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(GC_INTERVAL);

                        if inner.dropped.load(Ordering::Relaxed) {
                            return;
                        }

                        let mut table = inner.table.lock();
                        table.retain(|_, e| e.last_time.elapsed() <= GC_INTERVAL);

                        if table.is_empty() {
                            inner.gc_running.store(false, Ordering::Relaxed);
                            return;
                        }
                    }
                });
            }
        }

        allowed
    }
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Relaxed);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_initial_burst() {
        let rl = RateLimiter::new();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        for i in 0..PACKETS_BURSTABLE {
            assert!(rl.allow(&addr), "burst packet {i} should be allowed");
        }
    }

    #[test]
    fn test_burst_exhausted() {
        let rl = RateLimiter::new();
        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..PACKETS_BURSTABLE {
            rl.allow(&addr);
        }
        assert!(!rl.allow(&addr), "packet after burst should be denied");
    }

    #[test]
    fn test_different_ips_independent() {
        let rl = RateLimiter::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..25 {
            rl.allow(&a);
        }
        assert!(rl.allow(&b), "different IP should not be rate limited");
    }

    #[test]
    fn test_tokens_refill_over_time() {
        let rl = RateLimiter::new();
        let addr: IpAddr = "10.0.0.3".parse().unwrap();
        // exhaust burst
        for _ in 0..PACKETS_BURSTABLE {
            rl.allow(&addr);
        }
        assert!(!rl.allow(&addr));

        // wait for one packet's worth of tokens to refill
        std::thread::sleep(Duration::from_nanos(PACKET_COST));
        assert!(rl.allow(&addr), "should be allowed after token refill");
    }

    #[test]
    fn test_ipv6_independent() {
        let rl = RateLimiter::new();
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        for _ in 0..25 {
            rl.allow(&v4);
        }
        assert!(rl.allow(&v6));
    }
}
