use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::constants::*;

/// Per-peer timer state.
///
/// Instead of using a timer wheel (hjul), each timer is represented as an
/// `Option<Instant>` deadline.  A dedicated device-level thread calls
/// `check_timers()` every `TIMERS_TICK` to fire any expired timers.
pub struct Timers {
    // configuration (only updated during config, not hot-path)
    enabled: bool,
    keepalive_interval: u64,

    // handshake retry state
    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
    need_another_keepalive: AtomicBool,

    // last time data was sent or received (for adaptive tick)
    last_data: Mutex<Option<Instant>>,

    // timer deadlines
    retransmit_handshake: Mutex<Option<Instant>>,
    send_keepalive: Mutex<Option<Instant>>,
    send_persistent_keepalive: Mutex<Option<Instant>>,
    zero_key_material: Mutex<Option<Instant>>,
    new_handshake: Mutex<Option<Instant>>,
}

/// Actions that the timer tick loop should take after checking timers.
/// Each field is set to true when the corresponding timer fires.
#[derive(Debug, Default)]
pub struct TimerActions {
    pub retransmit_handshake: bool,
    pub send_keepalive: bool,
    pub send_persistent_keepalive: bool,
    pub zero_key_material: bool,
    pub new_handshake: bool,
}

/// Interval between timer ticks when the peer is active (100ms).
pub const TIMERS_TICK: Duration = Duration::from_millis(100);

/// Interval between timer ticks when the peer is idle (1s).
pub const TIMERS_TICK_IDLE: Duration = Duration::from_secs(1);

/// Duration after which a peer is considered idle (no data in 10 seconds).
pub const TIMERS_IDLE_THRESHOLD: Duration = Duration::from_secs(10);

impl Timers {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            keepalive_interval: 0,
            handshake_attempts: AtomicUsize::new(0),
            sent_lastminute_handshake: AtomicBool::new(false),
            need_another_keepalive: AtomicBool::new(false),
            last_data: Mutex::new(None),
            retransmit_handshake: Mutex::new(None),
            send_keepalive: Mutex::new(None),
            send_persistent_keepalive: Mutex::new(None),
            zero_key_material: Mutex::new(None),
            new_handshake: Mutex::new(None),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn keepalive_interval(&self) -> u64 {
        self.keepalive_interval
    }

    pub fn set_keepalive_interval(&mut self, secs: u64) {
        self.keepalive_interval = secs;
        // stop the old timer
        *self.send_persistent_keepalive.lock() = None;
        // if enabled and interval > 0, fire immediately
        if secs > 0 && self.enabled {
            *self.send_persistent_keepalive.lock() = Some(Instant::now());
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn need_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }

    pub fn handshake_attempts(&self) -> usize {
        self.handshake_attempts.load(Ordering::SeqCst)
    }

    pub fn sent_lastminute_handshake(&self) -> &AtomicBool {
        &self.sent_lastminute_handshake
    }

    // ── timer scheduling (called by workers on events) ───────────────────

    /// Called after an authenticated data packet is sent.
    pub fn timers_data_sent(&self) {
        if self.enabled {
            *self.last_data.lock() = Some(Instant::now());
            *self.new_handshake.lock() = Some(Instant::now() + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    /// Called after an authenticated data packet is received.
    pub fn timers_data_received(&self) {
        if self.enabled {
            *self.last_data.lock() = Some(Instant::now());
            let mut timer = self.send_keepalive.lock();
            if timer.is_none() {
                *timer = Some(Instant::now() + KEEPALIVE_TIMEOUT);
            } else {
                self.need_another_keepalive.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Called after any authenticated packet is sent (keepalive, data, handshake).
    pub fn timers_any_authenticated_packet_sent(&self) {
        if self.enabled {
            *self.send_keepalive.lock() = None;
        }
    }

    /// Called after any authenticated packet is received.
    pub fn timers_any_authenticated_packet_received(&self) {
        if self.enabled {
            *self.new_handshake.lock() = None;
        }
    }

    /// Called after a handshake initiation is sent.
    pub fn timers_handshake_initiated(&self) {
        if self.enabled {
            *self.send_keepalive.lock() = None;
            *self.retransmit_handshake.lock() = Some(Instant::now() + REKEY_TIMEOUT);
        }
    }

    /// Called after a handshake completes (response received or key confirmed).
    pub fn timers_handshake_complete(&self) {
        if self.enabled {
            *self.retransmit_handshake.lock() = None;
            self.handshake_attempts.store(0, Ordering::SeqCst);
            self.sent_lastminute_handshake
                .store(false, Ordering::SeqCst);
        }
    }

    /// Called after a new session key is derived.
    pub fn timers_session_derived(&self) {
        if self.enabled {
            *self.zero_key_material.lock() = Some(Instant::now() + REJECT_AFTER_TIME * 3);
        }
    }

    /// Called before any authenticated packet traverses (sent or received).
    pub fn timers_any_authenticated_packet_traversal(&self) {
        if self.enabled && self.keepalive_interval > 0 {
            *self.send_persistent_keepalive.lock() =
                Some(Instant::now() + Duration::from_secs(self.keepalive_interval));
        }
    }

    // ── composite methods (called by handshake worker) ───────────────────

    /// Called after sending a handshake initiation.
    pub fn sent_handshake_initiation(&self) {
        self.timers_handshake_initiated();
        // Also schedule retransmit (redundant with initiated but matches legacy)
        if self.enabled {
            *self.retransmit_handshake.lock() = Some(Instant::now() + REKEY_TIMEOUT);
        }
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    /// Called after sending a handshake response.
    pub fn sent_handshake_response(&self) {
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    // ── start / stop ─────────────────────────────────────────────────────

    pub fn stop(&mut self) {
        if !self.enabled {
            return;
        }
        self.enabled = false;
        *self.last_data.lock() = None;
        *self.retransmit_handshake.lock() = None;
        *self.send_keepalive.lock() = None;
        *self.send_persistent_keepalive.lock() = None;
        *self.zero_key_material.lock() = None;
        *self.new_handshake.lock() = None;
        self.handshake_attempts.store(0, Ordering::SeqCst);
        self.sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        self.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub fn start(&mut self) {
        if self.enabled {
            return;
        }
        self.enabled = true;
        if self.keepalive_interval > 0 {
            *self.send_persistent_keepalive.lock() = Some(Instant::now());
        }
    }

    /// Returns true if this peer has been idle (no data) for longer than
    /// `TIMERS_IDLE_THRESHOLD`.  Used by the device-level tick loop to
    /// select a slower tick interval for idle peers.
    pub fn is_idle(&self, now: Instant) -> bool {
        match *self.last_data.lock() {
            Some(last) => now.duration_since(last) > TIMERS_IDLE_THRESHOLD,
            None => true,
        }
    }

    // ── timer tick (called every TIMERS_TICK by the device timer thread) ─

    /// Check all timers against `now` and return which timers have fired.
    /// Also handles retransmit_handshake retry logic internally.
    pub fn check_timers(&self, now: Instant) -> TimerActions {
        if !self.enabled {
            return TimerActions::default();
        }

        let mut actions = TimerActions::default();

        // retransmit_handshake
        {
            let mut timer = self.retransmit_handshake.lock();
            if let Some(deadline) = *timer {
                if now >= deadline {
                    let attempts = self.handshake_attempts.fetch_add(1, Ordering::SeqCst);
                    if attempts > MAX_TIMER_HANDSHAKES {
                        // give up: stop keepalive, schedule zero_key_material
                        *self.send_keepalive.lock() = None;
                        *self.zero_key_material.lock() =
                            Some(Instant::now() + REJECT_AFTER_TIME * 3);
                        *timer = None;
                        // purge staged packets is handled by the caller
                        actions.retransmit_handshake = true;
                    } else {
                        // retry
                        *timer = Some(Instant::now() + REKEY_TIMEOUT);
                        actions.retransmit_handshake = true;
                    }
                }
            }
        }

        // send_keepalive
        {
            let mut timer = self.send_keepalive.lock();
            if let Some(deadline) = *timer {
                if now >= deadline {
                    *timer = None;
                    actions.send_keepalive = true;
                    // if need_another_keepalive, reschedule
                    if self.need_another_keepalive() {
                        *timer = Some(Instant::now() + KEEPALIVE_TIMEOUT);
                    }
                }
            }
        }

        // send_persistent_keepalive
        {
            let mut timer = self.send_persistent_keepalive.lock();
            if let Some(deadline) = *timer {
                if now >= deadline {
                    if self.keepalive_interval > 0 {
                        *self.send_keepalive.lock() = None;
                        actions.send_persistent_keepalive = true;
                        *timer =
                            Some(Instant::now() + Duration::from_secs(self.keepalive_interval));
                    } else {
                        *timer = None;
                    }
                }
            }
        }

        // zero_key_material
        {
            let mut timer = self.zero_key_material.lock();
            if let Some(deadline) = *timer {
                if now >= deadline {
                    *timer = None;
                    actions.zero_key_material = true;
                }
            }
        }

        // new_handshake
        {
            let mut timer = self.new_handshake.lock();
            if let Some(deadline) = *timer {
                if now >= deadline {
                    *timer = None;
                    actions.new_handshake = true;
                }
            }
        }

        actions
    }

    /// Returns true if the retransmit handshake has exceeded max attempts.
    pub fn is_handshake_expired(&self) -> bool {
        self.handshake_attempts.load(Ordering::SeqCst) > MAX_TIMER_HANDSHAKES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_new_disabled() {
        let timers = Timers::new(false);
        assert!(!timers.is_enabled());
        assert_eq!(timers.keepalive_interval(), 0);
    }

    #[test]
    fn test_timer_new_enabled() {
        let timers = Timers::new(true);
        assert!(timers.is_enabled());
    }

    #[test]
    fn test_timers_data_sent_schedules_new_handshake() {
        let timers = Timers::new(true);
        timers.timers_data_sent();

        let deadline = timers.new_handshake.lock().unwrap();
        let expected = Instant::now() + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
        // Allow 100ms tolerance
        assert!((deadline - expected) < Duration::from_millis(100));
    }

    #[test]
    fn test_timers_data_received_schedules_keepalive() {
        let timers = Timers::new(true);
        timers.timers_data_received();

        assert!(timers.send_keepalive.lock().is_some());
    }

    #[test]
    fn test_timers_data_received_sets_need_another_if_already_pending() {
        let timers = Timers::new(true);
        timers.timers_data_received(); // first: schedules
        timers.timers_data_received(); // second: sets need_another

        assert!(timers.need_another_keepalive.load(Ordering::SeqCst));
    }

    #[test]
    fn test_timers_any_authenticated_packet_sent_cancels_keepalive() {
        let timers = Timers::new(true);
        timers.timers_data_received(); // schedule keepalive
        assert!(timers.send_keepalive.lock().is_some());

        timers.timers_any_authenticated_packet_sent();
        assert!(timers.send_keepalive.lock().is_none());
    }

    #[test]
    fn test_timers_any_authenticated_packet_received_cancels_new_handshake() {
        let timers = Timers::new(true);
        timers.timers_data_sent(); // schedule new_handshake
        assert!(timers.new_handshake.lock().is_some());

        timers.timers_any_authenticated_packet_received();
        assert!(timers.new_handshake.lock().is_none());
    }

    #[test]
    fn test_timers_handshake_complete_resets_state() {
        let timers = Timers::new(true);
        timers.timers_handshake_initiated();
        assert!(timers.retransmit_handshake.lock().is_some());

        timers.timers_handshake_complete();
        assert!(timers.retransmit_handshake.lock().is_none());
        assert_eq!(timers.handshake_attempts(), 0);
    }

    #[test]
    fn test_timers_session_derived_schedules_zero_key_material() {
        let timers = Timers::new(true);
        timers.timers_session_derived();

        let deadline = timers.zero_key_material.lock().unwrap();
        let expected = Instant::now() + REJECT_AFTER_TIME * 3;
        assert!((deadline - expected) < Duration::from_millis(100));
    }

    #[test]
    fn test_timers_traversal_with_keepalive_interval() {
        let mut timers = Timers::new(true);
        timers.keepalive_interval = 25;
        timers.timers_any_authenticated_packet_traversal();

        assert!(timers.send_persistent_keepalive.lock().is_some());
    }

    #[test]
    fn test_timers_traversal_without_keepalive_interval() {
        let timers = Timers::new(true);
        // keepalive_interval is 0
        timers.timers_any_authenticated_packet_traversal();

        assert!(timers.send_persistent_keepalive.lock().is_none());
    }

    #[test]
    fn test_check_timers_fires_expired() {
        let timers = Timers::new(true);

        // Schedule new_handshake to fire immediately
        *timers.new_handshake.lock() = Some(Instant::now() - Duration::from_secs(1));

        let actions = timers.check_timers(Instant::now());
        assert!(actions.new_handshake);
        // Timer should be cleared after firing
        assert!(timers.new_handshake.lock().is_none());
    }

    #[test]
    fn test_check_timers_does_not_fire_future() {
        let timers = Timers::new(true);

        *timers.new_handshake.lock() = Some(Instant::now() + Duration::from_secs(60));

        let actions = timers.check_timers(Instant::now());
        assert!(!actions.new_handshake);
        assert!(timers.new_handshake.lock().is_some());
    }

    #[test]
    fn test_check_timers_disabled_noop() {
        let timers = Timers::new(false);
        *timers.new_handshake.lock() = Some(Instant::now() - Duration::from_secs(1));

        let actions = timers.check_timers(Instant::now());
        assert!(!actions.new_handshake);
    }

    #[test]
    fn test_retransmit_handshake_retry_increments_attempts() {
        let timers = Timers::new(true);
        *timers.retransmit_handshake.lock() = Some(Instant::now() - Duration::from_secs(1));

        let actions = timers.check_timers(Instant::now());
        assert!(actions.retransmit_handshake);
        assert_eq!(timers.handshake_attempts(), 1);
        // Should have rescheduled
        assert!(timers.retransmit_handshake.lock().is_some());
    }

    #[test]
    fn test_retransmit_handshake_gives_up_after_max() {
        let timers = Timers::new(true);
        timers
            .handshake_attempts
            .store(MAX_TIMER_HANDSHAKES + 1, Ordering::SeqCst);
        *timers.retransmit_handshake.lock() = Some(Instant::now() - Duration::from_secs(1));

        let actions = timers.check_timers(Instant::now());
        assert!(actions.retransmit_handshake);
        // Should have cleared retransmit timer
        assert!(timers.retransmit_handshake.lock().is_none());
        // Should have scheduled zero_key_material
        assert!(timers.zero_key_material.lock().is_some());
    }

    #[test]
    fn test_stop_clears_all() {
        let mut timers = Timers::new(true);
        timers.timers_data_sent();
        timers.timers_data_received();
        timers.timers_session_derived();

        timers.stop();

        assert!(!timers.is_enabled());
        assert!(timers.retransmit_handshake.lock().is_none());
        assert!(timers.send_keepalive.lock().is_none());
        assert!(timers.send_persistent_keepalive.lock().is_none());
        assert!(timers.zero_key_material.lock().is_none());
        assert!(timers.new_handshake.lock().is_none());
    }

    #[test]
    fn test_start_enables_persistent_keepalive() {
        let mut timers = Timers::new(false);
        timers.keepalive_interval = 25;

        timers.start();

        assert!(timers.is_enabled());
        assert!(timers.send_persistent_keepalive.lock().is_some());
    }

    #[test]
    fn test_sent_handshake_initiation_composite() {
        let mut timers = Timers::new(true);
        timers.keepalive_interval = 25;

        timers.sent_handshake_initiation();

        // retransmit_handshake should be scheduled
        assert!(timers.retransmit_handshake.lock().is_some());
        // send_keepalive should be cancelled
        assert!(timers.send_keepalive.lock().is_none());
        // persistent_keepalive should be rescheduled (traversal)
        assert!(timers.send_persistent_keepalive.lock().is_some());
    }

    #[test]
    fn test_is_idle_with_no_data() {
        let timers = Timers::new(true);
        // No data has ever been sent/received, so peer is idle
        assert!(timers.is_idle(Instant::now()));
    }

    #[test]
    fn test_is_idle_with_recent_data() {
        let timers = Timers::new(true);
        timers.timers_data_sent();
        // Just sent data, so peer should not be idle
        assert!(!timers.is_idle(Instant::now()));
    }

    #[test]
    fn test_is_idle_after_threshold() {
        let timers = Timers::new(true);
        // Simulate data from 11 seconds ago
        *timers.last_data.lock() = Some(Instant::now() - Duration::from_secs(11));
        assert!(timers.is_idle(Instant::now()));
    }

    #[test]
    fn test_stop_clears_last_data() {
        let mut timers = Timers::new(true);
        timers.timers_data_sent();
        assert!(timers.last_data.lock().is_some());

        timers.stop();
        assert!(timers.last_data.lock().is_none());
    }
}
