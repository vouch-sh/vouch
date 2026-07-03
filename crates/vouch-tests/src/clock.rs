// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Clock abstraction for time-based operations.
//!
//! This module provides a trait for abstracting time access, enabling testable
//! time-dependent code without modifying production behavior.

use jiff::Timestamp;

/// Trait for abstracting time access.
///
/// This enables testing time-dependent behavior (session expiration, token validity)
/// by injecting a controllable clock implementation.
pub trait Clock: Send + Sync {
    /// Get the current timestamp.
    fn now(&self) -> Timestamp;
}

/// Test clock that can be set to any time and advanced manually.
///
/// This is useful for testing time-dependent behavior like session expiration.
pub struct TestClock {
    /// Current timestamp in seconds since Unix epoch.
    now: std::sync::atomic::AtomicI64,
    /// Subsecond nanoseconds.
    nanos: std::sync::atomic::AtomicI32,
}

impl TestClock {
    /// Create a new test clock set to the given timestamp.
    #[must_use]
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            now: std::sync::atomic::AtomicI64::new(timestamp.as_second()),
            nanos: std::sync::atomic::AtomicI32::new(timestamp.subsec_nanosecond()),
        }
    }

    /// Create a test clock set to the current system time.
    #[must_use]
    pub fn now_clock() -> Self {
        Self::new(Timestamp::now())
    }

    /// Set the clock to a specific timestamp.
    pub fn set(&self, timestamp: Timestamp) {
        self.now
            .store(timestamp.as_second(), std::sync::atomic::Ordering::SeqCst);
        self.nanos.store(
            timestamp.subsec_nanosecond(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Advance the clock by the given duration.
    ///
    /// # Errors
    ///
    /// Returns an error if the span cannot be converted to a total seconds value.
    pub fn advance(&self, duration: jiff::Span) -> Result<(), jiff::Error> {
        let current = self.now();
        let new_time = current.checked_add(duration)?;
        self.set(new_time);
        Ok(())
    }

    /// Advance the clock by a number of seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting timestamp would overflow.
    pub fn advance_seconds(&self, seconds: i64) -> Result<(), jiff::Error> {
        self.advance(jiff::Span::new().seconds(seconds))
    }

    /// Advance the clock by a number of hours.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting timestamp would overflow.
    pub fn advance_hours(&self, hours: i64) -> Result<(), jiff::Error> {
        self.advance(jiff::Span::new().hours(hours))
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        let secs = self.now.load(std::sync::atomic::Ordering::SeqCst);
        let nanos = self.nanos.load(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: We only store valid timestamps, so this should never fail
        Timestamp::new(secs, nanos).unwrap_or(Timestamp::UNIX_EPOCH)
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::now_clock()
    }
}

impl std::fmt::Debug for TestClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestClock")
            .field("now", &self.now())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_clock_returns_set_time() {
        let fixed_time = Timestamp::new(1_700_000_000, 0).ok();
        let clock = TestClock::new(fixed_time.unwrap_or(Timestamp::UNIX_EPOCH));

        let time = clock.now();
        assert_eq!(time.as_second(), 1_700_000_000);
    }

    #[test]
    fn test_test_clock_advance() {
        let fixed_time = Timestamp::new(1_700_000_000, 0).ok();
        let clock = TestClock::new(fixed_time.unwrap_or(Timestamp::UNIX_EPOCH));

        let result = clock.advance_hours(8);
        assert!(result.is_ok());

        let time = clock.now();
        assert_eq!(time.as_second(), 1_700_000_000 + 8 * 3600);
    }

    #[test]
    fn test_test_clock_set() {
        let clock = TestClock::now_clock();

        let new_time = Timestamp::new(1_800_000_000, 500_000_000).ok();
        clock.set(new_time.unwrap_or(Timestamp::UNIX_EPOCH));

        let time = clock.now();
        assert_eq!(time.as_second(), 1_800_000_000);
        assert_eq!(time.subsec_nanosecond(), 500_000_000);
    }
}
