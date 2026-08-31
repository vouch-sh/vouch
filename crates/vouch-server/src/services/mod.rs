// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Service layer for business logic.
//!
//! This module contains business logic services that are called by HTTP handlers.
//! Services encapsulate domain logic and RFC-compliant protocol implementations,
//! while handlers focus on HTTP concerns (extraction, response formatting).
//!
//! # Architecture
//!
//! ```text
//! HTTP Request
//!     │
//!     ▼
//! ┌─────────────────┐
//! │    Handler      │  ← Extract HTTP-specific data (headers, cookies, form)
//! │  (thin layer)   │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Service      │  ← Business logic, RFC compliance, validation
//! │ (domain logic)  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   Database      │  ← Persistence operations
//! │   (db module)   │
//! └─────────────────┘
//! ```
//!
//! # Module Organization
//!
//! ## Protocols (standards we implement as a provider)
//!
//! - [`oidc`] - OpenID Connect provider (RFC 6749, 7636, 8628, 8693, 9449)
//!
//! ## Integrations (external systems we connect to)
//!
//! - [`integrations::github`] - GitHub App, OAuth, webhooks
//!
//! # Error Handling
//!
//! Services return [`ServiceError`] which can be converted to protocol-appropriate
//! responses (OAuth, SCIM, or standard HTTP errors).

pub(crate) mod auth;
pub(crate) mod idp;
pub(crate) mod integrations;
pub(crate) mod keys;
pub mod oidc;
pub(crate) mod policy;

// Protocol modules will be added here as they are implemented:
// pub mod scim;

/// A time window for judging whether a timestamp is recent enough to accept.
///
/// A timestamp is accepted when its age (`now - issued_at`, in seconds) falls
/// within `[-clock_skew_secs, max_age_secs]`. The two ends are independent:
///
/// * `max_age_secs` is the validity *lifetime* — how long after `issued_at` the
///   timestamp stays acceptable.
/// * `clock_skew_secs` is the tolerance for a client clock running *ahead* of
///   ours; a timestamp up to this far in the future is still accepted. Callers
///   for which a future timestamp is impossible use [`RecencyWindow::no_skew`],
///   so a future-dated value fails closed (issue #1144).
///
/// The bound is checked with saturating arithmetic, so an impossible timestamp
/// (age below `-clock_skew_secs`, e.g. from a regressed server clock) is
/// rejected rather than read as age-0 fresh.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecencyWindow {
    max_age_secs: i64,
    clock_skew_secs: i64,
}

impl RecencyWindow {
    /// A window that tolerates no clock skew: a timestamp dated after `now` is
    /// rejected. For gates where a future-dated event is impossible (the
    /// key-deletion step-up).
    pub(crate) fn no_skew(max_age_secs: i64) -> Self {
        Self {
            max_age_secs,
            clock_skew_secs: 0,
        }
    }

    /// A window that accepts timestamps up to `clock_skew_secs` in the future,
    /// forgiving a client clock ahead of ours (DPoP proofs allow this per
    /// RFC 9449).
    pub(crate) fn with_skew(max_age_secs: i64, clock_skew_secs: i64) -> Self {
        Self {
            max_age_secs,
            clock_skew_secs,
        }
    }

    /// Whether `issued_at` (Unix seconds) is within the window relative to the
    /// current wall clock.
    pub(crate) fn accepts(&self, issued_at: i64) -> bool {
        self.accepts_at(jiff::Timestamp::now().as_second(), issued_at)
    }

    /// Whether `issued_at` is within the window relative to an explicit `now` —
    /// for callers that have already stamped the time once (the DPoP validation
    /// snapshots it at the request entry point) or for deterministic tests.
    pub(crate) fn accepts_at(&self, now: i64, issued_at: i64) -> bool {
        let age = now.saturating_sub(issued_at);
        // `age >= -clock_skew_secs`, written without negating so
        // `arithmetic_side_effects` is satisfied.
        age.saturating_add(self.clock_skew_secs) >= 0 && age <= self.max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::RecencyWindow;

    const MAX_AGE: i64 = 60;
    const NOW: i64 = 1_000_000;

    #[test]
    fn accepts_recent_and_current() {
        assert!(
            RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW),
            "age 0"
        );
        assert!(RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW - 30));
    }

    #[test]
    fn max_age_boundary_is_inclusive() {
        assert!(RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW - 60));
        assert!(!RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW - 61));
    }

    // #1144: with no skew tolerated, a future-dated timestamp yields a negative
    // age and must fail closed rather than read as age-0 fresh.
    #[test]
    fn no_skew_rejects_any_future_timestamp() {
        assert!(!RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW + 1));
        assert!(!RecencyWindow::no_skew(MAX_AGE).accepts_at(NOW, NOW + 3600));
    }

    #[test]
    fn skew_is_tolerated_up_to_its_bound() {
        // Mirrors the DPoP 60s clock-skew allowance (RFC 9449).
        assert!(RecencyWindow::with_skew(MAX_AGE, 60).accepts_at(NOW, NOW + 60));
        assert!(!RecencyWindow::with_skew(MAX_AGE, 60).accepts_at(NOW, NOW + 61));
    }

    #[test]
    fn saturating_arithmetic_does_not_overflow_at_bounds() {
        assert!(!RecencyWindow::no_skew(MAX_AGE).accepts_at(i64::MAX, i64::MIN));
        assert!(!RecencyWindow::no_skew(MAX_AGE).accepts_at(i64::MIN, i64::MAX));
    }
}
