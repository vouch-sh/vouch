// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Background cleanup tasks for expired data.
//!
//! This module handles periodic cleanup of:
//! - Expired sessions
//! - Expired device authorization requests
//! - Expired OIDC states
//! - Old authentication events
//! - Old OAuth usage events
//! - Old GitHub credential events
//! - Old SCIM audit logs
//! - Old token exchange records
//! - DPoP nonces and JTI cache

use crate::db;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;
use aws_lc_rs::rand as aws_rand;
use jiff::{Span, Timestamp};
use tokio::task::JoinHandle;

/// Compute a retention cutoff timestamp by subtracting days from now.
///
/// `jiff::Timestamp` only supports time-based units, so we convert days to hours.
fn retention_cutoff(now: Timestamp, days: i64) -> Option<Timestamp> {
    let hours = days.checked_mul(24)?;
    now.checked_sub(Span::new().hours(hours)).ok()
}

/// Log cleanup results: info on deletions, warn on errors, silent on zero.
macro_rules! cleanup_and_log {
    ($op:expr, $desc:expr) => {
        match $op.await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} {}", $desc);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up {}: {e}", $desc);
            }
        }
    };
}

/// Generate a random jitter duration up to `max_jitter_secs` seconds.
///
/// Returns `Duration::ZERO` if `max_jitter_secs` is 0 or the RNG fails.
fn random_jitter(max_jitter_secs: u64) -> std::time::Duration {
    if max_jitter_secs == 0 {
        return std::time::Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    if aws_rand::fill(&mut buf).is_ok() {
        // checked_rem returns None only if max_jitter_secs is 0; guarded above.
        let value = u64::from_le_bytes(buf)
            .checked_rem(max_jitter_secs)
            .unwrap_or(0);
        std::time::Duration::from_secs(value)
    } else {
        std::time::Duration::ZERO
    }
}

/// Start the background cleanup task.
///
/// Returns a handle to the spawned task for graceful shutdown.
///
/// Each iteration sleeps for the base interval plus a random jitter of up to
/// 20% of the interval. This staggers cleanup across multiple server instances
/// to avoid thundering-herd database pressure.
pub fn start_cleanup_task(
    store: DocumentStore,
    audit: AuditStore,
    interval_minutes: u64,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let base_secs = interval_minutes.saturating_mul(60);
        // Jitter of up to 20% of the base interval
        // 5 is non-zero; unwrap_or arm is unreachable.
        let max_jitter_secs = base_secs.checked_div(5).unwrap_or(0);

        // Initial delay with jitter so instances started simultaneously don't
        // all fire their first cleanup at the same time.
        let initial_jitter = random_jitter(max_jitter_secs);
        let initial_delay =
            std::time::Duration::from_secs(base_secs).saturating_add(initial_jitter);
        tracing::debug!(
            "First cleanup in {}s (base {}s + jitter {}s)",
            initial_delay.as_secs(),
            base_secs,
            initial_jitter.as_secs(),
        );
        tokio::time::sleep(initial_delay).await;

        loop {
            tracing::debug!("Running background cleanup tasks");

            // Run all cleanup tasks
            run_cleanup(
                &store,
                &audit,
                auth_events_retention_days,
                oauth_events_retention_days,
            )
            .await;

            // Sleep with jitter before the next run
            let jitter = random_jitter(max_jitter_secs);
            let sleep_duration = std::time::Duration::from_secs(base_secs).saturating_add(jitter);
            tracing::debug!(
                "Next cleanup in {}s (base {}s + jitter {}s)",
                sleep_duration.as_secs(),
                base_secs,
                jitter.as_secs(),
            );
            tokio::time::sleep(sleep_duration).await;
        }
    })
}

/// Run all cleanup tasks once.
pub async fn run_cleanup(
    store: &DocumentStore,
    audit: &AuditStore,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) {
    let now = Timestamp::now();
    let now_str = now.to_string();

    // Clean up expired data (DocumentStore)
    cleanup_and_log!(
        db::delete_expired_sessions(store, &now_str),
        "expired sessions"
    );
    cleanup_and_log!(
        db::delete_expired_device_auth_requests(store, &now_str),
        "expired device auth requests"
    );
    cleanup_and_log!(
        db::delete_expired_oidc_states(store, &now_str),
        "expired OIDC states"
    );
    cleanup_and_log!(
        db::delete_expired_pending_oauth_authorizations(store, &now_str),
        "expired pending OAuth authorizations"
    );
    cleanup_and_log!(
        db::delete_expired_pushed_authorization_requests(store, &now_str),
        "expired pushed authorization requests"
    );
    cleanup_and_log!(
        db::delete_expired_authorization_codes(store),
        "expired authorization codes"
    );
    cleanup_and_log!(
        db::delete_expired_challenge_states(store),
        "expired FIDO2 challenge states"
    );
    cleanup_and_log!(
        db::delete_expired_enrollment_sessions(store),
        "expired enrollment sessions"
    );

    // Clean up old audit events with retention cutoffs (AuditStore)
    if let Some(cutoff) = retention_cutoff(now, auth_events_retention_days) {
        cleanup_and_log!(db::delete_old_auth_events(audit, cutoff), "old auth events");
    }

    if let Some(cutoff) = retention_cutoff(now, oauth_events_retention_days) {
        cleanup_and_log!(
            db::delete_old_oauth_usage_events(audit, cutoff),
            "old OAuth usage events"
        );
    }

    if let Some(cutoff) = retention_cutoff(now, oauth_events_retention_days) {
        cleanup_and_log!(
            db::delete_old_github_credential_events(audit, cutoff),
            "old GitHub credential events"
        );
    }

    if let Some(cutoff) = retention_cutoff(now, auth_events_retention_days) {
        cleanup_and_log!(
            db::delete_old_scim_audit_logs(audit, cutoff),
            "old SCIM audit logs"
        );
    }

    // Clean up old token exchanges (DocumentStore)
    cleanup_and_log!(
        db::delete_old_token_exchanges(store),
        "old token exchange records"
    );

    // Clean up expired JWT assertion JTIs (RFC 7523)
    cleanup_and_log!(
        db::delete_expired_jwt_assertion_jtis(store),
        "expired JWT assertion JTIs"
    );

    // Clean up expired DPoP nonces and JTIs (RFC 9449)
    cleanup_and_log!(
        db::delete_expired_dpop_nonces(store, &now_str),
        "expired DPoP nonces"
    );
    cleanup_and_log!(
        db::delete_expired_dpop_jtis(store, &now_str),
        "expired DPoP JTIs"
    );

    // Clean up expired SSH certificate revocations
    cleanup_and_log!(
        db::delete_expired_ssh_revocations(store),
        "expired SSH certificate revocations"
    );

    // Clean up expired SSH issued certificate records
    cleanup_and_log!(
        db::delete_expired_ssh_issued_certs(store),
        "expired SSH issued certificate records"
    );

    // Clean up expired JWKS cache entries (standalone cache docs)
    cleanup_and_log!(db::delete_expired_jwks_caches(store), "expired JWKS caches");

    tracing::debug!("Background cleanup tasks complete");
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_cutoff_30_days() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 30).expect("30 days should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs();
        let expected_secs: i64 = 30 * 24 * 3600;
        assert!(
            (expected_secs - 5..=expected_secs + 5).contains(&diff_secs),
            "30-day cutoff should be ~{expected_secs}s ago, got {diff_secs}s"
        );
    }

    #[test]
    fn test_retention_cutoff_one_day() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 1).expect("1 day should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs();
        let expected_secs: i64 = 24 * 3600;
        assert!(
            (expected_secs - 5..=expected_secs + 5).contains(&diff_secs),
            "1-day cutoff should be ~{expected_secs}s ago, got {diff_secs}s"
        );
    }

    #[test]
    fn test_retention_cutoff_is_in_the_past() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 90).expect("90 days should not overflow");
        assert!(cutoff < now, "cutoff must be before now");
    }

    #[test]
    fn test_retention_cutoff_zero_days_returns_now() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 0).expect("0 days should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs().abs();
        assert!(diff_secs <= 1, "0-day cutoff should be ~now");
    }
}
