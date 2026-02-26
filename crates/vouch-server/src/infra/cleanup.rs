// SPDX-License-Identifier: BUSL-1.1
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
use jiff::{Timestamp, ToSpan};
use tokio::task::JoinHandle;

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
        let value = u64::from_le_bytes(buf) % max_jitter_secs;
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
        let base_secs = interval_minutes * 60;
        // Jitter of up to 20% of the base interval
        let max_jitter_secs = base_secs / 5;

        // Initial delay with jitter so instances started simultaneously don't
        // all fire their first cleanup at the same time.
        let initial_jitter = random_jitter(max_jitter_secs);
        let initial_delay = std::time::Duration::from_secs(base_secs) + initial_jitter;
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
            let sleep_duration = std::time::Duration::from_secs(base_secs) + jitter;
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
        db::delete_expired_enrollment_sessions(store),
        "expired enrollment sessions"
    );

    // Clean up old audit events with retention cutoffs (AuditStore)
    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
        cleanup_and_log!(db::delete_old_auth_events(audit, cutoff), "old auth events");
    }

    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        cleanup_and_log!(
            db::delete_old_oauth_usage_events(audit, cutoff),
            "old OAuth usage events"
        );
    }

    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        cleanup_and_log!(
            db::delete_old_github_credential_events(audit, cutoff),
            "old GitHub credential events"
        );
    }

    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
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

    tracing::debug!("Background cleanup tasks complete");
}
