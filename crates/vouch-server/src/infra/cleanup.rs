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

use crate::db::{self, Pool};
use crate::services::oidc::dpop::DpopState;
use jiff::{Timestamp, ToSpan};
use std::sync::Arc;
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

/// Start the background cleanup task.
///
/// Returns a handle to the spawned task for graceful shutdown.
pub fn start_cleanup_task(
    db: Pool,
    dpop_state: Arc<DpopState>,
    interval_minutes: u64,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_minutes * 60));

        // Don't run immediately at startup - wait for first interval
        interval.tick().await;

        loop {
            interval.tick().await;

            tracing::debug!("Running background cleanup tasks");

            // Run all cleanup tasks
            run_cleanup(
                &db,
                &dpop_state,
                auth_events_retention_days,
                oauth_events_retention_days,
            )
            .await;
        }
    })
}

/// Run all cleanup tasks once.
pub async fn run_cleanup(
    db: &Pool,
    dpop_state: &DpopState,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) {
    let now = Timestamp::now();
    let now_str = now.to_string();

    // Clean up expired data
    cleanup_and_log!(
        db::delete_expired_sessions(db, &now_str),
        "expired sessions"
    );
    cleanup_and_log!(
        db::delete_expired_device_auth_requests(db, &now_str),
        "expired device auth requests"
    );
    cleanup_and_log!(
        db::delete_expired_oidc_states(db, &now_str),
        "expired OIDC states"
    );
    cleanup_and_log!(
        db::delete_expired_pending_oauth_authorizations(db, &now_str),
        "expired pending OAuth authorizations"
    );
    cleanup_and_log!(
        db::delete_expired_authorization_codes(db),
        "expired authorization codes"
    );
    cleanup_and_log!(
        db::delete_expired_enrollment_sessions(db),
        "expired enrollment sessions"
    );

    // Clean up old events with retention cutoffs
    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        cleanup_and_log!(
            db::delete_old_auth_events(db, &cutoff_str),
            "old auth events"
        );
    }

    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        cleanup_and_log!(
            db::delete_old_oauth_usage_events(db, &cutoff_str),
            "old OAuth usage events"
        );
    }

    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        cleanup_and_log!(
            db::delete_old_github_credential_events(db, &cutoff),
            "old GitHub credential events"
        );
    }

    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        cleanup_and_log!(
            db::delete_old_scim_audit_logs(db, &cutoff_str),
            "old SCIM audit logs"
        );
    }

    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        cleanup_and_log!(
            db::delete_old_token_exchanges(db, &cutoff_str),
            "old token exchange records"
        );
    }

    // Clean up DPoP nonces
    {
        let mut nonce_manager = dpop_state.nonce_manager.write().await;
        nonce_manager.cleanup();
    }

    // Clean up expired SSH certificate revocations
    cleanup_and_log!(
        db::delete_expired_ssh_revocations(db),
        "expired SSH certificate revocations"
    );

    tracing::debug!("Background cleanup tasks complete");
}
