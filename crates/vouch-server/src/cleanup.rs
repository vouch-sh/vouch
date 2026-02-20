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

    // Clean up expired sessions
    match db::delete_expired_sessions(db, &now_str).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired sessions");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired sessions: {e}");
        }
    }

    // Clean up expired device auth requests
    match db::delete_expired_device_auth_requests(db, &now_str).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired device auth requests");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired device auth requests: {e}");
        }
    }

    // Clean up expired OIDC states
    match db::delete_expired_oidc_states(db, &now_str).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired OIDC states");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired OIDC states: {e}");
        }
    }

    // Clean up expired pending OAuth authorizations (RFC 6749 browser login flow)
    match db::delete_expired_pending_oauth_authorizations(db, &now_str).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired pending OAuth authorizations");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired pending OAuth authorizations: {e}");
        }
    }

    // Clean up expired enrollment sessions
    match db::delete_expired_enrollment_sessions(db).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired enrollment sessions");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired enrollment sessions: {e}");
        }
    }

    // Clean up old auth events
    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        match db::delete_old_auth_events(db, &cutoff_str).await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} old auth events");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up old auth events: {e}");
            }
        }
    }

    // Clean up old OAuth usage events
    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        match db::delete_old_oauth_usage_events(db, &cutoff_str).await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} old OAuth usage events");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up old OAuth usage events: {e}");
            }
        }
    }

    // Clean up old GitHub credential events
    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        match db::delete_old_github_credential_events(db, &cutoff).await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} old GitHub credential events");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up old GitHub credential events: {e}");
            }
        }
    }

    // Clean up old SCIM audit logs
    if let Ok(cutoff) = now.checked_sub(auth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        match db::delete_old_scim_audit_logs(db, &cutoff_str).await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} old SCIM audit logs");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up old SCIM audit logs: {e}");
            }
        }
    }

    // Clean up old token exchange records
    if let Ok(cutoff) = now.checked_sub(oauth_events_retention_days.days()) {
        let cutoff_str = cutoff.to_string();
        match db::delete_old_token_exchanges(db, &cutoff_str).await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} old token exchange records");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up old token exchange records: {e}");
            }
        }
    }

    // Clean up DPoP nonces
    {
        let mut nonce_manager = dpop_state.nonce_manager.write().await;
        nonce_manager.cleanup();
    }

    // Clean up expired SSH certificate revocations
    match db::delete_expired_ssh_revocations(db).await {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} expired SSH certificate revocations");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to clean up expired SSH revocations: {e}");
        }
    }

    tracing::debug!("Background cleanup tasks complete");
}
