// SPDX-License-Identifier: BUSL-1.1
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use super::audit::AuditStore;
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ============================================================================
// Authentication Events
// ============================================================================

/// Authentication event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum AuthEventType {
    #[default]
    #[serde(rename = "login_success")]
    LoginSuccess,
    #[serde(rename = "login_failed")]
    LoginFailed,
    #[serde(rename = "enrollment")]
    Enrollment,
    #[serde(rename = "logout")]
    Logout,
}

impl AuthEventType {
    /// Return the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoginSuccess => "login_success",
            Self::LoginFailed => "login_failed",
            Self::Enrollment => "enrollment",
            Self::Logout => "logout",
        }
    }
}

/// Parameters for creating an authentication event.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthEventParams {
    pub user_id: String,
    #[serde(skip)]
    pub event_type: AuthEventType,
    pub authenticator_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub client_hostname: Option<String>,
    pub client_os: Option<String>,
    pub client_arch: Option<String>,
    pub client_version: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
}

/// Insert a new authentication event via the audit store.
pub async fn insert_auth_event(
    audit: &AuditStore,
    params: &AuthEventParams,
    email: Option<&str>,
) -> Result<String> {
    let data_json = serde_json::to_string(params)
        .map_err(|e| anyhow::anyhow!("Failed to serialize auth event: {e}"))?;
    audit
        .insert_event(
            params.event_type.as_str(),
            Some(&params.user_id),
            email,
            &data_json,
        )
        .await
}

/// Delete authentication events older than the specified timestamp.
pub async fn delete_old_auth_events(audit: &AuditStore, before: jiff::Timestamp) -> Result<u64> {
    let before_str = before.to_string();
    // Delete all auth event types
    let mut total = 0;
    for event_type in ["login_success", "login_failed", "enrollment", "logout"] {
        total += audit.delete_old_events(event_type, &before_str).await?;
    }
    Ok(total)
}
