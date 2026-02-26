// SPDX-License-Identifier: BUSL-1.1
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use super::audit::{AuditEventFilter, AuditStore};
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

/// Authentication event record (retrieved from audit store).
#[derive(Debug)]
pub struct AuthEvent {
    pub id: String,
    pub user_id: String,
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
    pub created_at: jiff::Timestamp,
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

/// Query parameters for listing authentication events.
#[derive(Debug, Default)]
pub struct AuthEventQuery {
    pub user_id: Option<String>,
    pub event_type: Option<String>,
    pub since: Option<String>,
    pub limit: Option<i64>,
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

/// Get authentication events with optional filtering.
pub async fn get_auth_events(
    audit: &AuditStore,
    query_params: &AuthEventQuery,
) -> Result<Vec<AuthEvent>> {
    let filter = AuditEventFilter {
        event_type: query_params.event_type.clone(),
        user_id: query_params.user_id.clone(),
        email: None,
        since: query_params.since.clone(),
        limit: query_params.limit.map(|l| l as u64),
    };

    let events = audit.query_events(&filter).await?;
    let mut result = Vec::with_capacity(events.len());
    for event in events {
        // Deserialize the data JSON to extract auth event fields
        let params: AuthEventParams = serde_json::from_str(&event.data).unwrap_or_default();
        let event_type = match event.event_type.as_str() {
            "login_success" => AuthEventType::LoginSuccess,
            "login_failed" => AuthEventType::LoginFailed,
            "enrollment" => AuthEventType::Enrollment,
            "logout" => AuthEventType::Logout,
            _ => AuthEventType::LoginSuccess,
        };
        result.push(AuthEvent {
            id: event.id,
            user_id: params.user_id,
            event_type,
            authenticator_id: params.authenticator_id,
            client_ip: params.client_ip,
            user_agent: params.user_agent,
            client_hostname: params.client_hostname,
            client_os: params.client_os,
            client_arch: params.client_arch,
            client_version: params.client_version,
            success: params.success,
            failure_reason: params.failure_reason,
            created_at: event
                .created_at
                .parse::<jiff::Timestamp>()
                .unwrap_or_else(|_| jiff::Timestamp::now()),
        });
    }
    Ok(result)
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
