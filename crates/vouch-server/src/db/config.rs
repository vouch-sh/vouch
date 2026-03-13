// SPDX-License-Identifier: BUSL-1.1
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use std::net::IpAddr;

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
    pub client_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub client_hostname: Option<String>,
    pub client_os: Option<String>,
    pub client_arch: Option<String>,
    pub client_version: Option<String>,
    pub success: bool,
    pub failure_reason: Option<String>,
}

impl AuthEventParams {
    /// Populate all client metadata fields from a `ClientInfo` extractor.
    #[must_use]
    pub fn with_client_info(mut self, info: crate::handlers::extractors::ClientInfo) -> Self {
        self.client_ip = info.client_ip;
        self.user_agent = info.user_agent;
        self.client_hostname = info.client_hostname;
        self.client_os = info.client_os;
        self.client_arch = info.client_arch;
        self.client_version = info.client_version;
        self
    }
}

/// Insert a new authentication event via the audit store.
pub async fn insert_auth_event(
    audit: &AuditStore,
    params: &AuthEventParams,
    email: Option<&str>,
) -> Result<String> {
    let mut value = serde_json::to_value(params)
        .map_err(|e| anyhow::anyhow!("Failed to serialize auth event: {e}"))?;
    if let (Some(obj), Some(geo)) =
        (value.as_object_mut(), params.client_ip.and_then(crate::geo::lookup))
    {
        obj.insert("country_code".to_string(), serde_json::Value::String(geo.country_code));
        if let Some(asn) = geo.asn {
            obj.insert("asn".to_string(), serde_json::json!(asn));
        }
        if let Some(org) = geo.org_name {
            obj.insert("org_name".to_string(), serde_json::Value::String(org));
        }
    }
    let data_json = value.to_string();
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::handlers::extractors::ClientInfo;

    #[test]
    fn test_with_client_info_populates_all_fields() {
        let params = AuthEventParams {
            user_id: "u1".into(),
            event_type: AuthEventType::LoginSuccess,
            success: true,
            ..AuthEventParams::default()
        }
        .with_client_info(ClientInfo {
            client_ip: Some("1.2.3.4".parse().unwrap()),
            user_agent: Some("vouch-cli/1.0".into()),
            client_hostname: Some("host.local".into()),
            client_os: Some("macos".into()),
            client_arch: Some("aarch64".into()),
            client_version: Some("1.0.0".into()),
        });

        assert_eq!(params.client_ip, Some("1.2.3.4".parse::<IpAddr>().unwrap()));
        assert_eq!(params.user_agent.as_deref(), Some("vouch-cli/1.0"));
        assert_eq!(params.client_hostname.as_deref(), Some("host.local"));
        assert_eq!(params.client_os.as_deref(), Some("macos"));
        assert_eq!(params.client_arch.as_deref(), Some("aarch64"));
        assert_eq!(params.client_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_with_client_info_preserves_non_client_fields() {
        let params = AuthEventParams {
            user_id: "u1".into(),
            event_type: AuthEventType::LoginFailed,
            authenticator_id: Some("auth-abc".into()),
            success: false,
            failure_reason: Some("bad pin".into()),
            ..AuthEventParams::default()
        }
        .with_client_info(ClientInfo::default());

        assert_eq!(params.user_id, "u1");
        assert_eq!(params.event_type, AuthEventType::LoginFailed);
        assert_eq!(params.authenticator_id.as_deref(), Some("auth-abc"));
        assert!(!params.success);
        assert_eq!(params.failure_reason.as_deref(), Some("bad pin"));
    }

    #[test]
    fn test_with_client_info_none_clears_existing_fields() {
        let params = AuthEventParams {
            client_ip: Some("10.0.0.1".parse().unwrap()),
            user_agent: Some("old-ua".into()),
            client_hostname: Some("old-host".into()),
            client_os: Some("old-os".into()),
            client_arch: Some("old-arch".into()),
            client_version: Some("old-ver".into()),
            ..AuthEventParams::default()
        }
        .with_client_info(ClientInfo::default());

        assert_eq!(params.client_ip, None);
        assert_eq!(params.user_agent, None);
        assert_eq!(params.client_hostname, None);
        assert_eq!(params.client_os, None);
        assert_eq!(params.client_arch, None);
        assert_eq!(params.client_version, None);
    }
}
