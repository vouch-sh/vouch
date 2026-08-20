// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use std::net::IpAddr;

use super::audit::{AuditEventKind, AuditStore};
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ============================================================================
// Authentication Events
// ============================================================================

/// Authentication event types — the registry kinds whose audit payload is
/// [`AuthEventParams`]. The stored `event_type` string comes from
/// [`Self::kind`]; this enum carries no string knowledge of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthEventType {
    #[default]
    LoginSuccess,
    LoginFailed,
    Enrollment,
    Logout,
    KeyRegistered,
    KeyRemoved,
    DeviceAuthApproved,
    /// An upstream `(issuer, subject)` identity was bound to an existing
    /// account on its first IdP login (lazy bind).
    IdentityBound,
    /// An email match was refused because the account is already bound to
    /// a different subject for the same issuer (possible upstream email
    /// reassignment / takeover attempt).
    IdentityBindRefused,
}

impl AuthEventType {
    /// The registry kind this auth event maps to (drives the stored
    /// `event_type` string and retention).
    #[must_use]
    pub fn kind(&self) -> AuditEventKind {
        match self {
            Self::LoginSuccess => AuditEventKind::LoginSuccess,
            Self::LoginFailed => AuditEventKind::LoginFailed,
            Self::Enrollment => AuditEventKind::Enrollment,
            Self::Logout => AuditEventKind::Logout,
            Self::KeyRegistered => AuditEventKind::KeyRegistered,
            Self::KeyRemoved => AuditEventKind::KeyRemoved,
            Self::DeviceAuthApproved => AuditEventKind::DeviceAuthApproved,
            Self::IdentityBound => AuditEventKind::IdentityBound,
            Self::IdentityBindRefused => AuditEventKind::IdentityBindRefused,
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
    /// Caller transport metadata, flattened so the stored JSON keeps the
    /// same flat `client_ip`/`user_agent`/`client_*` keys as before.
    #[serde(flatten)]
    pub client: ClientInfo,
    pub success: bool,
    pub failure_reason: Option<String>,
    /// OAuth client ID of the RP that initiated logout, when applicable.
    /// Included in the `data` JSON blob so RP-initiated logouts are
    /// distinguishable from user-initiated ones without a schema migration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_id: Option<String>,
    /// Upstream IdP issuer for identity-binding events. The upstream
    /// subject is deliberately NOT recorded: a SAML NameID is frequently
    /// an email address, and audit payloads must not carry raw emails
    /// (see the [`crate::db::AuditData`] payload contract).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub idp_issuer: Option<String>,
}

/// Client information extracted from the request.
///
/// `client_ip` comes from the TCP socket (`ConnectInfo<SocketAddr>`), not from
/// proxy headers. This prevents IP spoofing via `X-Forwarded-For` when the
/// server is exposed directly without a trusted reverse proxy. The axum
/// extractor and header-parsing impls live in `handlers::extractors`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client IP address from the TCP peer socket.
    pub client_ip: Option<IpAddr>,
    /// User-Agent header.
    pub user_agent: Option<String>,
    /// Client hostname (from `Vouch-Client-Hostname` header).
    pub client_hostname: Option<String>,
    /// Client OS (from `Vouch-Client-OS` header).
    pub client_os: Option<String>,
    /// Client CPU architecture (from `Vouch-Client-Arch` header).
    pub client_arch: Option<String>,
    /// Client version (from `Vouch-Client-Version` header).
    pub client_version: Option<String>,
}

/// Insert a new authentication event via the audit store.
///
/// Production code records events through [`spawn_audit_event`]; this is
/// exposed to in-crate tests that need to await the write and inspect the
/// returned event ID.
pub(super) async fn insert_auth_event(
    audit: &AuditStore,
    params: &AuthEventParams,
    email: Option<&str>,
) -> Result<String> {
    let mut value = serde_json::to_value(params)
        .map_err(|e| anyhow::anyhow!("Failed to serialize auth event: {e}"))?;
    if let (Some(obj), Some(geo)) = (
        value.as_object_mut(),
        params.client.client_ip.and_then(crate::geo::lookup),
    ) {
        obj.insert(
            "country_code".to_string(),
            serde_json::Value::String(geo.country_code),
        );
        if let Some(asn) = geo.asn {
            obj.insert("asn".to_string(), serde_json::json!(asn));
        }
        if let Some(org) = geo.org_name {
            obj.insert("org_name".to_string(), serde_json::Value::String(org));
        }
    }
    let data_json = value.to_string();
    audit
        .insert_event_json(
            params.event_type.kind(),
            Some(&params.user_id),
            email,
            &data_json,
        )
        .await
}

/// Record an authentication event without blocking the caller.
///
/// Spawns a detached task so credential flows never wait on (or fail with)
/// the audit write; failures are logged with the event type so dropped
/// records are visible in one consistent format.
pub fn spawn_audit_event(audit: &AuditStore, params: AuthEventParams, email: Option<String>) {
    let audit = audit.clone();
    tokio::spawn(async move {
        if let Err(e) = insert_auth_event(&audit, &params, email.as_deref()).await {
            tracing::warn!(error = %e, event_type = ?params.event_type, "failed to record audit event");
        }
    });
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils::test_app_state;
    use jiff::SignedDuration;

    #[test]
    fn test_client_info_serializes_flat() {
        // The flattened ClientInfo must keep the same flat JSON keys the
        // pre-flatten struct wrote, so stored rows stay shape-compatible.
        let params = AuthEventParams {
            user_id: "u1".into(),
            event_type: AuthEventType::LoginSuccess,
            success: true,
            client: ClientInfo {
                client_ip: Some("1.2.3.4".parse().unwrap()),
                user_agent: Some("vouch-cli/1.0".into()),
                client_hostname: Some("host.local".into()),
                client_os: Some("macos".into()),
                client_arch: Some("aarch64".into()),
                client_version: Some("1.0.0".into()),
            },
            ..AuthEventParams::default()
        };
        let value = serde_json::to_value(&params).unwrap();
        assert!(value.get("client").is_none(), "no nested client object");
        assert_eq!(
            value.get("client_ip").and_then(|v| v.as_str()),
            Some("1.2.3.4")
        );
        assert_eq!(
            value.get("user_agent").and_then(|v| v.as_str()),
            Some("vouch-cli/1.0")
        );
        assert_eq!(
            value.get("client_hostname").and_then(|v| v.as_str()),
            Some("host.local")
        );
        assert_eq!(
            value.get("client_version").and_then(|v| v.as_str()),
            Some("1.0.0")
        );
    }

    #[test]
    fn test_audit_data_includes_client_id_when_set() {
        let params = AuthEventParams {
            user_id: "u1".into(),
            event_type: AuthEventType::Logout,
            success: true,
            client_id: Some("my-rp-client".to_string()),
            ..AuthEventParams::default()
        };
        let value = serde_json::to_value(&params).unwrap();
        assert_eq!(
            value.get("client_id").and_then(|v| v.as_str()),
            Some("my-rp-client"),
            "audit data must include client_id when set"
        );
    }

    #[test]
    fn test_audit_data_omits_client_id_when_none() {
        let params = AuthEventParams {
            user_id: "u1".into(),
            event_type: AuthEventType::LoginSuccess,
            success: true,
            client_id: None,
            ..AuthEventParams::default()
        };
        let value = serde_json::to_value(&params).unwrap();
        assert!(
            value.get("client_id").is_none(),
            "audit data must omit client_id when None"
        );
    }

    #[tokio::test]
    async fn test_retention_sweep_covers_all_auth_event_variants() -> anyhow::Result<()> {
        let state = test_app_state().await;
        let variants = [
            AuthEventType::LoginSuccess,
            AuthEventType::LoginFailed,
            AuthEventType::Enrollment,
            AuthEventType::Logout,
            AuthEventType::KeyRegistered,
            AuthEventType::KeyRemoved,
            AuthEventType::DeviceAuthApproved,
            AuthEventType::IdentityBound,
            AuthEventType::IdentityBindRefused,
        ];

        for (idx, event_type) in variants.iter().copied().enumerate() {
            let params = AuthEventParams {
                user_id: format!("user-{idx}"),
                event_type,
                success: !matches!(event_type, AuthEventType::LoginFailed),
                failure_reason: matches!(event_type, AuthEventType::LoginFailed)
                    .then(|| "invalid assertion".to_string()),
                ..AuthEventParams::default()
            };
            insert_auth_event(&state.audit, &params, Some("test@example.com")).await?;
        }

        let before = jiff::Timestamp::now()
            .checked_add(SignedDuration::from_mins(5))
            .map_err(|e| anyhow::anyhow!("valid timestamp arithmetic failed: {e}"))?;

        // Every auth event variant must be swept by the auth-events cutoff —
        // this fails if a variant's registry kind lost its AuthEvents class.
        let deleted = state
            .audit
            .delete_expired_events(Some(before), None)
            .await?;
        if deleted != variants.len() as u64 {
            return Err(anyhow::anyhow!(
                "auth cleanup must cover all AuthEventType variants: deleted={deleted}, expected={}",
                variants.len()
            ));
        }
        Ok(())
    }
}
