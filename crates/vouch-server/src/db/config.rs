// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use super::audit::{AuditEventKind, AuditStore};
use serde::Serialize;

pub use crate::client_info::ClientInfo;

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
    KeyRenamed,
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
            Self::KeyRenamed => AuditEventKind::KeyRenamed,
            Self::DeviceAuthApproved => AuditEventKind::DeviceAuthApproved,
            Self::IdentityBound => AuditEventKind::IdentityBound,
            Self::IdentityBindRefused => AuditEventKind::IdentityBindRefused,
        }
    }
}

/// Parameters for creating an authentication event.
///
/// No `Default` outside tests: `client` has no default, so every writer names
/// the request's [`ClientInfo`].
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Default))]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Upstream IdP issuer for identity-binding events. The upstream
    /// subject is deliberately NOT recorded: a SAML NameID is frequently
    /// an email address, and audit payloads must not carry raw emails
    /// (see the [`crate::db::AuditData`] payload contract).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_issuer: Option<String>,
}

/// Record an authentication event via the audit store.
///
/// Awaited so the row is committed before the response is sent, and
/// best-effort like every [`AuditStore`] write: failures are logged with
/// the wire `event_type` and swallowed.
pub async fn record_auth_event(audit: &AuditStore, params: AuthEventParams, email: Option<String>) {
    let data = crate::db::documents::audit::AuthEventData {
        geo: crate::db::documents::audit::GeoFields::from_ip(params.client.client_ip()),
        params: &params,
    };
    audit
        .record_event(
            params.event_type.kind(),
            Some(&params.user_id),
            email.as_deref(),
            &data,
        )
        .await;
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
            client: ClientInfo::for_test(
                Some("1.2.3.4".parse().unwrap()),
                &axum::http::HeaderMap::from_iter([
                    (
                        axum::http::header::USER_AGENT,
                        axum::http::HeaderValue::from_static("vouch-cli/1.0"),
                    ),
                    (
                        axum::http::HeaderName::from_static("vouch-client-hostname"),
                        axum::http::HeaderValue::from_static("host.local"),
                    ),
                    (
                        axum::http::HeaderName::from_static("vouch-client-os"),
                        axum::http::HeaderValue::from_static("macos"),
                    ),
                    (
                        axum::http::HeaderName::from_static("vouch-client-arch"),
                        axum::http::HeaderValue::from_static("aarch64"),
                    ),
                    (
                        axum::http::HeaderName::from_static("vouch-client-version"),
                        axum::http::HeaderValue::from_static("1.0.0"),
                    ),
                ]),
            ),
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
            AuthEventType::KeyRenamed,
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
            record_auth_event(&state.audit, params, Some("test@example.com".to_string())).await;
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
