// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server configuration and authentication event database operations.
//!
//! Auth events are now stored via `AuditStore`. This module provides the
//! domain types and a convenience wrapper.

use std::net::IpAddr;

use super::audit::{AuditEventKind, AuditStore};
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

/// Who an authentication event is attributed to.
///
/// Only [`Principal::Verified`] fills the audit row's `user_id` column, and
/// that column is what per-user temporal policies replay
/// (`services::policy::events::history_event` skips rows without one), so a
/// row can count toward `failed_login_burst` only when the server verified
/// the user it names. Every writer states which case it is; the default is
/// the unattributed one, so a forgotten field fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A user the server authenticated for this request: a WebAuthn assertion
    /// whose signature verified, an upstream IdP callback that verified the
    /// identity, or a session or access token the server validated.
    Verified(String),
    /// No principal was verified. `asserted` is the request-supplied
    /// identifier (a WebAuthn `user_handle`, or the owner of a presented
    /// credential ID) kept in the payload for forensics; the `user_id`
    /// column stays NULL.
    Unverified { asserted: Option<String> },
    /// The server verified this user, but the event records a server fault,
    /// not something the user did. The id goes in the payload; the `user_id`
    /// column stays NULL so a storage outage cannot lock the user out.
    ServerFault { verified: String },
}

impl Principal {
    /// The id stored in the audit row's `user_id` column: the verified
    /// principal, or none.
    #[must_use]
    pub fn attributed_user_id(&self) -> Option<&str> {
        match self {
            Self::Verified(id) => Some(id),
            Self::Unverified { .. } | Self::ServerFault { .. } => None,
        }
    }
}

impl Default for Principal {
    fn default() -> Self {
        Self::Unverified { asserted: None }
    }
}

/// Flattened into the payload as `user_id` (verified), `asserted_user_id`
/// (unverified, when known), or `fault_user_id` (server fault). A payload
/// `user_id` key therefore always names a verified principal.
impl Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let entry = match self {
            Self::Verified(id) => Some(("user_id", id)),
            Self::Unverified { asserted } => asserted.as_ref().map(|id| ("asserted_user_id", id)),
            Self::ServerFault { verified } => Some(("fault_user_id", verified)),
        };
        let mut map = serializer.serialize_map(Some(usize::from(entry.is_some())))?;
        if let Some((key, id)) = entry {
            map.serialize_entry(key, id)?;
        }
        map.end()
    }
}

/// Parameters for creating an authentication event.
#[derive(Debug, Default, Serialize)]
pub struct AuthEventParams {
    #[serde(flatten)]
    pub user_id: Principal,
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

/// Record an authentication event via the audit store.
///
/// Awaited so the row is committed before the response is sent, and
/// best-effort like every [`AuditStore`] write: failures are logged with
/// the wire `event_type` and swallowed.
pub async fn record_auth_event(audit: &AuditStore, params: AuthEventParams, email: Option<String>) {
    let data = crate::db::documents::audit::AuthEventData {
        geo: crate::db::documents::audit::GeoFields::from_ip(params.client.client_ip),
        params: &params,
    };
    audit
        .record_event(
            params.event_type.kind(),
            params.user_id.attributed_user_id(),
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
            user_id: Principal::Verified("u1".into()),
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
            user_id: Principal::Verified("u1".into()),
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
            user_id: Principal::Verified("u1".into()),
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
                user_id: Principal::Verified(format!("user-{idx}")),
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
