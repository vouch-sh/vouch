// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit event data payloads for the `audit_events.data` JSON column.
//!
//! These are serialized to JSON and stored in the unencrypted audit table.
//! They are NOT `DocumentType` implementations — they're the typed payload
//! behind [`AuditData`] that `AuditStore::insert_event` serializes.
//!
//! Every payload the audit write API accepts is a named struct in this
//! file: [`AuditData`] is sealed by a module-private supertrait, so an ad
//! hoc `serde_json::json!` literal cannot be passed, and this module is
//! the whole review surface for what audit `data` may contain. The seal
//! cannot inspect values — a free-text field on a vetted payload could
//! still carry an address, so payload fields here are what review guards.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::db::audit::AuditEventKind;

/// Seal for [`AuditData`]. Private to this module on purpose: a new payload
/// type must be added here, not implemented ad hoc elsewhere in the crate.
mod sealed {
    pub trait Sealed {}
}

/// A vetted, named audit `data` payload accepted by
/// `AuditStore::insert_event` / `insert_event_with_domain`.
///
/// Raw email addresses must not appear in payload fields — audit rows
/// carry only the derived `email_domain` / `email_hmac` columns; identify
/// users via `*_user_id` fields.
pub trait AuditData: Serialize + sealed::Sealed {}

/// Implement [`AuditData`] (and its seal) for payload structs in this file.
macro_rules! impl_audit_data {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl AuditData for $ty {}
        )+
    };
}

/// Administrative member actions (promote/demote/activate/deactivate/
/// revoke-credentials/remove), written under the corresponding `Admin*`
/// kinds. `target_user_id` is what the admin UI resolves to a display
/// email at render time.
#[derive(Debug, Serialize)]
pub(crate) struct AdminMemberActionData<'a> {
    pub action: &'static str,
    pub target_user_id: &'a str,
    pub admin_user_id: &'a str,
    /// Only the revoke-credentials site records how many keys were revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_revoked: Option<usize>,
}

/// Admin-initiated additional-domain add/verify (`OrgDomainAdded`,
/// `OrgDomainVerified`).
#[derive(Debug, Serialize)]
pub(crate) struct OrgDomainAdminData<'a> {
    pub action: &'static str,
    pub domain: &'a str,
    pub admin_user_id: &'a str,
    /// Verification method; only the verify site records it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
}

/// Admin-initiated additional-domain removal (`OrgDomainRemoved`), with the
/// revocation fallout the removal triggered.
#[derive(Debug, Serialize)]
pub(crate) struct OrgDomainRemovalData<'a> {
    pub action: &'static str,
    pub domain: &'a str,
    pub admin_user_id: &'a str,
    pub revoked_user_session_count: u64,
    pub revocation_errored: bool,
    /// Issuer subdomain released because this was its last verified backing
    /// domain; serialized as an explicit `null` when none was.
    pub released_subdomain: Option<String>,
}

/// Admin-initiated issuer-subdomain claim (`OrgSubdomainClaimed`).
#[derive(Debug, Serialize)]
pub(crate) struct OrgSubdomainClaimData<'a> {
    pub action: &'static str,
    pub label: &'a str,
    /// Full issuer URL; serialized as an explicit `null` when the config
    /// cannot derive one.
    pub issuer: Option<&'a str>,
    pub admin_user_id: &'a str,
}

/// Admin-initiated issuer-subdomain release (`OrgSubdomainReleased`).
#[derive(Debug, Serialize)]
pub(crate) struct OrgSubdomainReleaseData<'a> {
    pub action: &'static str,
    pub label: &'a str,
    pub admin_user_id: &'a str,
}

/// SCIM API token lifecycle (`AdminCreateScimToken`, `AdminDeleteScimToken`,
/// `AdminRevokeScimToken`).
#[derive(Debug, Serialize)]
pub(crate) struct ScimTokenAdminData<'a> {
    pub action: &'static str,
    pub token_id: &'a str,
    pub admin_user_id: &'a str,
}

/// Preconfigured posture-policy enable/disable (`AdminPolicyToggle`).
#[derive(Debug, Serialize)]
pub(crate) struct PreconfiguredPolicyToggleData<'a> {
    /// `preconfigured_policy_{enabled|disabled}` — built with `format!` at
    /// the call site.
    pub action: String,
    pub slug: &'a str,
    pub admin_user_id: &'a str,
}

/// Custom posture-policy lifecycle (`AdminPolicyCreate`/`Update`/`Delete`
/// and the custom-policy arm of `AdminPolicyToggle`).
#[derive(Debug, Serialize)]
pub(crate) struct CustomPolicyAdminData<'a> {
    /// `custom_policy_created` / `_updated` / `_deleted` /
    /// `custom_policy_{enabled|disabled}`.
    pub action: String,
    pub policy_id: &'a str,
    /// Absent on delete (the policy is gone).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<&'a str>,
    pub admin_user_id: &'a str,
    /// SHA-256 of the policy text; absent on delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_text_hash: Option<String>,
}

/// Cleanup-task removal of a stale additional domain (`OrgDomainExpired`)
/// or automatic unverify after DNS re-check failures (`OrgDomainUnverified`).
/// System actor: no `admin_user_id`.
#[derive(Debug, Serialize)]
pub(crate) struct OrgDomainCleanupData<'a> {
    pub action: &'static str,
    pub domain: &'a str,
    pub org_id: &'a str,
    pub reason: &'static str,
}

/// Cleanup-task release of an issuer subdomain whose backing domain became
/// unverified (`OrgSubdomainReleased`). System actor: no `admin_user_id`.
#[derive(Debug, Serialize)]
pub(crate) struct OrgSubdomainCleanupData<'a> {
    pub action: &'static str,
    pub label: &'a str,
    pub org_id: &'a str,
    pub reason: &'static str,
}

/// Replayed key-registration link rejected (`KeyRegistrationReplay`).
#[derive(Debug, Serialize)]
pub(crate) struct RegistrationReplayData {
    /// `cli_register` or `browser_register`.
    pub flow: &'static str,
    /// `false` — the event records a rejection.
    pub success: bool,
    pub error_code: &'static str,
}

/// Per-org issuer key rotation, scheduled or emergency
/// (`OrgIssuerKeyRotated`, `OrgIssuerKeyEmergencyRotation`) — one event per
/// algorithm.
#[derive(Debug, Serialize)]
pub(crate) struct OrgIssuerKeyRotationData<'a> {
    pub action: &'static str,
    pub org_id: &'a str,
    pub alg: &'static str,
    pub old_kid: &'a str,
    pub new_kid: &'a str,
}

/// Per-org previous-key revocation (`OrgIssuerKeyRevoked`) — one event per
/// algorithm.
#[derive(Debug, Serialize)]
pub(crate) struct OrgIssuerKeyRevocationData<'a> {
    pub action: &'static str,
    pub org_id: &'a str,
    pub alg: &'static str,
    pub kid: &'a str,
}

/// A posture or temporal policy denying credential issuance
/// (`PolicyDenied`). `policy` is the policy's registered name, not free
/// text.
#[derive(Debug, Serialize)]
pub(crate) struct PolicyDenialData<'a> {
    /// `issue_token` or `exchange_token`.
    pub action: &'static str,
    pub policy: &'a str,
    pub org_id: &'a str,
}

impl_audit_data!(
    AdminMemberActionData<'_>,
    OrgDomainAdminData<'_>,
    OrgDomainRemovalData<'_>,
    OrgSubdomainClaimData<'_>,
    OrgSubdomainReleaseData<'_>,
    ScimTokenAdminData<'_>,
    PreconfiguredPolicyToggleData<'_>,
    CustomPolicyAdminData<'_>,
    OrgDomainCleanupData<'_>,
    OrgSubdomainCleanupData<'_>,
    RegistrationReplayData,
    OrgIssuerKeyRotationData<'_>,
    OrgIssuerKeyRevocationData<'_>,
    PolicyDenialData<'_>,
    OAuthUsageData,
    ScimAuditData,
);

/// Data payload for OAuth usage audit events.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OAuthUsageData {
    pub oauth_client_id: String,
    pub details: Option<String>,
    #[serde(alias = "ip_address")]
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// Data payload for SCIM operation audit events.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScimAuditData {
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
    pub actor_token_id: Option<String>,
    pub details: Option<String>,
}

/// Fields shared by every credential-issuance audit payload.
///
/// Serialized flattened alongside a [`CredentialAuditDetails`] payload, so
/// stored events keep one flat JSON object per event.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredentialAuditEnvelope {
    /// Event subtype within the kind (e.g. "token_issued",
    /// "certificate_issued", "installation_connected").
    pub event_type: String,
    pub org_id: Option<String>,
    pub authenticator_id: Option<String>,
    /// AI coding agent from the DPoP `source` claim (e.g. "claude-code");
    /// mirrors the `vouch:Agent` session tag minted into AWS tokens.
    pub agent: Option<String>,
    pub success: bool,
    #[serde(alias = "ip_address")]
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

impl CredentialAuditEnvelope {
    /// Record the caller's transport metadata: IP, user agent, and the
    /// geo fields derived from the IP. Events written without this carry
    /// null transport fields (e.g. token exchange, which runs in the
    /// services layer without request context).
    #[must_use]
    pub fn with_client(mut self, ip: Option<std::net::IpAddr>, user_agent: Option<String>) -> Self {
        self.client_ip = ip.map(|a| a.to_string());
        self.user_agent = user_agent;
        (self.country_code, self.asn, self.org_name) = crate::geo::audit_fields(ip);
        self
    }
}

/// Domain-specific fields of a credential audit event, tied at compile time
/// to the registry kind they are written under — a payload cannot be stored
/// under another kind's `event_type`.
pub trait CredentialAuditDetails: Serialize {
    /// The registry kind this payload is written under.
    const KIND: AuditEventKind;
}

/// GitHub credential events: token issuance and installation lifecycle.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GitHubCredentialDetails {
    pub installation_id: Option<i64>,
    pub session_id: Option<String>,
    pub repositories: Option<Vec<String>>,
    pub permissions: Option<HashMap<String, String>>,
    pub token_expires_at: Option<String>,
    pub error_code: Option<String>,
}

impl CredentialAuditDetails for GitHubCredentialDetails {
    const KIND: AuditEventKind = AuditEventKind::GitHubCredential;
}

/// AWS OIDC token issuance.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AwsCredentialDetails {
    /// IAM role ARN the token was pinned to via the
    /// `https://aws.amazon.com/roles` claim; `None` for unpinned tokens.
    pub role_arn: Option<String>,
    pub token_expires_at: Option<String>,
}

impl CredentialAuditDetails for AwsCredentialDetails {
    const KIND: AuditEventKind = AuditEventKind::AwsCredential;
}

/// SSH certificate issuance.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SshCredentialDetails {
    /// Certificate serial number, for correlation with the KRL.
    pub serial: u64,
    pub principals: Vec<String>,
    /// Certificate expiry (RFC 3339).
    pub cert_expires_at: Option<String>,
}

impl CredentialAuditDetails for SshCredentialDetails {
    const KIND: AuditEventKind = AuditEventKind::SshCredential;
}

/// RFC 8693 token exchange (workload identity federation).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TokenExchangeDetails {
    /// OAuth client that performed the exchange.
    pub client_id: String,
    /// Requested audience (`aud` of the issued token), if any.
    pub audience: Option<String>,
    /// Granted OAuth scope (absent for ID-token exchanges).
    pub scope: Option<String>,
    /// RFC 8693 issued token type URN
    /// (`urn:ietf:params:oauth:token-type:access_token` or `...:id_token`).
    pub issued_token_type: String,
    /// Issued token expiry (RFC 3339).
    pub token_expires_at: Option<String>,
}

impl CredentialAuditDetails for TokenExchangeDetails {
    const KIND: AuditEventKind = AuditEventKind::TokenExchange;
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_usage_data_deserialize_without_asn_fields() {
        let json = r#"{
            "oauth_client_id": "c1",
            "details": null,
            "client_ip": "1.2.3.4",
            "user_agent": null,
            "country_code": "US"
        }"#;
        let data: OAuthUsageData = serde_json::from_str(json).unwrap();
        assert_eq!(data.country_code.as_deref(), Some("US"));
        assert!(data.asn.is_none());
        assert!(data.org_name.is_none());
    }

    #[test]
    fn test_oauth_usage_data_roundtrip_with_asn() {
        let data = OAuthUsageData {
            oauth_client_id: "c1".to_string(),
            details: None,
            client_ip: Some("8.8.8.8".to_string()),
            user_agent: None,
            country_code: Some("US".to_string()),
            asn: Some(15169),
            org_name: Some("GOOGLE".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: OAuthUsageData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.asn, Some(15169));
        assert_eq!(back.org_name.as_deref(), Some("GOOGLE"));
    }

    #[test]
    fn test_oauth_usage_data_serialize_none_asn_omits_keys() {
        let data = OAuthUsageData {
            oauth_client_id: "c1".to_string(),
            details: None,
            client_ip: None,
            user_agent: None,
            country_code: None,
            asn: None,
            org_name: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.contains("\"asn\""));
        assert!(!json.contains("\"org_name\""));
    }

    #[test]
    fn test_envelope_deserialize_without_geo_fields() {
        let json = r#"{"event_type":"token_issued","success":true}"#;
        let data: CredentialAuditEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(data.event_type, "token_issued");
        assert!(data.asn.is_none());
        assert!(data.org_name.is_none());
    }

    #[test]
    fn test_envelope_reads_legacy_ip_address_field() {
        // Rows written before the client_ip rename used "ip_address".
        let json = r#"{"event_type":"token_issued","success":true,"ip_address":"1.2.3.4"}"#;
        let data: CredentialAuditEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(data.client_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn test_envelope_roundtrip_with_geo() {
        let data = CredentialAuditEnvelope {
            event_type: "token_issued".to_string(),
            agent: Some("claude-code".to_string()),
            asn: Some(3320),
            org_name: Some("DTAG".to_string()),
            ..CredentialAuditEnvelope::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: CredentialAuditEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent.as_deref(), Some("claude-code"));
        assert_eq!(back.asn, Some(3320));
        assert_eq!(back.org_name.as_deref(), Some("DTAG"));
    }

    /// Every typed payload must serialize to the exact JSON shape of the
    /// rows already stored in `audit_events` (Value equality — key order
    /// is irrelevant, every reader parses). Covers both branches of every
    /// optional field.
    #[test]
    fn test_typed_payloads_match_stored_row_shapes() {
        use serde_json::json;

        let cases: Vec<(serde_json::Value, serde_json::Value)> = vec![
            // members.rs promote (keys_revoked absent) and
            // revoke_credentials (keys_revoked present)
            (
                serde_json::to_value(AdminMemberActionData {
                    action: "promote",
                    target_user_id: "u-target",
                    admin_user_id: "u-admin",
                    keys_revoked: None,
                })
                .unwrap(),
                json!({
                    "action": "promote",
                    "target_user_id": "u-target",
                    "admin_user_id": "u-admin",
                }),
            ),
            (
                serde_json::to_value(AdminMemberActionData {
                    action: "revoke_credentials",
                    target_user_id: "u-target",
                    admin_user_id: "u-admin",
                    keys_revoked: Some(3),
                })
                .unwrap(),
                json!({
                    "action": "revoke_credentials",
                    "target_user_id": "u-target",
                    "admin_user_id": "u-admin",
                    "keys_revoked": 3,
                }),
            ),
            // domains.rs add (method absent) and verify (method present)
            (
                serde_json::to_value(OrgDomainAdminData {
                    action: "add_org_domain",
                    domain: "acme.co",
                    admin_user_id: "u-admin",
                    method: None,
                })
                .unwrap(),
                json!({
                    "action": "add_org_domain",
                    "domain": "acme.co",
                    "admin_user_id": "u-admin",
                }),
            ),
            (
                serde_json::to_value(OrgDomainAdminData {
                    action: "verify_org_domain",
                    domain: "acme.co",
                    admin_user_id: "u-admin",
                    method: Some("dns_txt"),
                })
                .unwrap(),
                json!({
                    "action": "verify_org_domain",
                    "domain": "acme.co",
                    "admin_user_id": "u-admin",
                    "method": "dns_txt",
                }),
            ),
            // domains.rs remove: released_subdomain None serialized as an
            // explicit null (the historical json! shape), Some as a string
            (
                serde_json::to_value(OrgDomainRemovalData {
                    action: "remove_org_domain",
                    domain: "acme.co",
                    admin_user_id: "u-admin",
                    revoked_user_session_count: 2,
                    revocation_errored: false,
                    released_subdomain: None,
                })
                .unwrap(),
                json!({
                    "action": "remove_org_domain",
                    "domain": "acme.co",
                    "admin_user_id": "u-admin",
                    "revoked_user_session_count": 2,
                    "revocation_errored": false,
                    "released_subdomain": null,
                }),
            ),
            (
                serde_json::to_value(OrgDomainRemovalData {
                    action: "remove_org_domain",
                    domain: "acme.co",
                    admin_user_id: "u-admin",
                    revoked_user_session_count: 0,
                    revocation_errored: true,
                    released_subdomain: Some("acme-co".to_string()),
                })
                .unwrap(),
                json!({
                    "action": "remove_org_domain",
                    "domain": "acme.co",
                    "admin_user_id": "u-admin",
                    "revoked_user_session_count": 0,
                    "revocation_errored": true,
                    "released_subdomain": "acme-co",
                }),
            ),
        ];
        for (typed, literal) in cases {
            assert_eq!(typed, literal);
        }
    }

    /// Same stored-row-shape contract for the subdomain, SCIM-token, and
    /// policy payloads.
    #[test]
    fn test_subdomain_scim_and_policy_payloads_match_stored_row_shapes() {
        use serde_json::json;

        let cases: Vec<(serde_json::Value, serde_json::Value)> = vec![
            // subdomain.rs claim (issuer present) and release (absent)
            (
                serde_json::to_value(OrgSubdomainClaimData {
                    action: "claim_subdomain",
                    label: "acme-co",
                    issuer: Some("https://acme-co.us.vouch.sh"),
                    admin_user_id: "u-admin",
                })
                .unwrap(),
                json!({
                    "action": "claim_subdomain",
                    "label": "acme-co",
                    "issuer": "https://acme-co.us.vouch.sh",
                    "admin_user_id": "u-admin",
                }),
            ),
            (
                serde_json::to_value(OrgSubdomainClaimData {
                    action: "claim_subdomain",
                    label: "acme-co",
                    issuer: None,
                    admin_user_id: "u-admin",
                })
                .unwrap(),
                json!({
                    "action": "claim_subdomain",
                    "label": "acme-co",
                    "issuer": null,
                    "admin_user_id": "u-admin",
                }),
            ),
            (
                serde_json::to_value(OrgSubdomainReleaseData {
                    action: "release_subdomain",
                    label: "acme-co",
                    admin_user_id: "u-admin",
                })
                .unwrap(),
                json!({
                    "action": "release_subdomain",
                    "label": "acme-co",
                    "admin_user_id": "u-admin",
                }),
            ),
            // scim_tokens.rs create
            (
                serde_json::to_value(ScimTokenAdminData {
                    action: "create_scim_token",
                    token_id: "tok-1",
                    admin_user_id: "u-admin",
                })
                .unwrap(),
                json!({
                    "action": "create_scim_token",
                    "token_id": "tok-1",
                    "admin_user_id": "u-admin",
                }),
            ),
            // policies.rs preconfigured toggle
            (
                serde_json::to_value(PreconfiguredPolicyToggleData {
                    action: "preconfigured_policy_enabled".to_string(),
                    slug: "require-secure-boot",
                    admin_user_id: "u-admin",
                })
                .unwrap(),
                json!({
                    "action": "preconfigured_policy_enabled",
                    "slug": "require-secure-boot",
                    "admin_user_id": "u-admin",
                }),
            ),
            // policies.rs custom create (name + hash) and delete (neither)
            (
                serde_json::to_value(CustomPolicyAdminData {
                    action: "custom_policy_created".to_string(),
                    policy_id: "pol-1",
                    policy_name: Some("Block exports"),
                    admin_user_id: "u-admin",
                    policy_text_hash: Some("abc123".to_string()),
                })
                .unwrap(),
                json!({
                    "action": "custom_policy_created",
                    "policy_id": "pol-1",
                    "policy_name": "Block exports",
                    "admin_user_id": "u-admin",
                    "policy_text_hash": "abc123",
                }),
            ),
            // policies.rs custom update (name + hash), mirroring create
            (
                serde_json::to_value(CustomPolicyAdminData {
                    action: "custom_policy_updated".to_string(),
                    policy_id: "pol-1",
                    policy_name: Some("Block exports"),
                    admin_user_id: "u-admin",
                    policy_text_hash: Some("abc123".to_string()),
                })
                .unwrap(),
                json!({
                    "action": "custom_policy_updated",
                    "policy_id": "pol-1",
                    "policy_name": "Block exports",
                    "admin_user_id": "u-admin",
                    "policy_text_hash": "abc123",
                }),
            ),
            (
                serde_json::to_value(CustomPolicyAdminData {
                    action: "custom_policy_deleted".to_string(),
                    policy_id: "pol-1",
                    policy_name: None,
                    admin_user_id: "u-admin",
                    policy_text_hash: None,
                })
                .unwrap(),
                json!({
                    "action": "custom_policy_deleted",
                    "policy_id": "pol-1",
                    "admin_user_id": "u-admin",
                }),
            ),
        ];
        for (typed, literal) in cases {
            assert_eq!(typed, literal);
        }
    }

    /// Same stored-row-shape contract for the cleanup, replay, key-rotation,
    /// and policy-denial payloads.
    #[test]
    fn test_system_actor_payloads_match_stored_row_shapes() {
        use serde_json::json;

        let cases: Vec<(serde_json::Value, serde_json::Value)> = vec![
            // infra/cleanup.rs expire + subdomain release
            (
                serde_json::to_value(OrgDomainCleanupData {
                    action: "expire_org_domain",
                    domain: "acme.co",
                    org_id: "org-1",
                    reason: "pending_ttl_expired",
                })
                .unwrap(),
                json!({
                    "action": "expire_org_domain",
                    "domain": "acme.co",
                    "org_id": "org-1",
                    "reason": "pending_ttl_expired",
                }),
            ),
            (
                serde_json::to_value(OrgSubdomainCleanupData {
                    action: "release_subdomain",
                    label: "acme-co",
                    org_id: "org-1",
                    reason: "backing_domain_unverified",
                })
                .unwrap(),
                json!({
                    "action": "release_subdomain",
                    "label": "acme-co",
                    "org_id": "org-1",
                    "reason": "backing_domain_unverified",
                }),
            ),
            // keys.rs / enroll.rs replay rejection
            (
                serde_json::to_value(RegistrationReplayData {
                    flow: "cli_register",
                    success: false,
                    error_code: "state_already_used",
                })
                .unwrap(),
                json!({
                    "flow": "cli_register",
                    "success": false,
                    "error_code": "state_already_used",
                }),
            ),
            // org_keys/rotation.rs rotate and revoke
            (
                serde_json::to_value(OrgIssuerKeyRotationData {
                    action: "rotate_org_issuer_key",
                    org_id: "org-1",
                    alg: "ES256",
                    old_kid: "kid-old",
                    new_kid: "kid-new",
                })
                .unwrap(),
                json!({
                    "action": "rotate_org_issuer_key",
                    "org_id": "org-1",
                    "alg": "ES256",
                    "old_kid": "kid-old",
                    "new_kid": "kid-new",
                }),
            ),
            (
                serde_json::to_value(OrgIssuerKeyRevocationData {
                    action: "revoke_org_issuer_key",
                    org_id: "org-1",
                    alg: "RS256",
                    kid: "kid-old",
                })
                .unwrap(),
                json!({
                    "action": "revoke_org_issuer_key",
                    "org_id": "org-1",
                    "alg": "RS256",
                    "kid": "kid-old",
                }),
            ),
            // services/policy/mod.rs denial
            (
                serde_json::to_value(PolicyDenialData {
                    action: "issue_token",
                    policy: "exchange-ip-consistency",
                    org_id: "org-1",
                })
                .unwrap(),
                json!({
                    "action": "issue_token",
                    "policy": "exchange-ip-consistency",
                    "org_id": "org-1",
                }),
            ),
        ];

        for (typed, literal) in cases {
            assert_eq!(typed, literal);
        }
    }

    #[test]
    fn test_details_roundtrip() {
        let aws = AwsCredentialDetails {
            role_arn: Some("arn:aws:iam::111122223333:role/Example".to_string()),
            token_expires_at: None,
        };
        let back: AwsCredentialDetails =
            serde_json::from_str(&serde_json::to_string(&aws).unwrap()).unwrap();
        assert_eq!(
            back.role_arn.as_deref(),
            Some("arn:aws:iam::111122223333:role/Example")
        );

        let ssh = SshCredentialDetails {
            serial: u64::MAX,
            principals: vec!["dev".to_string()],
            cert_expires_at: None,
        };
        let back: SshCredentialDetails =
            serde_json::from_str(&serde_json::to_string(&ssh).unwrap()).unwrap();
        assert_eq!(back.serial, u64::MAX);
        assert_eq!(back.principals, vec!["dev".to_string()]);
    }
}
