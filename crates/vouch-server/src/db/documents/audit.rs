// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit event data payloads for the `audit_events.data` JSON column.
//!
//! These are serialized to JSON and stored in the unencrypted audit table.
//! They are NOT `DocumentType` implementations — they're the payload
//! inside `AuditStore::insert_event(data_json)`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::db::audit::AuditEventKind;

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
