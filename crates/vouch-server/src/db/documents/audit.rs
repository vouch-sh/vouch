// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit event data payloads for the `audit_events.data` JSON column.
//!
//! These are serialized to JSON and stored in the unencrypted audit table.
//! They are NOT `DocumentType` implementations — they're the payload
//! inside `AuditStore::insert_event(data_json)`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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

/// Data payload for GitHub credential audit events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GitHubCredentialAuditData {
    pub event_type: String,
    pub org_id: Option<String>,
    pub installation_id: Option<i64>,
    pub session_id: Option<String>,
    pub authenticator_id: Option<String>,
    pub repositories: Option<Vec<String>>,
    pub permissions: Option<HashMap<String, String>>,
    pub token_expires_at: Option<String>,
    pub success: bool,
    pub error_code: Option<String>,
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

/// Data payload for AWS credential (OIDC token issuance) audit events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AwsCredentialAuditData {
    pub event_type: String,
    pub org_id: Option<String>,
    pub authenticator_id: Option<String>,
    /// IAM role ARN the token was pinned to via the
    /// `https://aws.amazon.com/roles` claim; `None` for unpinned tokens.
    pub role_arn: Option<String>,
    /// AI coding agent from the DPoP `source` claim (e.g. "claude-code");
    /// mirrors the `vouch:Agent` session tag minted into the token.
    pub agent: Option<String>,
    pub token_expires_at: Option<String>,
    pub success: bool,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// Data payload for SSH certificate issuance audit events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SshCredentialAuditData {
    pub event_type: String,
    pub org_id: Option<String>,
    pub authenticator_id: Option<String>,
    /// Certificate serial number, for correlation with the KRL.
    pub serial: u64,
    pub principals: Vec<String>,
    /// AI coding agent from the DPoP `source` claim (e.g. "claude-code").
    pub agent: Option<String>,
    /// Certificate expiry (RFC 3339).
    pub cert_expires_at: Option<String>,
    pub success: bool,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

/// Data payload for RFC 8693 token exchange audit events.
///
/// Client IP and user agent are not recorded: the exchange runs in the
/// services layer, which matches the authorization-code issuance precedent
/// of recording token events without transport metadata.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TokenExchangeAuditData {
    pub event_type: String,
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
    pub success: bool,
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
    fn test_github_audit_data_deserialize_without_asn_fields() {
        let json = r#"{"event_type":"token_issued","success":true}"#;
        let data: GitHubCredentialAuditData = serde_json::from_str(json).unwrap();
        assert_eq!(data.event_type, "token_issued");
        assert!(data.asn.is_none());
        assert!(data.org_name.is_none());
    }

    #[test]
    fn test_github_audit_data_roundtrip_with_asn() {
        let data = GitHubCredentialAuditData {
            event_type: "token_issued".to_string(),
            asn: Some(3320),
            org_name: Some("DTAG".to_string()),
            ..GitHubCredentialAuditData::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: GitHubCredentialAuditData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.asn, Some(3320));
        assert_eq!(back.org_name.as_deref(), Some("DTAG"));
    }

    #[test]
    fn test_aws_audit_data_deserialize_without_geo_fields() {
        let json = r#"{"event_type":"token_issued","success":true}"#;
        let data: AwsCredentialAuditData = serde_json::from_str(json).unwrap();
        assert_eq!(data.event_type, "token_issued");
        assert!(data.role_arn.is_none());
        assert!(data.asn.is_none());
        assert!(data.org_name.is_none());
    }

    #[test]
    fn test_ssh_audit_data_roundtrip() {
        let data = SshCredentialAuditData {
            event_type: "certificate_issued".to_string(),
            serial: u64::MAX,
            principals: vec!["dev".to_string(), "dev@example.com".to_string()],
            agent: Some("claude-code".to_string()),
            ..SshCredentialAuditData::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SshCredentialAuditData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.serial, u64::MAX);
        assert_eq!(back.principals.len(), 2);
        assert_eq!(back.agent.as_deref(), Some("claude-code"));
        assert!(back.asn.is_none());
    }

    #[test]
    fn test_token_exchange_audit_data_roundtrip() {
        let data = TokenExchangeAuditData {
            event_type: "token_issued".to_string(),
            client_id: "client-1".to_string(),
            audience: Some("sts.amazonaws.com".to_string()),
            scope: None,
            issued_token_type: "id_token".to_string(),
            token_expires_at: Some("2026-07-14T00:00:00Z".to_string()),
            success: true,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: TokenExchangeAuditData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.client_id, "client-1");
        assert_eq!(back.audience.as_deref(), Some("sts.amazonaws.com"));
        assert_eq!(back.issued_token_type, "id_token");
    }

    #[test]
    fn test_aws_audit_data_roundtrip_with_role_arn() {
        let data = AwsCredentialAuditData {
            event_type: "token_issued".to_string(),
            role_arn: Some("arn:aws:iam::111122223333:role/Example".to_string()),
            agent: Some("claude-code".to_string()),
            asn: Some(15169),
            ..AwsCredentialAuditData::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: AwsCredentialAuditData = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.role_arn.as_deref(),
            Some("arn:aws:iam::111122223333:role/Example")
        );
        assert_eq!(back.agent.as_deref(), Some("claude-code"));
        assert_eq!(back.asn, Some(15169));
    }
}
