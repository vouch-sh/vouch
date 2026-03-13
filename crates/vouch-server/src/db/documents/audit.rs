// SPDX-License-Identifier: BUSL-1.1
//! Audit event data payloads for the `audit_events.data` JSON column.
//!
//! These are serialized to JSON and stored in the unencrypted audit table.
//! They are NOT `DocumentType` implementations — they're the payload
//! inside `AuditStore::insert_event(data_json)`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Data payload for OAuth usage audit events.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUsageData {
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
pub struct ScimAuditData {
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
    pub actor_token_id: Option<String>,
    pub details: Option<String>,
}

/// Data payload for AWS IdC credential audit events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdcCredentialAuditData {
    pub event_type: String,
    pub org_id: Option<String>,
    pub authenticator_id: Option<String>,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
}
