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
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
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
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
