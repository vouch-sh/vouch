// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 types (RFC 7643).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// SCIM error response (RFC 7644 Section 3.12).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            status: status.to_string(),
            scim_type: None,
            detail: detail.into(),
        }
    }

    pub fn with_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }
}

/// SCIM list response (RFC 7644 Section 3.4.2).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub items_per_page: usize,
    pub start_index: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// SCIM User resource (RFC 7643 Section 4.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<ScimEmail>>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

fn default_true() -> bool {
    true
}

/// SCIM Name component (RFC 7643 Section 4.1.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

/// SCIM Email component (RFC 7643 Section 4.1.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
}

/// SCIM Meta component (RFC 7643 Section 3.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<Timestamp>,
    pub location: String,
}

/// SCIM Patch operation request (RFC 7644 Section 3.5.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchRequest {
    #[allow(dead_code)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOp>,
}

/// SCIM Patch operation type (RFC 7644 Section 3.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScimPatchOpType {
    /// Replace existing attribute value(s).
    Replace,
    /// Add attribute value(s).
    Add,
    /// Remove attribute value(s).
    Remove,
}

/// SCIM Patch operation item.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOp {
    pub op: ScimPatchOpType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM Service Provider Configuration (RFC 7643 Section 5).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimServiceProviderConfig {
    pub schemas: Vec<String>,
    pub documentation_uri: String,
    pub patch: ScimSupported,
    pub bulk: ScimBulkConfig,
    pub filter: ScimFilterConfig,
    pub change_password: ScimSupported,
    pub sort: ScimSupported,
    pub etag: ScimSupported,
    pub authentication_schemes: Vec<ScimAuthScheme>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimSupported {
    pub supported: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimBulkConfig {
    pub supported: bool,
    pub max_operations: i32,
    pub max_payload_size: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimFilterConfig {
    pub supported: bool,
    pub max_results: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimAuthScheme {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub spec_uri: String,
}

/// SCIM Schema definition (RFC 7643 Section 7).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimSchema {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attributes: Vec<ScimAttribute>,
}

/// SCIM Attribute definition (RFC 7643 Section 7).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimAttribute {
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub multi_valued: bool,
    pub required: bool,
    pub case_exact: bool,
    pub mutability: String,
    pub returned: String,
    pub uniqueness: String,
}

/// SCIM Resource Type definition (RFC 7643 Section 6).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimResourceType {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub description: String,
    pub schema: String,
}

/// Query parameters for listing users/groups (RFC 7644 Section 3.4.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListQuery {
    pub start_index: Option<usize>,
    pub count: Option<usize>,
    pub filter: Option<String>,
}

/// SCIM Group resource (RFC 7643 Section 4.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ScimGroupMember>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

/// SCIM Group member reference (RFC 7643 Section 8.7.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}
