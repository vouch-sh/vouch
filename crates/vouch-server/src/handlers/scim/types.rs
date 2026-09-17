// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 types (RFC 7643).

use super::urn;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// SCIM error response (RFC 7644 Section 3.12).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimError {
    pub(crate) fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec![urn::ERROR.to_string()],
            status: status.to_string(),
            scim_type: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn with_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }
}

/// SCIM list response (RFC 7644 Section 3.4.2).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimListResponse<T> {
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
pub(crate) struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Required (RFC 7643 §4.1.1), but `Option` so a request that omits it
    /// is answered as the schema violation it is — see
    /// `patch::required_attribute` — rather than as unparsable JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
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
pub(crate) struct ScimName {
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
pub(crate) struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
}

/// SCIM Meta component (RFC 7643 Section 3.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimMeta {
    pub resource_type: String,
    pub created: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<Timestamp>,
    pub location: String,
}

/// SCIM Patch operation request (RFC 7644 Section 3.5.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimPatchRequest {
    #[allow(
        dead_code,
        reason = "RFC 7644 schemas field required by spec but unused"
    )]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOp>,
}

/// SCIM Patch operation type (RFC 7644 Section 3.5.2).
///
/// Matched case-insensitively: RFC 7644 spells the values in lowercase without
/// saying whether case matters, and Entra ID sends `Add` and `Replace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScimPatchOpType {
    /// Replace existing attribute value(s).
    Replace,
    /// Add attribute value(s).
    Add,
    /// Remove attribute value(s).
    Remove,
}

impl<'de> Deserialize<'de> for ScimPatchOpType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let op = String::deserialize(deserializer)?;
        [Self::Add, Self::Replace, Self::Remove]
            .into_iter()
            .find(|candidate| {
                let name = match candidate {
                    Self::Add => "add",
                    Self::Replace => "replace",
                    Self::Remove => "remove",
                };
                op.eq_ignore_ascii_case(name)
            })
            .ok_or_else(|| serde::de::Error::unknown_variant(&op, &["add", "replace", "remove"]))
    }
}

/// SCIM Patch operation item.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimPatchOp {
    pub op: ScimPatchOpType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM Service Provider Configuration (RFC 7643 Section 5).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimServiceProviderConfig {
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
pub(crate) struct ScimSupported {
    pub supported: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimBulkConfig {
    pub supported: bool,
    pub max_operations: i32,
    pub max_payload_size: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimFilterConfig {
    pub supported: bool,
    pub max_results: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimAuthScheme {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub spec_uri: String,
}

/// SCIM Schema definition (RFC 7643 Section 7).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimSchema {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attributes: Vec<ScimAttribute>,
}

/// SCIM Attribute definition (RFC 7643 Section 7).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimAttribute {
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
pub(crate) struct ScimResourceType {
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
pub(crate) struct ScimListQuery {
    pub start_index: Option<usize>,
    pub count: Option<usize>,
    pub filter: Option<String>,
}

/// SCIM Group resource (RFC 7643 Section 4.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Required (RFC 7643 §4.2), but `Option` for the same reason as
    /// [`ScimUser::user_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ScimGroupMember>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

/// SCIM Group member reference (RFC 7643 Section 8.7.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimGroupMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}
