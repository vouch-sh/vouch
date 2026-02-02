// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 API handlers (RFC 7643/7644).
//!
//! Implements user provisioning for enterprise identity providers.

use aws_lc_rs::digest::{self, SHA256};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use crate::db;

// ============================================================================
// SCIM Types
// ============================================================================

/// SCIM error response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimError {
    fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            status: status.to_string(),
            scim_type: None,
            detail: detail.into(),
        }
    }

    fn with_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }
}

/// SCIM list response.
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

/// SCIM User resource.
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

/// SCIM Name component.
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

/// SCIM Email component.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
}

/// SCIM Meta component.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    pub location: String,
}

/// SCIM Patch operation.
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

/// SCIM Service Provider Config.
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

/// SCIM Schema definition.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimSchema {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attributes: Vec<ScimAttribute>,
}

/// SCIM Attribute definition.
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

/// SCIM Resource Type definition.
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

/// Query parameters for listing users.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListQuery {
    pub start_index: Option<usize>,
    pub count: Option<usize>,
    pub filter: Option<String>,
}

// ============================================================================
// Authentication
// ============================================================================

/// Extract and validate SCIM bearer token.
async fn authenticate_scim(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ScimError>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Missing Authorization header")),
            )
        })?;

    // Case-insensitive check for "Bearer " prefix, extract token safely
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid Authorization header format")),
            )
        })?;
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Verify token exists and is valid
    let token_record = db::get_scim_token_by_hash(&state.db, &token_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Database error")),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid token")),
            )
        })?;

    // Check expiration
    if let Some(expires_at) = &token_record.expires_at
        && expires_at.to_jiff() < jiff::Timestamp::now()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ScimError::new(401, "Token expired")),
        ));
    }

    // Update last_used_at
    if let Err(e) = db::update_scim_token_last_used(&state.db, &token_record.id).await {
        tracing::warn!("Failed to update SCIM token last_used_at: {e}");
    }

    Ok(token_record.id)
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /scim/v2/ServiceProviderConfig
pub async fn service_provider_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = state.config.base_url();

    Json(ScimServiceProviderConfig {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string()],
        documentation_uri: format!("{base_url}/docs/scim"),
        patch: ScimSupported { supported: true },
        bulk: ScimBulkConfig {
            supported: false,
            max_operations: 0,
            max_payload_size: 0,
        },
        filter: ScimFilterConfig {
            supported: true,
            max_results: 100,
        },
        change_password: ScimSupported { supported: false },
        sort: ScimSupported { supported: false },
        etag: ScimSupported { supported: false },
        authentication_schemes: vec![ScimAuthScheme {
            name: "OAuth Bearer Token".to_string(),
            description: "Authentication scheme using the OAuth Bearer Token Standard".to_string(),
            auth_type: "oauthbearertoken".to_string(),
            spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
        }],
    })
}

/// GET /scim/v2/Schemas
pub async fn schemas() -> impl IntoResponse {
    let user_schema = ScimSchema {
        id: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
        name: "User".to_string(),
        description: "User Account".to_string(),
        attributes: vec![
            ScimAttribute {
                name: "userName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                required: true,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "server".to_string(),
            },
            ScimAttribute {
                name: "name".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: false,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
            ScimAttribute {
                name: "emails".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
            ScimAttribute {
                name: "active".to_string(),
                attr_type: "boolean".to_string(),
                multi_valued: false,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
        ],
    };

    let group_schema = ScimSchema {
        id: "urn:ietf:params:scim:schemas:core:2.0:Group".to_string(),
        name: "Group".to_string(),
        description: "Group".to_string(),
        attributes: vec![
            ScimAttribute {
                name: "displayName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                required: true,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "server".to_string(),
            },
            ScimAttribute {
                name: "members".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
        ],
    };

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 2,
        items_per_page: 2,
        start_index: 1,
        resources: vec![user_schema, group_schema],
    })
}

/// GET /scim/v2/ResourceTypes
pub async fn resource_types(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = state.config.base_url();

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 2,
        items_per_page: 2,
        start_index: 1,
        resources: vec![
            ScimResourceType {
                schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ResourceType".to_string()],
                id: "User".to_string(),
                name: "User".to_string(),
                endpoint: format!("{base_url}/scim/v2/Users"),
                description: "User Account".to_string(),
                schema: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
            },
            ScimResourceType {
                schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ResourceType".to_string()],
                id: "Group".to_string(),
                name: "Group".to_string(),
                endpoint: format!("{base_url}/scim/v2/Groups"),
                description: "Group".to_string(),
                schema: "urn:ietf:params:scim:schemas:core:2.0:Group".to_string(),
            },
        ],
    })
}

/// GET /scim/v2/Users
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    let start_index = query.start_index.unwrap_or(1);
    let count = query.count.unwrap_or(100).min(100);

    // Get users from database
    let users =
        match db::list_scim_users(&state.db, query.filter.as_deref(), start_index, count).await {
            Ok(users) => users,
            Err(e) => {
                tracing::error!("Failed to list users: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ScimError::new(500, "Failed to list users")),
                )
                    .into_response();
            }
        };

    let total = match db::count_scim_users(&state.db, query.filter.as_deref()).await {
        Ok(count) => count,
        Err(_) => users.len(),
    };

    let base_url = state.config.base_url();
    let resources: Vec<ScimUser> = users
        .into_iter()
        .map(|u| db_user_to_scim(&base_url, u))
        .collect();

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "list",
        "User",
        "*",
        Some(&token_id),
        Some(&format!("{{\"count\": {}}}", resources.len())),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        items_per_page: resources.len(),
        start_index,
        resources,
    })
    .into_response()
}

/// POST /scim/v2/Users
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(user): Json<ScimUser>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Extract email from userName or emails
    let email = if user.user_name.contains('@') {
        user.user_name.clone()
    } else if let Some(emails) = &user.emails {
        emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| emails.first())
            .map(|e| e.value.clone())
            .unwrap_or_else(|| user.user_name.clone())
    } else {
        user.user_name.clone()
    };

    // Extract name
    let name = user.name.as_ref().and_then(|n| {
        n.formatted
            .clone()
            .or_else(|| match (&n.given_name, &n.family_name) {
                (Some(g), Some(f)) => Some(format!("{g} {f}")),
                (Some(g), None) => Some(g.clone()),
                (None, Some(f)) => Some(f.clone()),
                (None, None) => None,
            })
    });

    // Create user
    let db_user = match db::create_scim_user(
        &state.db,
        &email,
        name.as_deref(),
        user.external_id.as_deref(),
        user.active,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to create user: {e}");
            // Check if it's a uniqueness constraint
            let detail = if e.to_string().contains("UNIQUE") {
                "User already exists"
            } else {
                "Failed to create user"
            };
            return (
                StatusCode::CONFLICT,
                Json(ScimError::new(409, detail).with_type("uniqueness")),
            )
                .into_response();
        }
    };

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "create",
        "User",
        &db_user.id,
        Some(&token_id),
        Some(&format!("{{\"email\": \"{}\"}}", email)),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    let base_url = state.config.base_url();
    let scim_user = db_user_to_scim(&base_url, db_user);

    (StatusCode::CREATED, Json(scim_user)).into_response()
}

/// GET /scim/v2/Users/:id
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate
    if let Err((status, json)) = authenticate_scim(&state, &headers).await {
        return (status, json).into_response();
    }

    let user = match db::get_scim_user(&state.db, &id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response();
        }
    };

    let base_url = state.config.base_url();
    Json(db_user_to_scim(&base_url, user)).into_response()
}

/// PATCH /scim/v2/Users/:id
pub async fn patch_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchRequest>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Get existing user
    let user = match db::get_scim_user(&state.db, &id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response();
        }
    };

    // Apply patch operations
    let mut active = user.active;
    let mut name = user.name.clone();
    let mut external_id = user.external_id.clone();
    let mut deactivated = false;

    for op in &patch.operations {
        match op.op {
            ScimPatchOpType::Replace => {
                if let Some(path) = &op.path {
                    match path.as_str() {
                        "active" => {
                            if let Some(val) = &op.value {
                                let new_active = val.as_bool().unwrap_or(true);
                                if active && !new_active {
                                    deactivated = true;
                                }
                                active = new_active;
                            }
                        }
                        "name.formatted" | "displayName" => {
                            if let Some(val) = &op.value {
                                name = val.as_str().map(String::from);
                            }
                        }
                        "externalId" => {
                            if let Some(val) = &op.value {
                                external_id = val.as_str().map(String::from);
                            }
                        }
                        _ => {}
                    }
                } else if let Some(val) = &op.value {
                    // Replace entire resource
                    if let Some(a) = val.get("active").and_then(|v| v.as_bool()) {
                        if active && !a {
                            deactivated = true;
                        }
                        active = a;
                    }
                    if let Some(n) = val
                        .get("name")
                        .and_then(|v| v.get("formatted"))
                        .and_then(|v| v.as_str())
                    {
                        name = Some(n.to_string());
                    }
                    if let Some(e) = val.get("externalId").and_then(|v| v.as_str()) {
                        external_id = Some(e.to_string());
                    }
                }
            }
            ScimPatchOpType::Add => {
                // Similar logic for add operations
                if let Some(path) = &op.path
                    && path == "active"
                    && let Some(val) = &op.value
                {
                    let new_active = val.as_bool().unwrap_or(true);
                    if active && !new_active {
                        deactivated = true;
                    }
                    active = new_active;
                }
            }
            ScimPatchOpType::Remove => {
                // Remove operations
                if let Some(path) = &op.path
                    && path == "externalId"
                {
                    external_id = None;
                }
            }
        }
    }

    // Update user in database
    if let Err(e) = db::update_scim_user(
        &state.db,
        &id,
        name.as_deref(),
        external_id.as_deref(),
        active,
    )
    .await
    {
        tracing::error!("Failed to update user: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to update user")),
        )
            .into_response();
    }

    // If user was deactivated, invalidate all their sessions and revoke SSH certificates
    if deactivated {
        tracing::info!(
            "User {} deactivated via SCIM, invalidating sessions and revoking SSH certificates",
            id
        );
        if let Err(e) = db::delete_sessions_for_user(&state.db, &id).await {
            tracing::error!("Failed to delete sessions for deactivated user: {e}");
        }
        // Revoke all SSH certificates for this user
        if let Err(e) = db::revoke_all_ssh_certificates_for_user(
            &state.db,
            &id,
            Some("User deactivated via SCIM"),
            Some("scim"),
        )
        .await
        {
            tracing::error!("Failed to revoke SSH certificates for deactivated user: {e}");
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "update",
        "User",
        &id,
        Some(&token_id),
        Some(&format!(
            "{{\"active\": {}, \"deactivated\": {}}}",
            active, deactivated
        )),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    // Return updated user
    let updated = match db::get_scim_user(&state.db, &id).await {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get updated user")),
            )
                .into_response();
        }
    };

    let base_url = state.config.base_url();
    Json(db_user_to_scim(&base_url, updated)).into_response()
}

/// DELETE /scim/v2/Users/:id
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Check user exists
    let user = match db::get_scim_user(&state.db, &id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response();
        }
    };

    // Delete all sessions first (immediate invalidation)
    tracing::info!(
        "Deleting user {} ({}) via SCIM, invalidating sessions and revoking SSH certificates",
        id,
        user.email
    );
    if let Err(e) = db::delete_sessions_for_user(&state.db, &id).await {
        tracing::error!("Failed to delete sessions: {e}");
    }

    // Revoke all SSH certificates for this user
    if let Err(e) = db::revoke_all_ssh_certificates_for_user(
        &state.db,
        &id,
        Some("User deleted via SCIM"),
        Some("scim"),
    )
    .await
    {
        tracing::error!("Failed to revoke SSH certificates for deleted user: {e}");
    }

    // Delete user (cascades to authenticators)
    if let Err(e) = db::delete_user(&state.db, &id).await {
        tracing::error!("Failed to delete user: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to delete user")),
        )
            .into_response();
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "delete",
        "User",
        &id,
        Some(&token_id),
        Some(&format!("{{\"email\": \"{}\"}}", user.email)),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    StatusCode::NO_CONTENT.into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Convert database user to SCIM user.
fn db_user_to_scim(base_url: &str, user: db::ScimUserRecord) -> ScimUser {
    ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: Some(user.id.clone()),
        external_id: user.external_id,
        user_name: user.email.clone(),
        name: user.name.map(|n| ScimName {
            formatted: Some(n),
            family_name: None,
            given_name: None,
        }),
        emails: Some(vec![ScimEmail {
            value: user.email,
            primary: true,
            email_type: Some("work".to_string()),
        }]),
        active: user.active,
        meta: Some(ScimMeta {
            resource_type: "User".to_string(),
            created: user.created_at.to_jiff().to_string(),
            last_modified: Some(user.created_at.to_jiff().to_string()),
            location: format!("{base_url}/scim/v2/Users/{}", user.id),
        }),
    }
}

// ============================================================================
// SCIM Groups (RFC 7643)
// ============================================================================

/// SCIM Group resource.
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

/// SCIM Group member reference.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// GET /scim/v2/Groups
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    let start_index = query.start_index.unwrap_or(1);
    let count = query.count.unwrap_or(100).min(100);

    // Get groups from database
    let groups =
        match db::list_scim_groups(&state.db, query.filter.as_deref(), start_index, count).await {
            Ok(groups) => groups,
            Err(e) => {
                tracing::error!("Failed to list groups: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ScimError::new(500, "Failed to list groups")),
                )
                    .into_response();
            }
        };

    let total = match db::count_scim_groups(&state.db, query.filter.as_deref()).await {
        Ok(count) => count,
        Err(_) => groups.len(),
    };

    let base_url = state.config.base_url();
    let mut resources = Vec::new();
    for g in groups {
        let members = get_group_members_scim(&state.db, &base_url, &g.id).await;
        resources.push(db_group_to_scim(&base_url, g, members));
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "list",
        "Group",
        "*",
        Some(&token_id),
        Some(&format!("{{\"count\": {}}}", resources.len())),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        items_per_page: resources.len(),
        start_index,
        resources,
    })
    .into_response()
}

/// POST /scim/v2/Groups
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(group): Json<ScimGroup>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Create group
    let db_group =
        match db::create_scim_group(&state.db, &group.display_name, group.external_id.as_deref())
            .await
        {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("Failed to create group: {e}");
                let detail = if e.to_string().contains("UNIQUE") {
                    "Group already exists"
                } else {
                    "Failed to create group"
                };
                return (
                    StatusCode::CONFLICT,
                    Json(ScimError::new(409, detail).with_type("uniqueness")),
                )
                    .into_response();
            }
        };

    // Add members if provided
    if let Some(members) = &group.members {
        for member in members {
            if let Err(e) = db::add_scim_group_member(&state.db, &db_group.id, &member.value).await
            {
                tracing::warn!("Failed to add member {} to group: {e}", member.value);
            }
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "create",
        "Group",
        &db_group.id,
        Some(&token_id),
        Some(&format!(
            "{{\"displayName\": \"{}\"}}",
            db_group.display_name
        )),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    let base_url = state.config.base_url();
    let members = get_group_members_scim(&state.db, &base_url, &db_group.id).await;
    let scim_group = db_group_to_scim(&base_url, db_group, members);

    (StatusCode::CREATED, Json(scim_group)).into_response()
}

/// GET /scim/v2/Groups/:id
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate
    if let Err((status, json)) = authenticate_scim(&state, &headers).await {
        return (status, json).into_response();
    }

    let group = match db::get_scim_group(&state.db, &id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    let base_url = state.config.base_url();
    let members = get_group_members_scim(&state.db, &base_url, &group.id).await;
    Json(db_group_to_scim(&base_url, group, members)).into_response()
}

/// PATCH /scim/v2/Groups/:id
pub async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchRequest>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Get existing group
    let group = match db::get_scim_group(&state.db, &id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    // Apply patch operations
    let mut display_name = group.display_name.clone();
    let mut external_id = group.external_id.clone();

    for op in &patch.operations {
        match op.op {
            ScimPatchOpType::Replace => {
                if let Some(path) = &op.path {
                    match path.as_str() {
                        "displayName" => {
                            if let Some(val) = &op.value
                                && let Some(s) = val.as_str()
                            {
                                display_name = s.to_string();
                            }
                        }
                        "externalId" => {
                            if let Some(val) = &op.value {
                                external_id = val.as_str().map(String::from);
                            }
                        }
                        "members" => {
                            // Replace all members
                            if let Some(val) = &op.value
                                && let Some(arr) = val.as_array()
                            {
                                let user_ids: Vec<String> = arr
                                    .iter()
                                    .filter_map(|v| {
                                        v.get("value").and_then(|v| v.as_str()).map(String::from)
                                    })
                                    .collect();
                                if let Err(e) =
                                    db::replace_scim_group_members(&state.db, &id, &user_ids).await
                                {
                                    tracing::error!("Failed to replace group members: {e}");
                                }
                            }
                        }
                        _ => {}
                    }
                } else if let Some(val) = &op.value {
                    // Replace entire resource
                    if let Some(n) = val.get("displayName").and_then(|v| v.as_str()) {
                        display_name = n.to_string();
                    }
                    if let Some(e) = val.get("externalId").and_then(|v| v.as_str()) {
                        external_id = Some(e.to_string());
                    }
                }
            }
            ScimPatchOpType::Add => {
                if let Some(path) = &op.path
                    && path == "members"
                    && let Some(val) = &op.value
                {
                    // Add members
                    if let Some(arr) = val.as_array() {
                        for member in arr {
                            if let Some(user_id) = member.get("value").and_then(|v| v.as_str())
                                && let Err(e) =
                                    db::add_scim_group_member(&state.db, &id, user_id).await
                            {
                                tracing::warn!("Failed to add member: {e}");
                            }
                        }
                    }
                }
            }
            ScimPatchOpType::Remove => {
                if let Some(path) = &op.path {
                    if path == "externalId" {
                        external_id = None;
                    } else if path.starts_with("members")
                        && let Some(user_id) = parse_member_filter(path)
                        && let Err(e) = db::remove_scim_group_member(&state.db, &id, &user_id).await
                    {
                        tracing::warn!("Failed to remove member: {e}");
                    }
                }
            }
        }
    }

    // Update group in database
    if (display_name != group.display_name || external_id != group.external_id)
        && let Err(e) =
            db::update_scim_group(&state.db, &id, Some(&display_name), external_id.as_deref()).await
    {
        tracing::error!("Failed to update group: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to update group")),
        )
            .into_response();
    }

    // Audit log
    if let Err(e) =
        db::insert_scim_audit(&state.db, "update", "Group", &id, Some(&token_id), None).await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    // Return updated group
    let updated = match db::get_scim_group(&state.db, &id).await {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get updated group")),
            )
                .into_response();
        }
    };

    let base_url = state.config.base_url();
    let members = get_group_members_scim(&state.db, &base_url, &updated.id).await;
    Json(db_group_to_scim(&base_url, updated, members)).into_response()
}

/// DELETE /scim/v2/Groups/:id
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate
    let token_id = match authenticate_scim(&state, &headers).await {
        Ok(id) => id,
        Err((status, json)) => return (status, json).into_response(),
    };

    // Check group exists
    let group = match db::get_scim_group(&state.db, &id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    // Delete group (cascades to memberships)
    if let Err(e) = db::delete_scim_group(&state.db, &id).await {
        tracing::error!("Failed to delete group: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to delete group")),
        )
            .into_response();
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.db,
        "delete",
        "Group",
        &id,
        Some(&token_id),
        Some(&format!("{{\"displayName\": \"{}\"}}", group.display_name)),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Helper to get group members in SCIM format.
async fn get_group_members_scim(
    db: &crate::db::Pool,
    base_url: &str,
    group_id: &str,
) -> Vec<ScimGroupMember> {
    match db::get_scim_group_members(db, group_id).await {
        Ok(users) => users
            .into_iter()
            .map(|u| ScimGroupMember {
                value: u.id.clone(),
                ref_url: Some(format!("{base_url}/scim/v2/Users/{}", u.id)),
                display: Some(u.email),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Convert database group to SCIM group.
fn db_group_to_scim(
    base_url: &str,
    group: db::ScimGroupRecord,
    members: Vec<ScimGroupMember>,
) -> ScimGroup {
    ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()],
        id: Some(group.id.clone()),
        external_id: group.external_id,
        display_name: group.display_name,
        members: if members.is_empty() {
            None
        } else {
            Some(members)
        },
        meta: Some(ScimMeta {
            resource_type: "Group".to_string(),
            created: group.created_at.to_jiff().to_string(),
            last_modified: Some(group.updated_at.to_jiff().to_string()),
            location: format!("{base_url}/scim/v2/Groups/{}", group.id),
        }),
    }
}

/// Parse members filter path like "members[value eq \"user-id\"]".
fn parse_member_filter(path: &str) -> Option<String> {
    // Simple parser for members[value eq "user-id"]
    if let Some(start) = path.find("value eq \"") {
        let start_idx = start + 10;
        if let Some(rest) = path.get(start_idx..)
            && let Some(end) = rest.find('"')
        {
            return rest.get(..end).map(String::from);
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // ========================================================================
    // RFC 7644 Section 4 - Service Provider Configuration Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_service_provider_config() {
        // RFC 7644 Section 4: ServiceProviderConfig endpoint
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/scim/v2/ServiceProviderConfig", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let config: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // Required fields per RFC 7643/7644
        assert!(config.get("schemas").is_some(), "schemas is required");
        assert!(config.get("patch").is_some(), "patch config is required");
        assert!(config.get("bulk").is_some(), "bulk config is required");
        assert!(config.get("filter").is_some(), "filter config is required");
        assert!(
            config.get("changePassword").is_some(),
            "changePassword config is required"
        );
        assert!(config.get("sort").is_some(), "sort config is required");
        assert!(config.get("etag").is_some(), "etag config is required");
        assert!(
            config.get("authenticationSchemes").is_some(),
            "authenticationSchemes is required"
        );

        // Verify schemas array contains correct URN
        let schemas = config["schemas"].as_array().expect("schemas is an array");
        assert!(
            schemas
                .iter()
                .any(|s| s == "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
        );
    }

    #[tokio::test]
    async fn test_rfc7644_schemas_endpoint() {
        // RFC 7644 Section 4: Schemas endpoint returns User schema
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/scim/v2/Schemas", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // Verify ListResponse format
        let schemas = response["schemas"].as_array().expect("schemas array");
        assert!(
            schemas
                .iter()
                .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:ListResponse")
        );

        // Verify User schema is present
        let resources = response["Resources"].as_array().expect("Resources array");
        assert!(
            resources
                .iter()
                .any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"),
            "User schema should be present"
        );
    }

    // ========================================================================
    // RFC 7644 Section 2 - Authentication Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_auth_required() {
        // RFC 7644 Section 2: Authentication is required
        let (app, _state) = test_app().await;

        // Try to list users without token
        let (status, body) = http_get(&app, "/scim/v2/Users", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(
            error.get("schemas").is_some(),
            "SCIM error should have schemas"
        );
        assert!(
            error.get("detail").is_some(),
            "SCIM error should have detail"
        );
    }

    #[tokio::test]
    async fn test_rfc7644_auth_invalid_token() {
        // Invalid token should return 401
        let (app, _state) = test_app().await;

        let (status, body) = http_get(
            &app,
            "/scim/v2/Users",
            &[("Authorization", "Bearer invalid_token")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["status"], "401");
    }

    // ========================================================================
    // RFC 7643 Section 4.1 - User Resource Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7643_create_user_requires_username() {
        // RFC 7643 Section 4.1: userName is REQUIRED for User resource
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-create-user").await;

        // Create user with valid userName
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "test@example.com", "active": true}"#,
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(user.get("id").is_some(), "Created user should have id");
        assert_eq!(user["userName"], "test@example.com");
    }

    #[tokio::test]
    async fn test_rfc7644_create_user_conflict() {
        // RFC 7644 Section 3.3: Duplicate user returns 409 Conflict
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-conflict").await;
        let auth_header = format!("Bearer {}", token);

        // Create first user
        let (status, _) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@example.com"}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Try to create duplicate user
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@example.com"}"#,
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["status"], "409");
        assert_eq!(error["scimType"], "uniqueness");
    }

    // ========================================================================
    // RFC 7644 Section 3.4.1 - GET User Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_get_user_by_id() {
        // RFC 7644 Section 3.4.1: GET user by ID
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-get-user").await;
        let auth_header = format!("Bearer {}", token);

        // Create a user first
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "gettest@example.com"}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let user_id = created["id"].as_str().expect("user id");

        // Get the user by ID
        let (status, body) = http_get(
            &app,
            &format!("/scim/v2/Users/{}", user_id),
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(user["id"], user_id);
        assert_eq!(user["userName"], "gettest@example.com");
    }

    #[tokio::test]
    async fn test_rfc7644_get_user_not_found() {
        // RFC 7644 Section 3.4.1: Non-existent user returns 404
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-not-found").await;

        let (status, body) = http_get(
            &app,
            "/scim/v2/Users/nonexistent-user-id",
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["status"], "404");
    }

    // ========================================================================
    // RFC 7644 Section 3.4.2 - List Users Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_list_users_pagination() {
        // RFC 7644 Section 3.4.2: Pagination with startIndex and count
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-pagination").await;
        let auth_header = format!("Bearer {}", token);

        // Create several users
        for i in 1..=5 {
            let _ = http_post_json(
                &app,
                "/scim/v2/Users",
                &format!(
                    r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "page{}@example.com"}}"#,
                    i
                ),
                &[("Authorization", &auth_header)],
            )
            .await;
        }

        // List with pagination
        let (status, body) = http_get(
            &app,
            "/scim/v2/Users?startIndex=1&count=2",
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // Verify ListResponse format
        assert_eq!(response["startIndex"], 1);
        assert!(response["itemsPerPage"].as_u64().unwrap() <= 2);
        assert!(response["totalResults"].as_u64().unwrap() >= 5);
    }

    #[tokio::test]
    async fn test_rfc7644_list_users_filter() {
        // RFC 7644 Section 3.4.2: Filter users by userName
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-filter").await;
        let auth_header = format!("Bearer {}", token);

        // Create users
        let _ = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "filtertest@example.com"}"#,
            &[("Authorization", &auth_header)],
        )
        .await;

        // Filter by userName
        let (status, body) = http_get(
            &app,
            "/scim/v2/Users?filter=userName%20eq%20%22filtertest@example.com%22",
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let resources = response["Resources"].as_array().expect("Resources array");
        assert!(!resources.is_empty());
    }

    // ========================================================================
    // RFC 7644 Section 3.5.2 - PATCH User Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_patch_user_deactivate() {
        // RFC 7644 Section 3.5.2: PATCH to deactivate user
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-patch-deactivate").await;
        let auth_header = format!("Bearer {}", token);

        // Create an active user
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "deactivate@example.com", "active": true}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let user_id = created["id"].as_str().expect("user id");

        // PATCH to deactivate
        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/scim/v2/Users/{}", user_id),
            Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#.to_string()),
            &[
                ("Authorization", &auth_header),
                ("Content-Type", "application/json"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(updated["active"], false);
    }

    // ========================================================================
    // RFC 7644 Section 3.6 - DELETE User Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_delete_user() {
        // RFC 7644 Section 3.6: DELETE removes user
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-delete").await;
        let auth_header = format!("Bearer {}", token);

        // Create a user
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "todelete@example.com"}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let user_id = created["id"].as_str().expect("user id");

        // Delete the user
        let (status, _body) = http_request(
            &app,
            "DELETE",
            &format!("/scim/v2/Users/{}", user_id),
            None,
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify user no longer exists
        let (status, _body) = http_get(
            &app,
            &format!("/scim/v2/Users/{}", user_id),
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ========================================================================
    // RFC 7644 Section 3.12 - Error Response Format Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc7644_error_format() {
        // RFC 7644 Section 3.12: Error response format
        let (app, state) = test_app().await;

        let token = create_test_scim_token(&state.db, "test-error-format").await;

        // Request non-existent user to get an error
        let (status, body) = http_get(
            &app,
            "/scim/v2/Users/nonexistent",
            &[("Authorization", &format!("Bearer {}", token))],
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // RFC 7644 Section 3.12: Error MUST include schemas
        let schemas = error["schemas"].as_array().expect("schemas array");
        assert!(
            schemas
                .iter()
                .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:Error")
        );

        // MUST include status and detail
        assert!(error.get("status").is_some(), "Error must have status");
        assert!(error.get("detail").is_some(), "Error must have detail");
    }
}
