// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 User operations (RFC 7644).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::authenticate_scim;
use super::types::{
    ScimEmail, ScimError, ScimListQuery, ScimListResponse, ScimMeta, ScimName, ScimPatchOpType,
    ScimPatchRequest, ScimUser,
};
use crate::AppState;
use crate::db;
use crate::db::{ScimFilterError, ScimScope};
use crate::redact_email;

/// GET /scim/v2/Users (RFC 7644 Section 3.4.2).
///
/// Returns a paginated list of User resources, with optional filtering.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let start_index = query.start_index.unwrap_or(1);
    let count = query.count.unwrap_or(100).min(100);

    if let Err((status, json)) = super::validate_list_params(query.filter.as_deref(), start_index) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersRead) {
        return (status, json).into_response();
    }

    // Get users from database (returns page + total count in one call)
    let (users, total) = match db::list_scim_users(
        &state.store,
        &auth.org_id,
        query.filter.as_deref(),
        start_index,
        count,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if let Some(filter_err) = e.downcast_ref::<ScimFilterError>() {
                let (detail, error_type) = match filter_err {
                    ScimFilterError::UnsupportedOperator(_) => {
                        tracing::debug!("SCIM filter parse error: {e}");
                        ("Invalid filter expression", "invalidFilter")
                    }
                    ScimFilterError::FilterTooBroad => (
                        "Filter is too broad; add a more specific filter",
                        "invalidFilter",
                    ),
                    ScimFilterError::OffsetTooLarge => (
                        "startIndex is too large; maximum supported offset is 10000",
                        "invalidValue",
                    ),
                };
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ScimError::new(400, detail).with_type(error_type)),
                )
                    .into_response();
            }
            tracing::error!("Failed to list users: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to list users")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    let resources: Vec<ScimUser> = users
        .into_iter()
        .map(|u| db_user_to_scim(base_url, u))
        .collect();

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "list",
        "User",
        "*",
        Some(&auth.token_id),
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

/// POST /scim/v2/Users (RFC 7644 Section 3.3).
///
/// Creates a new User resource. Returns 201 Created on success,
/// 409 Conflict if the user already exists (RFC 7644 Section 3.3.1).
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(user): Json<ScimUser>,
) -> Response {
    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    }

    // Extract email from userName or emails (RFC 7643: userName is not
    // required to be an email, so we accept whatever the IdP sends)
    let email = if user.user_name.contains('@') {
        user.user_name.clone()
    } else if let Some(emails) = &user.emails {
        emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| emails.first())
            .map_or_else(|| user.user_name.clone(), |e| e.value.clone())
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
        &state.store,
        Some(&auth.org_id),
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
        &state.audit,
        "create",
        "User",
        &db_user.id,
        Some(&auth.token_id),
        Some(&serde_json::json!({"email": email}).to_string()),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    let base_url = &state.config().base_url;
    let scim_user = db_user_to_scim(base_url, db_user);

    (StatusCode::CREATED, Json(scim_user)).into_response()
}

/// GET /scim/v2/Users/:id (RFC 7644 Section 3.4.1).
///
/// Retrieves a single User resource by ID.
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersRead) {
        return (status, json).into_response();
    }

    let user = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
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

    let base_url = &state.config().base_url;
    Json(db_user_to_scim(base_url, user)).into_response()
}

/// PATCH /scim/v2/Users/:id (RFC 7644 Section 3.5.2).
///
/// Modifies a User resource using SCIM PATCH operations (add, replace, remove).
/// Deactivating a user invalidates all sessions and revokes SSH certificates.
#[expect(
    clippy::too_many_lines,
    reason = "SCIM PATCH operation handles add/remove/replace across all user fields"
)]
pub async fn patch_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchRequest>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    }

    // Get existing user
    let user = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
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
                        _ => {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(
                                    ScimError::new(400, "Unsupported attribute path")
                                        .with_type("invalidPath"),
                                ),
                            )
                                .into_response();
                        }
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
    match db::update_scim_user(
        &state.store,
        &id,
        &auth.org_id,
        name.as_deref(),
        external_id.as_deref(),
        active,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to update user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to update user")),
            )
                .into_response();
        }
    }

    // If user was deactivated, invalidate all their sessions and revoke SSH certificates
    if deactivated {
        tracing::info!(
            "User {} deactivated via SCIM, invalidating sessions and revoking SSH certificates",
            id
        );
        if let Err(e) = db::delete_sessions_for_user(&state.store, &id).await {
            tracing::error!("Failed to delete sessions for deactivated user: {e}");
        } else {
            state.session_cache.invalidate_for_user(&id);
        }
        // Revoke all SSH certificates for this user
        if let Err(e) = db::revoke_all_ssh_certificates_for_user(
            &state.store,
            &id,
            Some("User deactivated via SCIM"),
            Some("scim"),
        )
        .await
        {
            tracing::error!("Failed to revoke SSH certificates for deactivated user: {e}");
        }
        // Clear GitHub refresh token to prevent further API access
        if let Err(e) = db::clear_user_github_refresh_token(&state.store, &id).await {
            tracing::error!("Failed to clear GitHub refresh token for deactivated user: {e}");
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "update",
        "User",
        &id,
        Some(&auth.token_id),
        Some(&serde_json::json!({"active": active, "deactivated": deactivated}).to_string()),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    // Return updated user
    let updated = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get updated user")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    Json(db_user_to_scim(base_url, updated)).into_response()
}

/// DELETE /scim/v2/Users/:id (RFC 7644 Section 3.6).
///
/// Permanently deletes a User resource. Returns 204 No Content on success.
/// All sessions are invalidated and SSH certificates are revoked.
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    };

    // Check user exists
    let user = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
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
        redact_email(&user.email)
    );
    if let Err(e) = db::delete_sessions_for_user(&state.store, &id).await {
        tracing::error!("Failed to delete sessions: {e}");
    } else {
        state.session_cache.invalidate_for_user(&id);
    }

    // Revoke SSH certificates before deleting. If revocation fails,
    // abort — delete_user would destroy the issued cert records,
    // making the certs permanently unrevocable.
    if let Err(e) = db::revoke_all_ssh_certificates_for_user(
        &state.store,
        &id,
        Some("User deleted via SCIM"),
        Some("scim"),
    )
    .await
    {
        tracing::error!("Failed to revoke SSH certificates for deleted user: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to revoke SSH certificates")),
        )
            .into_response();
    }

    // Delete user (cascades to authenticators)
    if let Err(e) = db::delete_user(&state.store, &id).await {
        tracing::error!("Failed to delete user: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to delete user")),
        )
            .into_response();
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "delete",
        "User",
        &id,
        Some(&auth.token_id),
        Some(&serde_json::json!({"email": user.email}).to_string()),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Convert database user to SCIM user.
pub fn db_user_to_scim(base_url: &str, user: db::ScimUserRecord) -> ScimUser {
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
            created: user.created_at,
            last_modified: Some(user.created_at),
            location: format!("{base_url}/scim/v2/Users/{}", user.id),
        }),
    }
}
