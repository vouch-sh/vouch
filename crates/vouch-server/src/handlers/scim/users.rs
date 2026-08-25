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
use super::patch::{Attribute, InvalidValue, apply_patch_op, optional_string};
use super::types::{
    ScimEmail, ScimError, ScimListQuery, ScimListResponse, ScimMeta, ScimName, ScimPatchRequest,
    ScimUser,
};
use super::urn;
use crate::AppState;
use crate::db;
use crate::db::{ScimFilterError, ScimScope};
use crate::redact_email;

/// GET /scim/v2/Users (RFC 7644 Section 3.4.2).
///
/// Returns a paginated list of User resources, with optional filtering.
pub(crate) async fn list_users(
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
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
        total_results: total,
        items_per_page: resources.len(),
        start_index,
        resources,
    })
    .into_response()
}

/// Map a [`db::CreateScimUserError`] onto its SCIM wire response.
///
/// Split from the create handler so every error arm — including the 503
/// backpressure mapping — has a test that triggers it directly.
pub(super) fn create_scim_user_error_response(
    org_id: &str,
    email: &str,
    err: db::CreateScimUserError,
) -> Response {
    match err {
        db::CreateScimUserError::DomainNotOwned => {
            tracing::warn!(
                org_id = %org_id,
                email = %redact_email(email),
                "rejected SCIM user creation: email domain is not verified for this organization"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(
                    ScimError::new(400, "Email domain is not verified for this organization")
                        .with_type("invalidValue"),
                ),
            )
                .into_response()
        }
        db::CreateScimUserError::DuplicateEmail => {
            tracing::debug!(
                org_id = %org_id,
                email = %redact_email(email),
                "rejected SCIM user creation: user already exists"
            );
            (
                StatusCode::CONFLICT,
                Json(ScimError::new(409, "User already exists").with_type("uniqueness")),
            )
                .into_response()
        }
        db::CreateScimUserError::OccConflict => {
            // The org doc is the OCC serialization point for user creation
            // (domain validation version-bumps it), so bulk provisioning or
            // concurrent domain churn can exhaust the retry budget. That is
            // transient backpressure, not a server fault: return 503 with
            // Retry-After — IdP provisioners (Okta, Entra) retry on 503.
            tracing::warn!(
                org_id = %org_id,
                "SCIM user creation exhausted OCC retries (concurrent provisioning or domain churn)"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "1")],
                Json(ScimError::new(
                    503,
                    "Concurrent modification, retry the request",
                )),
            )
                .into_response()
        }
        db::CreateScimUserError::Other(e) => {
            if let Some(resp) = super::invalid_index_value_response(&e) {
                return resp.into_response();
            }
            tracing::error!("Failed to create user: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to create user")),
            )
                .into_response()
        }
    }
}

/// POST /scim/v2/Users (RFC 7644 Section 3.3).
///
/// Creates a new User resource. Returns 201 Created on success,
/// 409 Conflict if the user already exists (RFC 7644 Section 3.3.1).
pub(crate) async fn create_user(
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

    // Extract email from userName or emails. RFC 7643 doesn't require
    // userName to be an email, but Vouch keys users by email — a userName
    // with no '@' and no emails[] fallback is rejected below.
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

    // Shape check only — domain ownership is validated inside
    // `create_scim_user`'s transaction (reading the org doc and
    // version-bumping it via `compare_and_update`), which closes the TOCTOU
    // race with a concurrent `remove_additional_domain` that a standalone
    // pre-check here could not.
    if crate::email::Email::domain_of(&email).is_none() {
        tracing::warn!(
            org_id = %auth.org_id,
            "rejected SCIM user creation: userName is not an email address"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(
                ScimError::new(400, "userName must be an email address").with_type("invalidValue"),
            ),
        )
            .into_response();
    }

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

    // Create user (domain ownership validated inside the transaction)
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
        Err(e) => return create_scim_user_error_response(&auth.org_id, &email, e),
    };

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "create",
        "User",
        &db_user.id,
        Some(&auth.token_id),
        None,
        auth.org_domain.as_deref(),
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
pub(crate) async fn get_user(
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

/// The User fields a PATCH can change, seeded from the stored record.
struct UserPatch {
    active: bool,
    name: Option<String>,
    external_id: Option<String>,
    /// Set when an operation takes `active` from true to false; the handler
    /// then invalidates sessions and revokes the user's credentials.
    deactivated: bool,
}

/// The single-valued User attributes Vouch stores (RFC 7643 §4.1).
/// `displayName` addresses the same stored name as `name.formatted`.
const USER_ATTRIBUTES: &[Attribute<UserPatch>] = &[
    Attribute {
        paths: &["active"],
        set: |user, path, value| {
            // RFC 7643 §2.2 — `active` is a boolean. Coercing a non-boolean
            // (e.g. the string "false") to `true` would silently reactivate
            // a disabled user.
            let Some(active) = value.as_bool() else {
                return Err(InvalidValue::new(format!("{path} must be a boolean")));
            };
            user.deactivated |= user.active && !active;
            user.active = active;
            Ok(())
        },
        // `active` is a stored boolean with no absent state, so a removal
        // has no value to fall back to: either default would change the
        // user's access without the identity provider asking for it.
        remove: |_, path| Err(InvalidValue::new(format!("{path} cannot be removed"))),
    },
    Attribute {
        paths: &["name.formatted", "displayName"],
        set: |user, path, value| {
            user.name = optional_string(path, value)?;
            Ok(())
        },
        remove: |user, _| {
            user.name = None;
            Ok(())
        },
    },
    Attribute {
        paths: &["externalId"],
        set: |user, path, value| {
            user.external_id = optional_string(path, value)?;
            Ok(())
        },
        remove: |user, _| {
            user.external_id = None;
            Ok(())
        },
    },
];

/// PATCH /scim/v2/Users/:id (RFC 7644 Section 3.5.2).
///
/// Modifies a User resource using SCIM PATCH operations (add, replace,
/// remove) applied against [`USER_ATTRIBUTES`]. Deactivating a user
/// invalidates all sessions and revokes SSH certificates.
pub(crate) async fn patch_user(
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
    let mut patched = UserPatch {
        active: user.active,
        name: user.name,
        external_id: user.external_id,
        deactivated: false,
    };

    for op in &patch.operations {
        if let Err(invalid) = apply_patch_op(USER_ATTRIBUTES, &mut patched, op) {
            return invalid.into_response();
        }
    }

    // Update user in database
    match db::update_scim_user(
        &state.store,
        &id,
        &auth.org_id,
        patched.name.as_deref(),
        patched.external_id.as_deref(),
        patched.active,
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
            if let Some(resp) = super::invalid_index_value_response(&e) {
                return resp.into_response();
            }
            tracing::error!("Failed to update user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to update user")),
            )
                .into_response();
        }
    }

    // If user was deactivated, invalidate all their sessions and revoke SSH certificates
    if patched.deactivated {
        tracing::info!(
            "User {} deactivated via SCIM, invalidating sessions and revoking SSH certificates",
            id
        );
        if crate::services::auth::revoke_user_access(
            &state,
            &id,
            "User deactivated via SCIM",
            "scim",
        )
        .await
        .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to revoke user access")),
            )
                .into_response();
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "update",
        "User",
        &id,
        Some(&auth.token_id),
        Some(
            &serde_json::json!({"active": patched.active, "deactivated": patched.deactivated})
                .to_string(),
        ),
        auth.org_domain.as_deref(),
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
pub(crate) async fn delete_user(
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
    // Revoke access before deleting. If revocation fails, abort — delete_user
    // would destroy the issued cert records, making the certs permanently
    // unrevocable.
    if crate::services::auth::revoke_user_access(&state, &id, "User deleted via SCIM", "scim")
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to revoke user access")),
        )
            .into_response();
    }

    // Delete user (cascades to authenticators). A `false` return means the
    // user vanished between the existence check above and the delete (e.g. a
    // concurrent request deleted it). Surface a 404 and skip the audit event
    // rather than reporting a successful delete — and logging a fraudulent
    // audit entry — for a change that never happened.
    match db::delete_user(&state.store, &id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to delete user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to delete user")),
            )
                .into_response();
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "delete",
        "User",
        &id,
        Some(&auth.token_id),
        None,
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Convert database user to SCIM user.
pub(crate) fn db_user_to_scim(base_url: &str, user: db::ScimUserRecord) -> ScimUser {
    ScimUser {
        schemas: vec![urn::USER.to_string()],
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
            last_modified: Some(user.updated_at),
            location: format!("{base_url}/scim/v2/Users/{}", user.id),
        }),
    }
}
