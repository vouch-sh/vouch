// SPDX-License-Identifier: BUSL-1.1
//! Organization admin handlers for SCIM token management, member management,
//! and audit log viewing.
//!
//! These APIs support both JWT Bearer authentication and cookie-based authentication
//! from regular FIDO2 sessions. Only organization admins can access these endpoints.

use crate::AppState;
use crate::db;
use crate::db::audit::AuditEventFilter;
use crate::impl_template_response;
use crate::services::error::ServiceError;
use crate::services::posture;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::extract::{OriginalUri, Query};
use axum::http::Method;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::sync::Arc;

use super::browser_login::validate_origin;
use super::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use super::{ValidPath, ValidUuid};

/// Maximum number of SCIM tokens per org (supports key rotation).
const MAX_SCIM_TOKENS: usize = 2;

/// Result of generating a SCIM token (plaintext + hash for storage).
struct GeneratedScimToken {
    /// Plaintext token to return to the caller (shown once).
    plaintext: SecretString,
    /// SHA-256 hex hash for storage in the database.
    hash: String,
}

/// Generate a random SCIM token and its hash for storage.
fn generate_scim_token() -> Result<GeneratedScimToken, ServiceError> {
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "RNG failure",
        )
    })?;
    let plaintext = format!("vouch_scim_{}", URL_SAFE_NO_PAD.encode(token_bytes));
    let hash = hex::encode(digest::digest(&SHA256, plaintext.as_bytes()));
    Ok(GeneratedScimToken {
        plaintext: SecretString::from(plaintext),
        hash,
    })
}

/// Compute token expiration from a number of days.
///
/// `jiff::Timestamp` only supports time-based units, so we convert days to hours.
fn compute_token_expiry(days: i64) -> Result<Timestamp, ServiceError> {
    let hours = days.checked_mul(24).ok_or_else(|| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "Expiration overflow",
        )
    })?;
    let duration = jiff::Span::new().hours(hours);
    jiff::Timestamp::now().checked_add(duration).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            format!("Invalid expiration: {e}"),
        )
    })
}

// ============================================================================
// SCIM Token Management API
// ============================================================================

/// Request to create a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub description: Option<String>,
    /// Token expiration in days (required, 1-365 days).
    pub expires_in_days: i64,
}

/// Response for created SCIM token.
#[derive(Debug, serde::Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub token: String,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
}

/// SCIM token info for listing.
#[derive(Debug, serde::Serialize)]
pub struct ScimTokenInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
}

/// Response for listing SCIM tokens.
#[derive(Debug, serde::Serialize)]
pub struct ListScimTokensResponse {
    pub tokens: Vec<ScimTokenInfo>,
}

/// Create a new SCIM token.
/// POST /api/v1/org/scim-tokens
pub async fn create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>, ServiceError> {
    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    if let Some(ref desc) = req.description
        && desc.len() > 256
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 256 characters or less",
        ));
    }

    if req.expires_in_days < 1 || req.expires_in_days > 365 {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "expires_in_days must be between 1 and 365",
        ));
    }

    // Enforce 2-token limit
    let existing = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if existing.len() >= MAX_SCIM_TOKENS {
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "token_limit_reached",
            "Maximum of 2 SCIM tokens per organization. Revoke one before creating another.",
        ));
    }

    let generated = generate_scim_token()?;
    let expires_at = Some(compute_token_expiry(req.expires_in_days)?);

    // Store the token
    let token_id = db::create_scim_token(
        &state.store,
        &generated.hash,
        req.description.as_deref(),
        expires_at,
        Some(&org_id),
        None, // Default scope: full access
    )
    .await
    .map_err(|e| ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;

    let data = serde_json::json!({
        "action": "create_scim_token",
        "token_id": token_id,
        "admin_user_id": user.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_create_scim_token",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await;

    tracing::info!("Created SCIM token: {} for org: {}", token_id, org_id);

    Ok(Json(CreateScimTokenResponse {
        id: token_id,
        token: generated.plaintext.expose_secret().to_string(),
        description: req.description,
        expires_at,
    }))
}

/// List SCIM tokens for the organization.
/// GET /api/v1/org/scim-tokens
pub async fn list_scim_tokens(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<ListScimTokensResponse>, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let tokens = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let tokens: Vec<ScimTokenInfo> = tokens
        .into_iter()
        .map(|t| ScimTokenInfo {
            id: t.id,
            description: t.description,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
        })
        .collect();

    Ok(Json(ListScimTokensResponse { tokens }))
}

/// Delete a SCIM token.
/// DELETE /api/v1/org/scim-tokens/:id
pub async fn delete_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(token_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if !deleted {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "SCIM token not found",
        ));
    }

    let data = serde_json::json!({
        "action": "delete_scim_token",
        "token_id": &*token_id,
        "admin_user_id": user.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_delete_scim_token",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await;

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Admin UI — Member Management
// ============================================================================

/// Page size for the members list.
const MEMBERS_PAGE_SIZE: u64 = 50;

/// Page size for the audit log.
const AUDIT_PAGE_SIZE: u64 = 100;

/// Query parameters for paginated pages.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub after: Option<String>,
}

/// Query parameters for audit page (pagination + optional event type filter).
#[derive(Debug, Deserialize)]
pub struct AuditParams {
    pub after: Option<String>,
    pub event_type: Option<String>,
}

/// A member row for the template.
pub struct MemberRow {
    pub id: String,
    pub email: String,
    pub is_org_admin: bool,
    pub active: bool,
    pub key_count: i64,
    pub is_self: bool,
}

/// Members list page template.
#[derive(Template)]
#[template(path = "admin/members.html")]
pub struct AdminMembersTemplate {
    pub auth: AuthContext,
    pub members: Vec<MemberRow>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

impl_template_response!(AdminMembersTemplate);

/// Audit event row for the template.
pub struct AuditRow {
    pub id: String,
    pub event_type: String,
    pub email_domain: Option<String>,
    pub data: String,
    pub created_at: String,
}

/// Audit log page template.
#[derive(Template)]
#[template(path = "admin/audit.html")]
pub struct AdminAuditTemplate {
    pub auth: AuthContext,
    pub events: Vec<AuditRow>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub event_type_filter: Option<String>,
}

impl_template_response!(AdminAuditTemplate);

/// GET /admin — Members list page.
pub async fn admin_members_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<PaginationParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    // Get the admin's org_id
    let org_id = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(id) => id,
            None => return Redirect::to("/integrations").into_response(),
        },
        _ => return Redirect::to("/integrations").into_response(),
    };

    let (users, has_more): (Vec<db::User>, bool) = match db::get_users_by_org_paginated(
        &state.store,
        &org_id,
        params.after.as_deref(),
        MEMBERS_PAGE_SIZE,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to load members for org {org_id}: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut members = Vec::with_capacity(users.len());
    for user in &users {
        let key_count = db::count_authenticators_for_user(&state.store, &user.id)
            .await
            .unwrap_or(0);
        members.push(MemberRow {
            id: user.id.clone(),
            email: user.email.clone(),
            is_org_admin: user.is_org_admin,
            active: user.active,
            key_count,
            is_self: user.id == user_id,
        });
    }

    let next_cursor = if has_more {
        members.last().map(|m| m.id.clone())
    } else {
        None
    };

    AdminMembersTemplate {
        auth,
        members,
        has_more,
        next_cursor,
    }
    .into_response()
}

/// Helper: extract org admin from cookie, verify target is in same org.
async fn extract_admin_and_target(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    target_user_id: &str,
) -> Result<(db::User, db::User, String), ServiceError> {
    let (admin, org_id) = extract_org_admin(state, headers, jar, method, uri).await?;

    let target = db::get_user_by_id(&state.store, target_user_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "User not found"))?;

    // Verify target belongs to the same org
    if target.org_id.as_deref() != Some(org_id.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "User not found in organization",
        ));
    }

    Ok((admin, target, org_id))
}

/// POST /admin/members/{id}/promote — Promote a member to admin.
pub async fn promote_member(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    // Cannot promote yourself (no-op but creates misleading audit events)
    if admin.id == *target_id {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "self_action",
            "Cannot promote yourself",
        ));
    }

    db::update_user_admin_status(&state.store, &target_id, true)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "promote",
        "target_email": target.email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_promote",
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} promoted {} to org admin",
        admin.email,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/demote — Demote an admin to regular member.
pub async fn demote_member(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    // Cannot demote yourself
    if admin.id == *target_id {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "self_action",
            "Cannot demote yourself",
        ));
    }

    db::update_user_admin_status(&state.store, &target_id, false)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "demote",
        "target_email": target.email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_demote",
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} demoted {} from org admin",
        admin.email,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/deactivate — Deactivate a user.
pub async fn deactivate_member(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    // Cannot deactivate yourself
    if admin.id == *target_id {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "self_action",
            "Cannot deactivate yourself",
        ));
    }

    db::update_user_active_status(&state.store, &target_id, false)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    // Invalidate all sessions for the deactivated user
    db::delete_sessions_for_user(&state.store, &target_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "deactivate",
        "target_email": target.email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_deactivate",
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await;

    tracing::info!("Admin {} deactivated user {}", admin.email, target.email);

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/activate — Reactivate a user.
pub async fn activate_member(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    db::update_user_active_status(&state.store, &target_id, true)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "activate",
        "target_email": target.email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_activate",
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await;

    tracing::info!("Admin {} reactivated user {}", admin.email, target.email);

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/revoke-credentials — Revoke all credentials for a user.
pub async fn revoke_member_credentials(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    // Cannot revoke your own credentials
    if admin.id == *target_id {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "self_action",
            "Cannot revoke your own credentials",
        ));
    }

    // Delete all authenticators (cascades to sessions)
    let authenticators = db::get_authenticators_for_user(&state.store, &target_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let key_count = authenticators.len();
    for auth in &authenticators {
        db::delete_authenticator(&state.store, &auth.id)
            .await
            .map_err(|e| {
                ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
            })?;
    }

    // Also kill any remaining sessions
    db::delete_sessions_for_user(&state.store, &target_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "revoke_credentials",
        "target_email": target.email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
        "keys_revoked": key_count,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_revoke_credentials",
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} revoked {} credentials for user {}",
        admin.email,
        key_count,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/remove — Remove a user from the organization.
pub async fn remove_member(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(target_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, target, _org_id) = extract_admin_and_target(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        &target_id,
    )
    .await?;

    // Cannot remove yourself
    if admin.id == *target_id {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "self_action",
            "Cannot remove yourself",
        ));
    }

    let target_email = target.email.clone();

    db::delete_user(&state.store, &target_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let data = serde_json::json!({
        "action": "remove_user",
        "target_email": target_email,
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_remove_user",
            Some(&admin.id),
            Some(&target_email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} removed user {} from organization",
        admin.email,
        target_email
    );

    Ok(Redirect::to("/admin").into_response())
}

// ============================================================================
// Admin UI — Audit Log
// ============================================================================

/// GET /admin/audit — Audit log page.
pub async fn admin_audit_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<AuditParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    // Get the org domain for filtering audit events
    let org_domain = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(ref org_id) => db::get_organization_domain(&state.store, org_id)
                .await
                .ok()
                .flatten(),
            None => None,
        },
        _ => None,
    };

    let org_domain = match org_domain {
        Some(d) => d,
        None => return Redirect::to("/integrations").into_response(),
    };

    let filter = AuditEventFilter {
        email_domain: Some(org_domain),
        event_type: params.event_type.clone(),
        before_id: params.after.clone(),
        ..AuditEventFilter::default()
    };

    let (audit_events, has_more): (Vec<crate::db::audit::AuditEvent>, bool) = match state
        .audit
        .query_events_paginated(&filter, AUDIT_PAGE_SIZE)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to load audit events: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let events: Vec<AuditRow> = audit_events
        .iter()
        .map(|e| AuditRow {
            id: e.id.clone(),
            event_type: e.event_type.clone(),
            email_domain: e.email_domain.clone(),
            data: e.data.clone(),
            created_at: e.created_at.clone(),
        })
        .collect();

    let next_cursor = if has_more {
        events.last().map(|e| e.id.clone())
    } else {
        None
    };

    AdminAuditTemplate {
        auth,
        events,
        has_more,
        next_cursor,
        event_type_filter: params.event_type,
    }
    .into_response()
}

// ============================================================================
// Admin UI — SCIM Token Management
// ============================================================================

/// Display row for SCIM tokens in the template.
pub struct ScimTokenRow {
    pub id: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

/// SCIM tokens page template.
#[derive(Template)]
#[template(path = "admin/scim_tokens.html")]
pub struct AdminScimTokensTemplate {
    pub auth: AuthContext,
    pub tokens: Vec<ScimTokenRow>,
    pub flash_message: Option<String>,
    pub new_token: Option<String>,
}

impl_template_response!(AdminScimTokensTemplate);

/// Query parameters for the SCIM tokens page.
#[derive(Debug, Deserialize)]
pub struct ScimTokensParams {
    pub error: Option<String>,
}

/// Form data for creating a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenForm {
    pub description: Option<String>,
    pub expires_in_days: i64,
}

/// Format a `jiff::Timestamp` as a date string for display.
fn format_timestamp(ts: &Timestamp) -> String {
    ts.strftime("%Y-%m-%d %H:%M UTC").to_string()
}

/// GET /admin/scim-tokens — SCIM token management page.
pub async fn admin_scim_tokens_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<ScimTokensParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    let org_id = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(id) => id,
            None => return Redirect::to("/integrations").into_response(),
        },
        _ => return Redirect::to("/integrations").into_response(),
    };

    let db_tokens = match db::list_scim_tokens(&state.store, Some(&org_id)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to load SCIM tokens for org {org_id}: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tokens: Vec<ScimTokenRow> = db_tokens
        .into_iter()
        .map(|t| ScimTokenRow {
            id: t.id,
            description: t.description,
            created_at: format_timestamp(&t.created_at),
            last_used_at: t.last_used_at.as_ref().map(format_timestamp),
            expires_at: t.expires_at.as_ref().map(format_timestamp),
        })
        .collect();

    AdminScimTokensTemplate {
        auth,
        tokens,
        flash_message: params.error,
        new_token: None,
    }
    .into_response()
}

/// POST /admin/scim-tokens — Create a new SCIM token (UI form).
pub async fn admin_create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<CreateScimTokenForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    if let Some(ref desc) = form.description
        && desc.len() > 256
    {
        return Ok(Redirect::to(
            "/admin/scim-tokens?error=Description must be 256 characters or less",
        )
        .into_response());
    }

    if form.expires_in_days < 1 || form.expires_in_days > 365 {
        return Ok(Redirect::to(
            "/admin/scim-tokens?error=Expiration must be between 1 and 365 days",
        )
        .into_response());
    }

    // Enforce 2-token limit
    let existing = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if existing.len() >= MAX_SCIM_TOKENS {
        return Ok(Redirect::to(
            "/admin/scim-tokens?error=Maximum of 2 SCIM tokens. Revoke one before creating another.",
        )
        .into_response());
    }

    let generated = generate_scim_token()?;
    let expires_at = Some(compute_token_expiry(form.expires_in_days)?);

    // Filter empty description to None
    let description = form
        .description
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(String::from);

    // Store the token
    let token_id = db::create_scim_token(
        &state.store,
        &generated.hash,
        description.as_deref(),
        expires_at,
        Some(&org_id),
        None,
    )
    .await
    .map_err(|e| ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;

    let data = serde_json::json!({
        "action": "create_scim_token",
        "token_id": token_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_create_scim_token",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} created SCIM token {} for org {}",
        admin.email,
        token_id,
        org_id
    );

    // Re-fetch tokens and render the page directly (avoids leaking token in URL)
    let db_tokens = db::list_scim_tokens(&state.store, Some(&org_id))
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    let tokens: Vec<ScimTokenRow> = db_tokens
        .into_iter()
        .map(|t| ScimTokenRow {
            id: t.id,
            description: t.description,
            created_at: format_timestamp(&t.created_at),
            last_used_at: t.last_used_at.as_ref().map(format_timestamp),
            expires_at: t.expires_at.as_ref().map(format_timestamp),
        })
        .collect();

    let auth = get_resource_auth_context(&state, &jar).await;

    Ok(AdminScimTokensTemplate {
        auth,
        tokens,
        flash_message: None,
        new_token: Some(generated.plaintext.expose_secret().to_string()),
    }
    .into_response())
}

/// POST /admin/scim-tokens/{id}/revoke — Revoke a SCIM token (UI form).
pub async fn admin_revoke_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(token_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if !deleted {
        return Ok(Redirect::to("/admin/scim-tokens?error=SCIM token not found").into_response());
    }

    let data = serde_json::json!({
        "action": "revoke_scim_token",
        "token_id": &*token_id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_revoke_scim_token",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} revoked SCIM token {} for org {}",
        admin.email,
        token_id,
        org_id
    );

    Ok(Redirect::to("/admin/scim-tokens").into_response())
}

// ============================================================================
// Admin UI — Device Posture Policies
// ============================================================================

/// Maximum number of custom policies per org (active + inactive).
const MAX_CUSTOM_POLICIES: usize = 20;

/// A preconfigured policy row for the template.
pub struct PreconfiguredPolicyRow {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub cel_expression: String,
    pub active: bool,
}

/// A custom policy row for the template.
pub struct CustomPolicyRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub cel_expression: String,
    pub active: bool,
}

/// Policies page template.
#[derive(Template)]
#[template(path = "admin/policies.html")]
pub struct AdminPoliciesTemplate {
    pub auth: AuthContext,
    pub preconfigured_policies: Vec<PreconfiguredPolicyRow>,
    pub custom_policies: Vec<CustomPolicyRow>,
    pub flash_message: Option<String>,
}

impl_template_response!(AdminPoliciesTemplate);

/// Query parameters for the policies page (error flash).
#[derive(Debug, Deserialize)]
pub struct PoliciesParams {
    pub error: Option<String>,
}

/// GET /admin/policies — Device posture policies page.
pub async fn admin_policies_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<PoliciesParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    let org_id = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(id) => id,
            None => return Redirect::to("/integrations").into_response(),
        },
        _ => return Redirect::to("/integrations").into_response(),
    };

    let active_slugs = match db::get_active_preconfigured_slugs(&state.store, &org_id).await {
        Ok(slugs) => slugs,
        Err(e) => {
            tracing::error!("Failed to load posture config: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let preconfigured_policies: Vec<PreconfiguredPolicyRow> = posture::PRECONFIGURED_POLICIES
        .iter()
        .map(|p| PreconfiguredPolicyRow {
            slug: p.slug.to_string(),
            name: p.name.to_string(),
            description: p.description.to_string(),
            cel_expression: p.cel_expression.to_string(),
            active: active_slugs.iter().any(|s| s == p.slug.as_str()),
        })
        .collect();

    let custom_policies: Vec<CustomPolicyRow> =
        match db::list_custom_policies(&state.store, &org_id).await {
            Ok(policies) => policies
                .into_iter()
                .map(|p| CustomPolicyRow {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                    cel_expression: p.cel_expression,
                    active: p.active,
                })
                .collect(),
            Err(e) => {
                tracing::error!("Failed to load custom policies: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    AdminPoliciesTemplate {
        auth,
        preconfigured_policies,
        custom_policies,
        flash_message: params.error,
    }
    .into_response()
}

/// POST /admin/policies/preconfigured/{slug}/toggle
pub async fn toggle_preconfigured_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(slug): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    if !posture::is_valid_preconfigured_slug(&slug) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("Unknown preconfigured policy: {slug}"),
        ));
    }

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Single read of active slugs — fixes TOCTOU from old handler
    let mut active_slugs = db::get_active_preconfigured_slugs(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

    let already_active = active_slugs.iter().any(|s| s == &slug);

    if already_active {
        active_slugs.retain(|s| s != &slug);
    } else {
        // Check max active limit (count custom active inline)
        let custom_active_count = db::get_active_custom_policies(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        let total_active = active_slugs.len() + custom_active_count;

        if total_active >= posture::MAX_ACTIVE_POLICIES {
            return Ok(Redirect::to(&format!(
                "/admin/policies?error=Maximum of {} active policies allowed",
                posture::MAX_ACTIVE_POLICIES
            ))
            .into_response());
        }
        active_slugs.push(slug.clone());
    }

    db::set_preconfigured_active(&state.store, &org_id, active_slugs)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to update posture config: {e}")))?;

    let action = if already_active {
        "disabled"
    } else {
        "enabled"
    };
    let data = serde_json::json!({
        "action": format!("preconfigured_policy_{action}"),
        "slug": &slug,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_policy_toggle",
            Some(&admin.id),
            Some(&slug),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} {} preconfigured policy '{}'",
        admin.email,
        action,
        slug
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// Form data for creating/updating a custom policy.
#[derive(Debug, Deserialize)]
pub struct CustomPolicyForm {
    #[serde(alias = "policy_name")]
    pub name: String,
    #[serde(default, alias = "policy_description")]
    pub description: Option<String>,
    pub cel_expression: String,
}

/// POST /admin/policies/custom — Create a new custom policy.
pub async fn create_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<CustomPolicyForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    // Validate inputs before auth
    if form.name.is_empty() || form.name.len() > 100 {
        return Ok(
            Redirect::to("/admin/policies?error=Name must be between 1 and 100 characters")
                .into_response(),
        );
    }

    if form.cel_expression.is_empty() || form.cel_expression.len() > 1024 {
        return Ok(Redirect::to(
            "/admin/policies?error=CEL expression must be between 1 and 1024 characters",
        )
        .into_response());
    }

    if let Some(ref desc) = form.description
        && desc.len() > 500
    {
        return Ok(Redirect::to(
            "/admin/policies?error=Description must be 500 characters or less",
        )
        .into_response());
    }

    // Auth before CEL compilation (fixes security finding F-04)
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Validate CEL syntax
    if let Err(e) = posture::validate_cel_expression(&form.cel_expression) {
        return Ok(Redirect::to(&format!(
            "/admin/policies?error=Invalid CEL expression: {e}"
        ))
        .into_response());
    }

    // Check total custom policy count limit
    let custom_count = db::list_custom_policies(&state.store, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
        .len();

    if custom_count >= MAX_CUSTOM_POLICIES {
        return Ok(Redirect::to(&format!(
            "/admin/policies?error=Maximum of {MAX_CUSTOM_POLICIES} custom policies allowed"
        ))
        .into_response());
    }

    let description = form.description.filter(|d| !d.is_empty());

    let policy = db::create_custom_policy(
        &state.store,
        db::CreateCustomPolicyParams {
            name: &form.name,
            description: description.as_deref(),
            cel_expression: &form.cel_expression,
            org_id: &org_id,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to create policy: {e}")))?;

    let cel_hash = cel_expression_hash(&form.cel_expression);
    let data = serde_json::json!({
        "action": "custom_policy_created",
        "policy_id": policy.id,
        "policy_name": policy.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_policy_create",
            Some(&admin.id),
            Some(&policy.name),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} created custom policy '{}'",
        admin.email,
        policy.name
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id} — Update a custom policy.
pub async fn update_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
    axum::Form(form): axum::Form<CustomPolicyForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    if form.name.is_empty() || form.name.len() > 100 {
        return Ok(
            Redirect::to("/admin/policies?error=Name must be between 1 and 100 characters")
                .into_response(),
        );
    }

    if form.cel_expression.is_empty() || form.cel_expression.len() > 1024 {
        return Ok(Redirect::to(
            "/admin/policies?error=CEL expression must be between 1 and 1024 characters",
        )
        .into_response());
    }

    // Auth before CEL compilation
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    if let Err(e) = posture::validate_cel_expression(&form.cel_expression) {
        return Ok(Redirect::to(&format!(
            "/admin/policies?error=Invalid CEL expression: {e}"
        ))
        .into_response());
    }

    let description = form.description.filter(|d| !d.is_empty());

    let result = db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: Some(&form.name),
            description: Some(description.as_deref()),
            cel_expression: Some(&form.cel_expression),
            active: None,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update policy: {e}")))?;

    if result.is_none() {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let cel_hash = cel_expression_hash(&form.cel_expression);
    let data = serde_json::json!({
        "action": "custom_policy_updated",
        "policy_id": &*id,
        "policy_name": form.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_policy_update",
            Some(&admin.id),
            Some(&form.name),
            &data.to_string(),
        )
        .await;

    tracing::info!("Admin {} updated custom policy '{}'", admin.email, id);

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id}/delete — Delete a custom policy.
pub async fn delete_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let deleted = db::delete_custom_policy(&state.store, &id, &org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to delete policy: {e}")))?;

    if !deleted {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let data = serde_json::json!({
        "action": "custom_policy_deleted",
        "policy_id": &*id,
        "admin_user_id": admin.id,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_policy_delete",
            Some(&admin.id),
            Some(&*id),
            &data.to_string(),
        )
        .await;

    tracing::info!("Admin {} deleted custom policy '{}'", admin.email, id);

    Ok(Redirect::to("/admin/policies").into_response())
}

/// POST /admin/policies/custom/{id}/toggle — Toggle active state.
pub async fn toggle_custom_policy(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidPath(id): ValidPath<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let policy = db::get_custom_policy(&state.store, &id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to get policy: {e}")))?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Policy not found"))?;

    if policy.org_id != org_id {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Policy not found",
        ));
    }

    let new_active = !policy.active;

    // Check max active limit when activating.
    // Read count and write in sequence — document-store operations are
    // serialized per-org so the window is narrow, and the worst case is
    // exceeding MAX by 1 (benign for a UI toggle).
    if new_active {
        let preconfigured_count = db::get_active_preconfigured_slugs(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        let custom_active_count = db::get_active_custom_policies(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to count policies: {e}")))?
            .len();
        // Subtract 1 if this policy was already counted as active
        let other_active = preconfigured_count + custom_active_count - usize::from(policy.active);

        if other_active >= posture::MAX_ACTIVE_POLICIES {
            return Ok(Redirect::to(&format!(
                "/admin/policies?error=Maximum of {} active policies allowed",
                posture::MAX_ACTIVE_POLICIES
            ))
            .into_response());
        }
    }

    db::update_custom_policy(
        &state.store,
        &id,
        &org_id,
        db::UpdateCustomPolicyParams {
            name: None,
            description: None,
            cel_expression: None,
            active: Some(new_active),
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to toggle policy: {e}")))?;

    let action = if new_active {
        "activated"
    } else {
        "deactivated"
    };
    let cel_hash = cel_expression_hash(&policy.cel_expression);
    let data = serde_json::json!({
        "action": format!("custom_policy_{action}"),
        "policy_id": &*id,
        "policy_name": policy.name,
        "admin_user_id": admin.id,
        "cel_expression_hash": cel_hash,
    });
    let _ = state
        .audit
        .insert_event(
            "admin_policy_toggle",
            Some(&admin.id),
            Some(&policy.name),
            &data.to_string(),
        )
        .await;

    tracing::info!(
        "Admin {} {} custom policy '{}'",
        admin.email,
        action,
        policy.name
    );

    Ok(Redirect::to("/admin/policies").into_response())
}

/// SHA-256 hash of a CEL expression, truncated to 16 hex chars.
///
/// Included in audit events to trace which version of a policy was in
/// effect at the time of an admin action.
fn cel_expression_hash(expression: &str) -> String {
    let hash = digest::digest(&SHA256, expression.as_bytes());
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Response for validating a CEL expression (JSON API for CEL playground).
#[derive(Debug, serde::Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestResult>,
}

/// Test result from dry-running a CEL expression against sample posture.
#[derive(Debug, serde::Serialize)]
pub struct TestResult {
    pub pass: bool,
}

/// Request to validate a CEL expression (JSON API for CEL playground).
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub cel_expression: String,
    #[serde(default)]
    pub test_posture: Option<vouch_common::posture::DevicePosture>,
}

/// POST /api/v1/org/policies/validate — Validate CEL expression (JSON).
pub async fn validate_cel_api(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ServiceError> {
    // Auth before CEL compilation (fixes security finding F-04)
    let _auth = extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    if req.cel_expression.is_empty() || req.cel_expression.len() > 1024 {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some("CEL expression must be between 1 and 1024 characters".to_string()),
            test_result: None,
        }));
    }

    if let Err(e) = posture::validate_cel_expression(&req.cel_expression) {
        return Ok(Json(ValidateResponse {
            valid: false,
            error: Some(format!("{e}")),
            test_result: None,
        }));
    }

    let test_result = if let Some(ref test_posture) = req.test_posture {
        match posture::test_cel_expression(&req.cel_expression, test_posture) {
            Ok(pass) => Some(TestResult { pass }),
            Err(_) => Some(TestResult { pass: false }),
        }
    } else {
        None
    };

    Ok(Json(ValidateResponse {
        valid: true,
        error: None,
        test_result,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;
    use secrecy::ExposeSecret;

    use crate::test_utils::*;

    // ValidPath<ValidUuid> is extracted before the handler body runs auth checks,
    // so a malformed UUID must produce 400 regardless of authentication state.

    #[tokio::test]
    async fn test_delete_scim_token_invalid_uuid_returns_400() {
        let (app, _state) = test_app().await;

        let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn test_delete_scim_token_invalid_uuid_error_is_json() {
        let (app, _state) = test_app().await;

        let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        // ServiceError::api produces {"code": "...", "message": "..."}
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("error response must be valid JSON");
        assert!(
            json.get("code").is_some(),
            "JSON error must contain 'code' field; got: {json}"
        );
    }

    #[tokio::test]
    async fn test_delete_scim_token_valid_uuid_proceeds_to_auth_check() {
        // A valid UUID with no auth should fail with 401, not 400,
        // confirming UUID validation passed and auth ran.
        let (app, _state) = test_app().await;
        let valid_uuid = uuid::Uuid::now_v7();

        let (status, _body) =
            http_delete(&app, &format!("/api/v1/org/scim-tokens/{valid_uuid}"), &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ================================================================
    // Auth-before-validation tests (unauthenticated requests get 401)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_invalid_input_returns_401_without_auth() {
        let (app, _state) = test_app().await;

        // Invalid expires_in_days should still return 401 (auth checked first)
        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 0}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Unauthenticated requests must return 401 regardless of input validity"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_long_description_returns_401_without_auth() {
        let (app, _state) = test_app().await;

        let long_desc = "x".repeat(257);
        let body_json = format!(
            r#"{{"description": "{}", "expires_in_days": 30}}"#,
            long_desc
        );

        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            &body_json,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Unauthenticated requests must return 401 regardless of input validity"
        );
    }

    // ================================================================
    // Token generation helper tests
    // ================================================================

    #[test]
    fn test_generate_scim_token_has_prefix_and_hash() {
        let generated = super::generate_scim_token().unwrap();
        let plaintext = generated.plaintext.expose_secret();
        assert!(
            plaintext.starts_with("vouch_scim_"),
            "token must have vouch_scim_ prefix"
        );
        // 32 random bytes → 43 base64url chars + 11 char prefix
        assert!(plaintext.len() > 40, "token must be sufficiently long");
        // Hash should be 64-char hex (SHA-256)
        assert_eq!(generated.hash.len(), 64, "hash must be 64 hex chars");
        // Hash must match the plaintext
        let expected_hash = hex::encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            plaintext.as_bytes(),
        ));
        assert_eq!(generated.hash, expected_hash, "hash must match plaintext");
    }

    #[test]
    fn test_generate_scim_token_unique() {
        let a = super::generate_scim_token().unwrap();
        let b = super::generate_scim_token().unwrap();
        assert_ne!(
            a.plaintext.expose_secret(),
            b.plaintext.expose_secret(),
            "tokens must be unique"
        );
    }

    #[test]
    fn test_compute_token_expiry_valid_days() {
        let expiry = super::compute_token_expiry(30).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs = 30 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "30 days should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    #[test]
    fn test_compute_token_expiry_one_day() {
        let expiry = super::compute_token_expiry(1).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs = 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "1 day should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    #[test]
    fn test_compute_token_expiry_365_days() {
        let expiry = super::compute_token_expiry(365).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs: i64 = 365 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "365 days should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    // ================================================================
    // Admin member management tests
    // ================================================================

    /// Helper: create an org, admin user with session, and a target member.
    async fn setup_admin_and_member(
        state: &crate::AppState,
    ) -> (crate::db::User, String, crate::db::User) {
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(state, &admin.id, &admin.email, &auth_id).await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        (admin, token, member)
    }

    fn admin_cookie(token: &str) -> String {
        format!("{}={token}", vouch_common::SESSION_COOKIE_NAME)
    }

    // ---- Critical #1: Deactivated user cannot authenticate as admin ----

    #[tokio::test]
    async fn test_deactivated_admin_cannot_access_scim_tokens() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;

        // Deactivate the admin
        crate::db::update_user_active_status(&state.store, &admin.id, false)
            .await
            .unwrap();

        let auth = format!("Bearer {token}");
        let (status, _body) =
            http_get(&app, "/api/v1/org/scim-tokens", &[("Authorization", &auth)]).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Deactivated admin must be rejected"
        );
    }

    #[tokio::test]
    async fn test_deactivated_user_cookie_auth_returns_unauthenticated() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;

        // Deactivate the user
        crate::db::update_user_active_status(&state.store, &admin.id, false)
            .await
            .unwrap();

        // Cookie-based access to admin page should redirect (unauthenticated)
        let cookie = admin_cookie(&token);
        let resp = http_get_full(&app, "/admin", &[("Cookie", &cookie)]).await;

        assert_eq!(
            resp.status,
            StatusCode::SEE_OTHER,
            "Deactivated user should be redirected away from admin page"
        );
    }

    // ---- Critical #2: CSRF origin validation on admin POST ----

    #[tokio::test]
    async fn test_admin_post_without_origin_rejected() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", member.id),
            "",
            &[("Cookie", &cookie)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "POST without Origin header must be rejected"
        );
    }

    #[tokio::test]
    async fn test_admin_post_with_wrong_origin_rejected() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://evil.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "POST with wrong Origin must be rejected"
        );
    }

    #[tokio::test]
    async fn test_admin_post_with_correct_origin_proceeds() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        // Should succeed (redirect to /admin)
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "POST with correct Origin should succeed"
        );
    }

    // ---- Authorization: non-admin cannot access admin POST endpoints ----

    #[tokio::test]
    async fn test_non_admin_cannot_promote() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        // Create a non-admin user with a session
        let user = create_test_user_in_org(&state.store, "user@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let target =
            create_test_user_in_org(&state.store, "target@example.com", &org.id, false).await;

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", target.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Non-admin must be forbidden from admin actions"
        );
    }

    // ---- Self-action guards ----

    #[tokio::test]
    async fn test_admin_cannot_promote_self() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let (status, body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", admin.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Self-promote should be blocked: {body}"
        );
    }

    #[tokio::test]
    async fn test_admin_cannot_demote_self() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let (status, body) = http_post_form(
            &app,
            &format!("/admin/members/{}/demote", admin.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Self-demote should be blocked: {body}"
        );
    }

    #[tokio::test]
    async fn test_admin_cannot_deactivate_self() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let (status, body) = http_post_form(
            &app,
            &format!("/admin/members/{}/deactivate", admin.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Self-deactivate should be blocked: {body}"
        );
    }

    #[tokio::test]
    async fn test_admin_cannot_remove_self() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let (status, body) = http_post_form(
            &app,
            &format!("/admin/members/{}/remove", admin.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Self-remove should be blocked: {body}"
        );
    }

    // ---- Cross-org scoping ----

    #[tokio::test]
    async fn test_admin_cannot_target_user_in_different_org() {
        let (app, state) = test_app().await;
        let org1 = create_test_org(&state.store, "org1.com").await;
        let org2 = create_test_org(&state.store, "org2.com").await;

        let admin = create_test_user_in_org(&state.store, "admin@org1.com", &org1.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        let other_user =
            create_test_user_in_org(&state.store, "user@org2.com", &org2.id, false).await;

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/promote", other_user.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "Targeting user in different org must return not found"
        );
    }

    // ---- Happy path: admin actions succeed ----

    #[tokio::test]
    async fn test_admin_can_deactivate_member() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/deactivate", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "Deactivate should succeed");

        // Verify user is now inactive
        let updated = crate::db::get_user_by_id(&state.store, &member.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!updated.active, "User should be deactivated");
    }

    #[tokio::test]
    async fn test_admin_can_activate_member() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        // Deactivate first
        crate::db::update_user_active_status(&state.store, &member.id, false)
            .await
            .unwrap();

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/activate", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "Activate should succeed");

        let updated = crate::db::get_user_by_id(&state.store, &member.id)
            .await
            .unwrap()
            .unwrap();
        assert!(updated.active, "User should be reactivated");
    }

    #[tokio::test]
    async fn test_admin_can_demote_member() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin =
            create_test_user_in_org(&state.store, "admin1@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);

        // Create another admin to demote
        let admin2 =
            create_test_user_in_org(&state.store, "admin2@example.com", &org.id, true).await;

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/demote", admin2.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "Demote should succeed");

        let updated = crate::db::get_user_by_id(&state.store, &admin2.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!updated.is_org_admin, "User should no longer be admin");
    }

    #[tokio::test]
    async fn test_admin_can_remove_member() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let member_id = member.id.clone();
        let cookie = admin_cookie(&token);

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{member_id}/remove"),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "Remove should succeed");

        let deleted = crate::db::get_user_by_id(&state.store, &member_id)
            .await
            .unwrap();
        assert!(deleted.is_none(), "User should be deleted");
    }

    // ---- Invalid UUID on admin routes ----

    #[tokio::test]
    async fn test_admin_promote_invalid_uuid_returns_400() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_post_form(
            &app,
            "/admin/members/not-a-uuid/promote",
            "",
            &[("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
