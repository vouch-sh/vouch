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
use serde::Deserialize;
use std::sync::Arc;

use super::browser_login::validate_origin;
use super::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use super::{ValidPath, ValidUuid};

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
    // Pure validation first — no DB cost for malformed requests
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

    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    // Generate a secure random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "RNG failure",
        )
    })?;
    let token = format!("vouch_scim_{}", URL_SAFE_NO_PAD.encode(token_bytes));

    // Hash the token for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Calculate expiration
    let duration = jiff::Span::new().days(req.expires_in_days);
    let expires_at = jiff::Timestamp::now().checked_add(duration).ok();

    // Store the token
    let token_id = db::create_scim_token(
        &state.store,
        &token_hash,
        req.description.as_deref(),
        expires_at,
        Some(&org_id),
        None, // Default scope: full access
    )
    .await
    .map_err(|e| ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;

    tracing::info!("Created SCIM token: {} for org: {}", token_id, org_id);

    Ok(Json(CreateScimTokenResponse {
        id: token_id,
        token,
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
    let (_user, org_id) =
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;

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
    // Validation-before-auth tests (Phase 1E defense-in-depth)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_expires_zero_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 0}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expires_in_days=0 must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_expires_366_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 366}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expires_in_days=366 must return 400 (not 401) even without auth: {body}"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_long_description_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        let long_desc = "x".repeat(257);
        let body_json = format!(
            r#"{{"description": "{}", "expires_in_days": 30}}"#,
            long_desc
        );

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            &body_json,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Description >256 chars must return 400 (not 401) even without auth: {body}"
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
