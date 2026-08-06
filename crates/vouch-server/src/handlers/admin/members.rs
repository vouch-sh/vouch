// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Member management UI handlers.

use crate::AppState;
use crate::db;
use crate::error::ServiceError;
use crate::impl_template_response;
use askama::Template;
use axum::extract::OriginalUri;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

use super::{PaginationParams, extract_admin_and_target};
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, get_resource_auth_context};
use crate::handlers::{ValidPath, ValidUuid};

/// Page size for the members list.
const MEMBERS_PAGE_SIZE: u64 = 50;

/// A member row for the template.
pub(crate) struct MemberRow {
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
pub(crate) struct AdminMembersTemplate {
    pub auth: AuthContext,
    pub members: Vec<MemberRow>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

impl_template_response!(AdminMembersTemplate);

/// GET /admin — Members list page.
pub(crate) async fn admin_members_page(
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

/// POST /admin/members/{id}/promote — Promote a member to admin.
pub(crate) async fn promote_member(
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

    let updated = db::update_user_admin_status(&state.store, &target_id, true).await?;
    if !updated {
        return Err(member_gone());
    }

    let data = serde_json::json!({
        "action": "promote",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminPromote,
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_promote audit event");
    }

    tracing::info!(
        "Admin {} promoted {} to org admin",
        admin.email,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/demote — Demote an admin to regular member.
pub(crate) async fn demote_member(
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

    let updated = db::update_user_admin_status(&state.store, &target_id, false).await?;
    if !updated {
        return Err(member_gone());
    }

    let data = serde_json::json!({
        "action": "demote",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminDemote,
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_demote audit event");
    }

    tracing::info!(
        "Admin {} demoted {} from org admin",
        admin.email,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/deactivate — Deactivate a user.
pub(crate) async fn deactivate_member(
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

    let updated = db::update_user_active_status(&state.store, &target_id, false).await?;
    if !updated {
        return Err(member_gone());
    }

    // Invalidate all sessions for the deactivated user
    db::delete_sessions_for_user(&state.store, &target_id).await?;
    state.session_cache.invalidate_for_user(&target_id);

    // Revoke all SSH certificates for this user
    if let Err(e) = db::revoke_all_ssh_certificates_for_user(
        &state.store,
        &target_id,
        Some("User deactivated by admin"),
        Some(&admin.id),
    )
    .await
    {
        tracing::error!("Failed to revoke SSH certificates for deactivated user: {e}");
    }
    // Clear GitHub refresh token to prevent further API access
    if let Err(e) = db::clear_user_github_refresh_token(&state.store, &target_id).await {
        tracing::error!("Failed to clear GitHub refresh token for deactivated user: {e}");
    }

    let data = serde_json::json!({
        "action": "deactivate",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminDeactivate,
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_deactivate audit event");
    }

    tracing::info!("Admin {} deactivated user {}", admin.email, target.email);

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/activate — Reactivate a user.
pub(crate) async fn activate_member(
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

    let updated = db::update_user_active_status(&state.store, &target_id, true).await?;
    if !updated {
        return Err(member_gone());
    }

    let data = serde_json::json!({
        "action": "activate",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminActivate,
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_activate audit event");
    }

    tracing::info!("Admin {} reactivated user {}", admin.email, target.email);

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/revoke-credentials — Revoke all credentials for a user.
pub(crate) async fn revoke_member_credentials(
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
    let authenticators = db::get_authenticators_for_user(&state.store, &target_id).await?;

    let key_count = authenticators.len();
    for auth in &authenticators {
        db::delete_authenticator(&state.store, &auth.id).await?;
    }

    // Also kill any remaining sessions
    db::delete_sessions_for_user(&state.store, &target_id).await?;
    state.session_cache.invalidate_for_user(&target_id);

    // Revoke all SSH certificates for this user
    if let Err(e) = db::revoke_all_ssh_certificates_for_user(
        &state.store,
        &target_id,
        Some("Credentials revoked by admin"),
        Some(&admin.id),
    )
    .await
    {
        tracing::error!("Failed to revoke SSH certificates for user: {e}");
    }
    // Clear GitHub refresh token to prevent further API access
    if let Err(e) = db::clear_user_github_refresh_token(&state.store, &target_id).await {
        tracing::error!("Failed to clear GitHub refresh token for user: {e}");
    }

    let data = serde_json::json!({
        "action": "revoke_credentials",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
        "keys_revoked": key_count,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminRevokeCredentials,
            Some(&admin.id),
            Some(&target.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_revoke_credentials audit event");
    }

    tracing::info!(
        "Admin {} revoked {} credentials for user {}",
        admin.email,
        key_count,
        target.email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// POST /admin/members/{id}/remove — Remove a user from the organization.
pub(crate) async fn remove_member(
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

    // Revoke SSH certificates before deleting. If revocation fails,
    // abort — delete_user would destroy the issued cert records,
    // making the certs permanently unrevocable.
    db::revoke_all_ssh_certificates_for_user(
        &state.store,
        &target_id,
        Some("User removed by admin"),
        Some(&admin.id),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to revoke SSH certificates for removed user: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "revocation_failed",
            "Failed to revoke SSH certificates",
        )
    })?;

    let deleted = db::delete_user(&state.store, &target_id).await?;
    if !deleted {
        return Err(member_gone());
    }

    let data = serde_json::json!({
        "action": "remove_user",
        "target_user_id": &*target_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminRemoveUser,
            Some(&admin.id),
            Some(&target_email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_remove_user audit event");
    }

    tracing::info!(
        "Admin {} removed user {} from organization",
        admin.email,
        target_email
    );

    Ok(Redirect::to("/admin").into_response())
}

/// 404 for a member document that vanished between the admin's read and the
/// mutation. The DB layer reported no document to change, so returning an
/// error (instead of logging an audit event and redirecting with success)
/// keeps the audit log truthful.
fn member_gone() -> ServiceError {
    ServiceError::api(StatusCode::NOT_FOUND, "not_found", "User not found")
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use axum::http::StatusCode;

    use crate::test_utils::*;

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

    // ---- No raw email in audit `data` payloads (member-management events) ----

    #[tokio::test]
    async fn member_management_audit_events_never_carry_a_raw_target_email() {
        // Regression test: `data.target_email` used to store the target's
        // address raw, which the audit events API then re-exposed verbatim
        // to `audit:read` token holders (a third party) even though emails
        // are documented as masked to domain-only. `target_user_id` (kept)
        // is how the admin UI resolves a display email now — at view time,
        // not baked into the stored event.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let cookie = admin_cookie(&token);
        let target_email = "target@example.com";
        let target = create_test_user_in_org(&state.store, target_email, &org.id, false).await;

        let actions = [
            "promote",
            "demote",
            "deactivate",
            "activate",
            "revoke-credentials",
            // "remove" last: it deletes the user.
            "remove",
        ];
        for action in actions {
            let (status, body) = http_post_form(
                &app,
                &format!("/admin/members/{}/{action}", target.id),
                "",
                &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::SEE_OTHER,
                "{action} should succeed: {body}"
            );
        }

        let events = state
            .audit
            .query_events(&crate::db::AuditEventFilter {
                user_id: Some(admin.id.clone()),
                ..crate::db::AuditEventFilter::default()
            })
            .await
            .expect("query audit events");
        let member_events: Vec<_> = events
            .iter()
            .filter(|e| e.event_type.starts_with("admin_"))
            .collect();
        assert_eq!(
            member_events.len(),
            actions.len(),
            "one audit event per action must be written"
        );
        for event in member_events {
            assert!(
                !event.data.contains(target_email),
                "{}'s data payload must not contain the raw target email; got {}",
                event.event_type,
                event.data
            );
            assert!(
                event.data.contains(&target.id),
                "{}'s data payload must still carry target_user_id; got {}",
                event.event_type,
                event.data
            );
        }
    }

    // ---- Security: SSH certificate revocation on admin actions ----

    /// Record an issued SSH cert for `user_id` so revocation has something to act on.
    async fn record_test_ssh_cert(state: &crate::AppState, user_id: &str) {
        let expires_at = jiff::Timestamp::now()
            .checked_add(jiff::Span::new().hours(8))
            .expect("future timestamp");
        crate::db::record_ssh_certificate_issuance(
            &state.store,
            42_000_001,
            user_id,
            "member@example.com",
            &["member".to_string()],
            expires_at,
        )
        .await
        .expect("record issuance");
    }

    #[tokio::test]
    async fn test_deactivate_member_revokes_ssh_certificates() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        record_test_ssh_cert(&state, &member.id).await;

        // Pre-condition: one issued cert, zero revoked.
        let issued_before =
            crate::db::get_issued_ssh_certificates_for_user(&state.store, &member.id)
                .await
                .unwrap();
        assert_eq!(issued_before.len(), 1, "setup: one cert should be issued");
        let revoked_before = crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .unwrap();
        assert!(revoked_before.is_empty(), "setup: no revocations yet");

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/deactivate", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "deactivate should succeed");

        // The cert should now appear in the revocation list.
        let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .unwrap();
        assert_eq!(
            revoked.len(),
            1,
            "deactivate_member must revoke all SSH certificates"
        );
        assert_eq!(
            revoked[0].serial, issued_before[0].serial,
            "revoked serial must match the issued cert"
        );
    }

    #[tokio::test]
    async fn test_revoke_member_credentials_revokes_ssh_certificates() {
        let (app, state) = test_app().await;
        let (_admin, token, member) = setup_admin_and_member(&state).await;
        let cookie = admin_cookie(&token);

        record_test_ssh_cert(&state, &member.id).await;

        let issued_before =
            crate::db::get_issued_ssh_certificates_for_user(&state.store, &member.id)
                .await
                .unwrap();
        assert_eq!(issued_before.len(), 1, "setup: one cert should be issued");

        let (status, _body) = http_post_form(
            &app,
            &format!("/admin/members/{}/revoke-credentials", member.id),
            "",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "revoke-credentials should succeed"
        );

        let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .unwrap();
        assert_eq!(
            revoked.len(),
            1,
            "revoke_member_credentials must revoke all SSH certificates"
        );
        assert_eq!(
            revoked[0].serial, issued_before[0].serial,
            "revoked serial must match the issued cert"
        );
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

    // ---- Concurrent-delete races: no success + no audit event on a miss ----

    #[tokio::test]
    async fn test_member_actions_return_404_when_target_vanishes_mid_update() {
        // Same bug class as the custom-policy toggle (issue #844): the
        // handlers discarded the bool from `update_user_admin_status` /
        // `update_user_active_status`, so a member deleted between the
        // admin's read and the update produced a success redirect plus a
        // fraudulent audit event. The modify hook deletes the target's doc
        // on the first OCC attempt, deterministically forcing the miss.
        use std::sync::{Arc, Mutex};

        for (action, kind) in [
            ("promote", "admin_promote"),
            ("demote", "admin_demote"),
            ("deactivate", "admin_deactivate"),
            ("activate", "admin_activate"),
        ] {
            let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let slot = Arc::clone(&target_slot);
            let (app, state) = test_app_with_modify_hook(move |store| {
                let writer = store.clone();
                store.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
                    let writer = writer.clone();
                    let doc_id = doc_id.to_string();
                    let slot = Arc::clone(&slot);
                    Box::pin(async move {
                        // Only delete the member under test — other documents
                        // (admin session bookkeeping) must stay intact.
                        let is_target =
                            slot.lock().expect("slot lock").as_deref() == Some(doc_id.as_str());
                        if attempt == 0 && is_target {
                            writer
                                .delete(&doc_id)
                                .await
                                .expect("delete target member doc");
                        }
                    })
                }));
            })
            .await;

            let (_admin, token, member) = setup_admin_and_member(&state).await;
            *target_slot.lock().expect("slot lock") = Some(member.id.clone());
            let cookie = admin_cookie(&token);

            let (status, body) = http_post_form(
                &app,
                &format!("/admin/members/{}/{action}", member.id),
                "",
                &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
            )
            .await;

            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{action}: a member deleted mid-update must produce 404, got {status}: {body}"
            );

            let events = state
                .audit
                .query_events(&crate::db::AuditEventFilter {
                    event_types: Some(vec![kind.to_string()]),
                    ..crate::db::AuditEventFilter::default()
                })
                .await
                .expect("query audit events");
            assert!(
                events.is_empty(),
                "{action}: no {kind} audit event may be logged when the update did not occur"
            );
        }
    }
}
