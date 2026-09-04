// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM token management — browser UI handlers.

use crate::AppState;
use crate::db;
use crate::db::CreateScimTokenParams;
use crate::db::documents::audit::ScimTokenAdminData;
use crate::error::ServiceError;
use crate::handlers::admin::flash;
use crate::impl_template_response;
use askama::Template;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::sync::Arc;

use super::{
    MAX_SCIM_TOKEN_DESCRIPTION_CHARS, compute_token_expiry, generate_scim_token, has_audit_read,
    requested_scope,
};
use crate::filters;
use crate::handlers::extractors::{AdminPage, OrgAdmin};
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::handlers::{ValidPath, ValidUuid};

// ============================================================================
// Admin UI — SCIM Token Management
// ============================================================================

/// Display row for SCIM tokens in the template.
///
/// Timestamps are passed through as `jiff::Timestamp` and rendered client-side
/// in the viewer's locale and timezone (see `static/js/common.js`), with the
/// `humandatetime` filter as the no-JS fallback.
pub(crate) struct ScimTokenRow {
    pub id: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    pub audit_read: bool,
}

/// SCIM tokens page template.
#[derive(Template)]
#[template(path = "admin/scim_tokens.html")]
pub(crate) struct AdminScimTokensTemplate {
    pub auth: AuthContext,
    pub tokens: Vec<ScimTokenRow>,
    pub flash_message: Option<String>,
    pub new_token: Option<String>,
}

impl_template_response!(AdminScimTokensTemplate);

/// Form data for creating a SCIM token.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateScimTokenForm {
    pub description: Option<String>,
    pub expires_in_days: i64,
    /// Grant the `audit:read` scope. HTML checkboxes omit the field
    /// entirely when unchecked, hence the default.
    #[serde(default)]
    pub audit_read: bool,
}

const REDIRECT_BASE: &str = "/admin/scim-tokens";

fn redirect_error(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_err(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

/// GET /admin/scim-tokens — SCIM token management page.
pub(crate) async fn admin_scim_tokens_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    admin: AdminPage,
) -> Response {
    let AdminPage {
        auth,
        user_id: _,
        org_id,
    } = admin;

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
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            audit_read: has_audit_read(&t.scope),
        })
        .collect();

    // Consume any flash messages set by a prior POST → redirect, then expire
    // the cookies in the response so a refresh doesn't re-show them.
    let messages = flash::read(&jar);
    let jar = flash::clear(jar);

    let body = AdminScimTokensTemplate {
        auth,
        tokens,
        flash_message: messages.err,
        new_token: None,
    };
    (jar, body).into_response()
}

/// POST /admin/scim-tokens — Create a new SCIM token (UI form).
pub(crate) async fn admin_create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<CreateScimTokenForm>,
) -> Result<Response, ServiceError> {
    // Validate inputs before auth to fail fast on obviously bad requests
    if let Some(ref desc) = form.description
        && desc.chars().count() > MAX_SCIM_TOKEN_DESCRIPTION_CHARS
    {
        return Ok(redirect_error(
            jar,
            "Description must be 256 characters or less",
        ));
    }

    if form.expires_in_days < 1 || form.expires_in_days > 365 {
        return Ok(redirect_error(
            jar,
            "Expiration must be between 1 and 365 days",
        ));
    }

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let generated = generate_scim_token()?;
    let expires_at = Some(compute_token_expiry(form.expires_in_days)?);

    // Filter empty description to None
    let description = form
        .description
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(String::from);

    // The 2-token limit is enforced inside the transaction: counting here and
    // inserting afterwards lets two concurrent requests both pass the check.
    let token_id = match db::create_scim_token(
        &state.store,
        &CreateScimTokenParams {
            org_id: &org_id,
            token_hash: &generated.hash,
            description: description.as_deref(),
            expires_at,
            scope: requested_scope(form.audit_read),
        },
    )
    .await
    {
        Ok(id) => id,
        // Hitting the cap is ordinary form input, not a server fault — keep the
        // flash-message redirect rather than rendering an API error page.
        Err(ServiceError::Api { code, message, .. }) if code == "token_limit_reached" => {
            return Ok(redirect_error(jar, &message));
        }
        Err(e) => return Err(e),
    };

    let data = ScimTokenAdminData {
        action: "create_scim_token",
        token_id: &token_id,
        admin_user_id: &admin.id,
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminCreateScimToken,
            Some(&admin.id),
            Some(&admin.email),
            &data,
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_create_scim_token audit event");
    }

    tracing::info!(
        "Admin {} created SCIM token {} for org {}",
        admin.email,
        token_id,
        org_id
    );

    // Re-fetch tokens and render the page directly (avoids leaking token in URL)
    let db_tokens = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

    let tokens: Vec<ScimTokenRow> = db_tokens
        .into_iter()
        .map(|t| ScimTokenRow {
            id: t.id,
            description: t.description,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            audit_read: has_audit_read(&t.scope),
        })
        .collect();

    let auth = get_resource_auth_context(&state, &jar).await;

    Ok(AdminScimTokensTemplate {
        auth,
        tokens,
        flash_message: None,
        // Deliberate render-boundary exposure: this page shows the token
        // once, at creation, which is its purpose (Askama needs Display).
        new_token: Some(generated.plaintext.expose_secret().to_string()),
    }
    .into_response())
}

/// POST /admin/scim-tokens/{id}/revoke — Revoke a SCIM token (UI form).
pub(crate) async fn admin_revoke_scim_token(
    State(state): State<Arc<AppState>>,
    admin: OrgAdmin,
    jar: CookieJar,
    ValidPath(token_id): ValidPath<ValidUuid>,
) -> Result<Response, ServiceError> {
    let OrgAdmin {
        user: admin,
        org_id,
    } = admin;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id).await?;

    if !deleted {
        return Ok(redirect_error(jar, "SCIM token not found"));
    }

    let data = ScimTokenAdminData {
        action: "revoke_scim_token",
        token_id: &token_id,
        admin_user_id: &admin.id,
    };
    if let Err(e) = state
        .audit
        .insert_event(
            db::AuditEventKind::AdminRevokeScimToken,
            Some(&admin.id),
            Some(&admin.email),
            &data,
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_revoke_scim_token audit event");
    }

    tracing::info!(
        "Admin {} revoked SCIM token {} for org {}",
        admin.email,
        token_id,
        org_id
    );

    Ok(Redirect::to("/admin/scim-tokens").into_response())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;
    use axum::http::StatusCode;

    const ORIGIN: &str = "https://test.example.com";

    fn location(resp: &HttpResponse) -> &str {
        resp.headers
            .get("location")
            .expect("redirect must carry a location header")
            .to_str()
            .expect("ascii location")
    }

    // ── GET /admin/scim-tokens (AdminPage: redirects, never JSON errors) ──

    #[tokio::test]
    async fn page_without_session_redirects_to_enroll() {
        let (app, _state) = test_app().await;

        let resp = http_get_full(&app, "/admin/scim-tokens", &[]).await;

        assert!(resp.status.is_redirection(), "got {}", resp.status);
        assert_eq!(location(&resp), "/enroll/start");
    }

    #[tokio::test]
    async fn page_for_non_admin_redirects_to_integrations() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let user =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/admin/scim-tokens", &[("Cookie", &cookie)]).await;

        assert!(resp.status.is_redirection(), "got {}", resp.status);
        assert_eq!(location(&resp), "/integrations");
    }

    #[tokio::test]
    async fn page_renders_for_unverified_admin() {
        // The upstream IdP is the trust root for the browser: an admin
        // session minted by IdP sign-in alone (no FIDO2 ceremony) reads the
        // token-management page like any other signed-in admin.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                verification: TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/admin/scim-tokens", &[("Cookie", &cookie)]).await;

        assert_eq!(
            resp.status,
            StatusCode::OK,
            "a signed-in admin reads the page without a key ceremony"
        );
    }

    #[tokio::test]
    async fn page_renders_org_tokens_for_admin() {
        let (app, state) = test_app().await;
        let (admin, token) = create_test_org_admin(&state).await;
        let org_id = admin.org_id.expect("fixture admin belongs to an org");
        create_test_scim_token(&state.store, "provisioning token", &org_id).await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/admin/scim-tokens", &[("Cookie", &cookie)]).await;

        assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
        assert!(
            resp.body.contains("provisioning token"),
            "page must list the org's tokens"
        );
    }

    // ── POST /admin/scim-tokens (form: flash + redirect on bad input) ──

    #[tokio::test]
    async fn create_form_renders_token_once() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_post_form_full(
            &app,
            "/admin/scim-tokens",
            "description=CI+provisioning&expires_in_days=30",
            &[("Cookie", &cookie), ("Origin", ORIGIN)],
        )
        .await;

        assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
        assert!(
            resp.body.contains("vouch_scim_"),
            "the created token is shown once, on this response"
        );
    }

    #[tokio::test]
    async fn create_form_invalid_expiry_redirects_with_flash() {
        // Input validation runs before auth, so no session is needed to
        // observe the flash redirect.
        let (app, _state) = test_app().await;

        let resp = http_post_form_full(
            &app,
            "/admin/scim-tokens",
            "description=x&expires_in_days=0",
            &[("Origin", ORIGIN)],
        )
        .await;

        assert!(resp.status.is_redirection(), "got {}", resp.status);
        assert_eq!(location(&resp), "/admin/scim-tokens");
    }

    #[tokio::test]
    async fn create_form_long_description_redirects_with_flash() {
        let (app, _state) = test_app().await;
        let long = "x".repeat(crate::handlers::admin::MAX_SCIM_TOKEN_DESCRIPTION_CHARS + 1);

        let resp = http_post_form_full(
            &app,
            "/admin/scim-tokens",
            &format!("description={long}&expires_in_days=30"),
            &[("Origin", ORIGIN)],
        )
        .await;

        assert!(resp.status.is_redirection(), "got {}", resp.status);
        assert_eq!(location(&resp), "/admin/scim-tokens");
    }

    // ── POST /admin/scim-tokens/{id}/revoke ──

    #[tokio::test]
    async fn revoke_deletes_token_and_redirects() {
        let (app, state) = test_app().await;
        let (admin, token) = create_test_org_admin(&state).await;
        let org_id = admin.org_id.expect("fixture admin belongs to an org");
        create_test_scim_token(&state.store, "doomed", &org_id).await;
        let scim_tokens = crate::db::list_scim_tokens(&state.store, Some(&org_id))
            .await
            .expect("list tokens");
        let token_id = &scim_tokens.first().expect("one seeded token").id;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_post_form_full(
            &app,
            &format!("/admin/scim-tokens/{token_id}/revoke"),
            "",
            &[("Cookie", &cookie), ("Origin", ORIGIN)],
        )
        .await;

        assert!(resp.status.is_redirection(), "body: {}", resp.body);
        assert_eq!(location(&resp), "/admin/scim-tokens");
        let remaining = crate::db::list_scim_tokens(&state.store, Some(&org_id))
            .await
            .expect("list tokens");
        assert!(remaining.is_empty(), "the token must be gone");
    }

    #[tokio::test]
    async fn revoke_unknown_token_redirects_with_not_found_flash() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let cookie = format!("__Host-vouch_session={token}");
        let missing = uuid::Uuid::now_v7();

        let resp = http_post_form_full(
            &app,
            &format!("/admin/scim-tokens/{missing}/revoke"),
            "",
            &[("Cookie", &cookie), ("Origin", ORIGIN)],
        )
        .await;

        assert!(resp.status.is_redirection(), "body: {}", resp.body);
        assert_eq!(location(&resp), "/admin/scim-tokens");
    }

    #[tokio::test]
    async fn revoke_cannot_reach_another_orgs_token() {
        // delete_scim_token filters by org, so a foreign token behaves
        // exactly like a missing one and survives the attempt.
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let other_org = create_test_org(&state.store, "rival.example").await;
        create_test_scim_token(&state.store, "foreign", &other_org.id).await;
        let foreign = crate::db::list_scim_tokens(&state.store, Some(&other_org.id))
            .await
            .expect("list tokens");
        let foreign_id = &foreign.first().expect("one seeded token").id;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_post_form_full(
            &app,
            &format!("/admin/scim-tokens/{foreign_id}/revoke"),
            "",
            &[("Cookie", &cookie), ("Origin", ORIGIN)],
        )
        .await;

        assert!(resp.status.is_redirection(), "body: {}", resp.body);
        let survivors = crate::db::list_scim_tokens(&state.store, Some(&other_org.id))
            .await
            .expect("list tokens");
        assert_eq!(survivors.len(), 1, "the foreign token must survive");
    }
}
