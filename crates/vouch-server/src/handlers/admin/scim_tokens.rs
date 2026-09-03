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
