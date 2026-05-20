// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM token management — API and UI handlers.

use crate::AppState;
use crate::db;
use crate::handlers::HasVersion;
use crate::handlers::admin::flash;
use crate::impl_template_response;
use crate::services::error::ServiceError;
use askama::Template;
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::sync::Arc;

use super::{MAX_SCIM_TOKENS, compute_token_expiry, format_timestamp, generate_scim_token};
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::handlers::{ValidPath, ValidUuid};

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
///
/// `Debug` is hand-implemented to redact the bearer token; do not derive.
#[derive(serde::Serialize)]
pub struct CreateScimTokenResponse {
    pub id: String,
    pub token: String,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
}

impl std::fmt::Debug for CreateScimTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateScimTokenResponse")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("description", &self.description)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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
    // Validate inputs before auth to fail fast on obviously bad requests
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

    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Enforce 2-token limit
    let existing = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

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
    .await?;

    let data = serde_json::json!({
        "action": "create_scim_token",
        "token_id": token_id,
        "admin_user_id": user.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "admin_create_scim_token",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_create_scim_token audit event");
    }

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
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let tokens = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

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
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id).await?;

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
    if let Err(e) = state
        .audit
        .insert_event(
            "admin_delete_scim_token",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write admin_delete_scim_token audit event");
    }

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
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

/// Form data for creating a SCIM token.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenForm {
    pub description: Option<String>,
    pub expires_in_days: i64,
}

const REDIRECT_BASE: &str = "/admin/scim-tokens";

fn redirect_error(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_err(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

/// GET /admin/scim-tokens — SCIM token management page.
pub async fn admin_scim_tokens_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
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
pub async fn admin_create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<CreateScimTokenForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;

    // Validate inputs before auth to fail fast on obviously bad requests
    if let Some(ref desc) = form.description
        && desc.len() > 256
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

    // Enforce 2-token limit
    let existing = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

    if existing.len() >= MAX_SCIM_TOKENS {
        return Ok(redirect_error(
            jar,
            "Maximum of 2 SCIM tokens. Revoke one before creating another.",
        ));
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
    .await?;

    let data = serde_json::json!({
        "action": "create_scim_token",
        "token_id": token_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "admin_create_scim_token",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
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
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id).await?;

    if !deleted {
        return Ok(redirect_error(jar, "SCIM token not found"));
    }

    let data = serde_json::json!({
        "action": "revoke_scim_token",
        "token_id": &*token_id,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "admin_revoke_scim_token",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
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
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
    // Input validation runs before auth (fail fast on bad input)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_invalid_expiry_returns_400_without_auth() {
        let (app, _state) = test_app().await;

        // Invalid expires_in_days returns 400 (input validation before auth)
        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 0}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Invalid input must return 400 before auth check"
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

        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            &body_json,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Invalid input must return 400 before auth check"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_valid_input_returns_401_without_auth() {
        let (app, _state) = test_app().await;

        // Valid input but no auth → 401 (input validation passes, auth fails)
        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 30}"#,
            &[], // No auth header
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Valid input without auth must return 401"
        );
    }

    // ================================================================
    // Token generation helper tests
    // ================================================================

    #[test]
    fn test_generate_scim_token_has_prefix_and_hash() {
        let generated = super::super::generate_scim_token().unwrap();
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
        let a = super::super::generate_scim_token().unwrap();
        let b = super::super::generate_scim_token().unwrap();
        assert_ne!(
            a.plaintext.expose_secret(),
            b.plaintext.expose_secret(),
            "tokens must be unique"
        );
    }

    #[test]
    fn test_compute_token_expiry_valid_days() {
        let expiry = super::super::compute_token_expiry(30).unwrap();
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
        let expiry = super::super::compute_token_expiry(1).unwrap();
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
        let expiry = super::super::compute_token_expiry(365).unwrap();
        let now = jiff::Timestamp::now();
        let diff_secs = expiry.duration_since(now).as_secs();
        let expected_secs: i64 = 365 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 5 && diff_secs <= expected_secs + 5,
            "365 days should be ~{expected_secs}s, got {diff_secs}s"
        );
    }

    // ================================================================
    // Authenticated CRUD — Create (positive)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_succeeds() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(resp["id"].as_str().is_some(), "response must contain id");
        let scim_token = resp["token"].as_str().expect("response must contain token");
        assert!(
            scim_token.starts_with("vouch_scim_"),
            "token must start with vouch_scim_, got: {scim_token}"
        );
        assert_eq!(
            resp["description"].as_str(),
            Some("CI provisioning"),
            "description must match"
        );
        assert!(
            resp["expires_at"].as_str().is_some(),
            "expires_at must be present"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_custom_expiry() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "long-lived", "expires_in_days": 365}"#,
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let expires_at_str = resp["expires_at"]
            .as_str()
            .expect("expires_at must be present");
        let expires_at: jiff::Timestamp = expires_at_str
            .parse()
            .expect("expires_at must be valid timestamp");
        let now = jiff::Timestamp::now();
        let diff_secs = expires_at.duration_since(now).as_secs();
        let expected_secs: i64 = 365 * 24 * 3600;
        assert!(
            diff_secs >= expected_secs - 60 && diff_secs <= expected_secs + 60,
            "expires_at should be ~365 days from now, diff was {diff_secs}s"
        );
    }

    // ================================================================
    // Authenticated CRUD — Create (negative)
    // ================================================================

    #[tokio::test]
    async fn test_create_scim_token_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 30}"#,
            &[],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "missing auth must return 401"
        );
    }

    #[tokio::test]
    async fn test_create_scim_token_requires_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session(&state, &member.id, &member.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        let (status, _body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "test", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "non-admin must receive 403");
    }

    #[tokio::test]
    async fn test_create_scim_token_max_limit() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        // Create first token
        let (status, _) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "first", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first token must succeed");

        // Create second token
        let (status, _) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "second", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "second token must succeed");

        // Third token must be rejected with 409
        let (status, body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "third", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "third token must return 409; body: {body}"
        );
    }

    // ================================================================
    // Authenticated CRUD — List (positive)
    // ================================================================

    #[tokio::test]
    async fn test_list_scim_tokens_empty() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        let (status, body) = http_get(
            &app,
            "/api/v1/org/scim-tokens",
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let tokens = resp["tokens"].as_array().expect("tokens must be an array");
        assert!(tokens.is_empty(), "no tokens created, list must be empty");
    }

    #[tokio::test]
    async fn test_list_scim_tokens_returns_created() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        // Create a token
        let (status, create_body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "listed token", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "create must succeed; body: {create_body}"
        );
        let created: serde_json::Value = serde_json::from_str(&create_body).expect("valid JSON");
        let created_id = created["id"].as_str().expect("id present");

        // List tokens — should contain the created one
        let (status, list_body) = http_get(
            &app,
            "/api/v1/org/scim-tokens",
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "list must succeed; body: {list_body}"
        );
        let resp: serde_json::Value = serde_json::from_str(&list_body).expect("valid JSON");
        let tokens = resp["tokens"].as_array().expect("tokens must be an array");
        assert_eq!(tokens.len(), 1, "list must contain exactly one token");
        assert_eq!(
            tokens[0]["id"].as_str(),
            Some(created_id),
            "listed token id must match created id"
        );
        assert_eq!(
            tokens[0]["description"].as_str(),
            Some("listed token"),
            "listed token description must match"
        );
    }

    // ================================================================
    // Authenticated CRUD — List (negative)
    // ================================================================

    #[tokio::test]
    async fn test_list_scim_tokens_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/api/v1/org/scim-tokens", &[]).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "missing auth must return 401"
        );
    }

    // ================================================================
    // Authenticated CRUD — Delete (positive)
    // ================================================================

    #[tokio::test]
    async fn test_delete_scim_token_succeeds() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        // Create a token to delete
        let (status, create_body) = http_post_json(
            &app,
            "/api/v1/org/scim-tokens",
            r#"{"description": "to delete", "expires_in_days": 30}"#,
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "create must succeed; body: {create_body}"
        );
        let resp: serde_json::Value = serde_json::from_str(&create_body).expect("valid JSON");
        let token_id = resp["id"].as_str().expect("id present");

        // Delete the token
        let (status, _body) = http_delete(
            &app,
            &format!("/api/v1/org/scim-tokens/{token_id}"),
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT, "delete must return 204");
    }

    // ================================================================
    // Authenticated CRUD — Delete (negative)
    // ================================================================

    #[tokio::test]
    async fn test_delete_scim_token_not_found() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session(&state, &admin.id, &admin.email, &auth_id).await;
        let auth_header = format!("Bearer {token}");

        let nonexistent_id = uuid::Uuid::now_v7();
        let (status, _body) = http_delete(
            &app,
            &format!("/api/v1/org/scim-tokens/{nonexistent_id}"),
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "unknown token id must return 404"
        );
    }

    #[tokio::test]
    async fn test_delete_scim_token_requires_auth() {
        let (app, _state) = test_app().await;
        let token_id = uuid::Uuid::now_v7();

        let (status, _body) =
            http_delete(&app, &format!("/api/v1/org/scim-tokens/{token_id}"), &[]).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "missing auth must return 401"
        );
    }
}
