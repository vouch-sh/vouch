// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM token management — API and UI handlers.

use crate::AppState;
use crate::db;
use crate::handlers::HasVersion;
use crate::impl_template_response;
use crate::services::error::ServiceError;
use askama::Template;
use axum::Json;
use axum::extract::{OriginalUri, Query, State};
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

    // Validate inputs before auth to fail fast on obviously bad requests
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

    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    // Enforce 2-token limit
    let existing = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

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
    .await?;

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
}
