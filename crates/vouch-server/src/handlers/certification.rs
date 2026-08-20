// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Certification test-mode login handler.
//!
//! Provides `GET /certification/complete-login` — a bypass login path that lets
//! the OpenID Foundation conformance suite at `certification.openid.net` drive
//! the login flow without a physical FIDO2 key. Only registered when
//! `VOUCH_CERTIFICATION_TEST_TOKEN` is set; **never enable in production**.
//!
//! Setting that token is a broad test-mode switch (see `config.rs` and
//! `infra/router.rs`): besides this login bypass it also disables global rate
//! limiting and relaxes the upstream-IdP requirement. A leaked or mistakenly
//! set token in production therefore exposes a login-bypass-shaped endpoint.
//! Activation is deliberately not gated on TLS because conformance runs over
//! HTTPS with self-signed certs; the safeguards are operational discipline and
//! the loud startup warnings.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use axum::http::header;
use jiff::Timestamp;

use crate::{
    AppState, db,
    handlers::browser_login::hmac_sha256_base64url,
    handlers::session::create_session_cookie,
    services::auth::{
        ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof,
        TokenIssuanceProof, create_oauth_access_token,
    },
    services::oidc::ScopeSet,
};

/// Test user email used by the certification endpoint (never a real user).
const CERT_USER_EMAIL: &str = "cert-test@vouch.sh";

/// Query parameters for `GET /certification/complete-login`.
#[derive(Deserialize)]
pub(crate) struct CompleteLoginQuery {
    /// Pending OAuth authorization ID (UUID).
    pub pending_auth: String,
    /// HMAC-SHA256 of `pending_auth`, base64url-encoded (no padding).
    pub token: SecretString,
}

// Custom Debug that redacts the token to prevent accidental log exposure:
// presenting it alongside `pending_auth` is what completes the login.
impl std::fmt::Debug for CompleteLoginQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteLoginQuery")
            .field("pending_auth", &self.pending_auth)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// GET /certification/complete-login?pending_auth=<UUID>&token=<HMAC>
///
/// Validates the HMAC, creates a browser session for the test user, and
/// redirects back to the authorize endpoint with the pending auth ID.
/// The authorize endpoint then issues the authorization code via its
/// normal flow (matching the production browser login pattern).
///
/// Responses:
/// - `303` — session created, redirect to `/oauth/authorize?pending_auth=…`
/// - `403` — HMAC validation failed
/// - `404` — no pending authorization found for the given ID
/// - `500` — internal error
pub(crate) async fn complete_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompleteLoginQuery>,
) -> Response {
    // ── 1. Token validation ───────────────────────────────────────────────
    let config = state.config();
    let secret = match config.certification_test_token.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("Certification endpoint called but token not configured");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let expected = hmac_sha256_base64url(secret.expose_secret(), &query.pending_auth);

    let token_valid: bool = expected
        .as_bytes()
        .ct_eq(query.token.expose_secret().as_bytes())
        .into();
    if !token_valid {
        tracing::warn!(
            pending_auth = %query.pending_auth,
            "Certification login rejected: HMAC mismatch"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // ── 2. Validate pending authorization exists (read, don't consume) ────
    // The pending auth will be consumed by the authorize endpoint when
    // it issues the authorization code via handle_pending_auth.
    match db::get_pending_oauth_authorization(&state.store, &query.pending_auth).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            tracing::warn!(
                pending_auth = %query.pending_auth,
                "Certification login: pending authorization not found or already consumed"
            );
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => {
            tracing::error!(
                pending_auth = %query.pending_auth,
                error = %e,
                "Certification login: DB error reading pending authorization"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // ── 3. Get or create the certification test user ──────────────────────
    let user = match get_or_create_cert_user(&state).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Certification login: failed to get/create cert user");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // ── 4. Get or create the certification test authenticator ─────────────
    let authenticator_id =
        match get_or_create_cert_authenticator(&state, &user.id, &user.email).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Certification login: failed to get/create cert authenticator"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    // ── 5. Create a browser session ──────────────────────────────────────
    // Delete any previous sessions for the cert user first to prevent
    // session leakage between conformance test modules (which share a
    // browser context). Each module should start with a clean session.
    if let Err(e) = db::delete_sessions_for_user(&state.store, &user.id).await {
        tracing::error!("Failed to delete previous cert sessions: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to clear previous sessions",
        )
            .into_response();
    }

    let session_client_id = state.config().base_url.clone();
    let session_result = match create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator_id),
            client_id: &session_client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(Timestamp::now().as_second()),
            hardware_verification: crate::services::auth::HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            // Cert user has no org and the cert authenticator AAGUID isn't
            // exercised by conformance suites; omit both.
            hardware_aaguid: None,
            org_domain: None,
        },
        TokenIssuanceProof {
            grant: GrantProof::CertificationBypass,
            client_auth: ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
            sender_constraint: SenderConstraintProof::no_registered_client(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Certification login: failed to create session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let cookie = create_session_cookie(
        session_result.token.expose_secret(),
        session_hours.saturating_mul(3600),
    );

    // ── 6. Redirect to authorize endpoint with pending_auth ──────────────
    // This mirrors the production browser login flow: after authentication,
    // redirect to /oauth/authorize?pending_auth={id} where handle_pending_auth
    // consumes the pending auth, checks the session, and issues the code.
    let redirect_url = format!(
        "/oauth/authorize?pending_auth={}",
        urlencoding::encode(&query.pending_auth)
    );

    tracing::info!(
        pending_auth = %query.pending_auth,
        user_id = %user.id,
        "Certification login: session created, redirecting to authorize endpoint"
    );

    (
        [(header::SET_COOKIE, cookie.to_string())],
        Redirect::to(&redirect_url),
    )
        .into_response()
}

/// GET /certification/deny-login?pending_auth=<UUID>&token=<HMAC>
///
/// Simulates user rejection for conformance testing. Consumes the pending
/// authorization and returns an `access_denied` error to the client's
/// callback URI, dispatching on `response_mode` (JARM JWT, Form Post HTML
/// form, or query-string redirect) via the shared `oauth_error_response`
/// helper.
pub(crate) async fn deny_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompleteLoginQuery>,
) -> Response {
    // Validate HMAC token.
    let config = state.config();
    let secret = match config.certification_test_token.as_ref() {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let expected = hmac_sha256_base64url(secret.expose_secret(), &query.pending_auth);
    let token_valid: bool = expected
        .as_bytes()
        .ct_eq(query.token.expose_secret().as_bytes())
        .into();
    if !token_valid {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Consume pending authorization. The `_claim` witness is bound to
    // satisfy `#[must_use]`; downstream code uses `pending` directly.
    let (pending, _claim) =
        match db::consume_pending_oauth_authorization(&state.store, &query.pending_auth).await {
            Ok(pair) => pair,
            Err(db::claim::ClaimError::AlreadyConsumed) => {
                return StatusCode::NOT_FOUND.into_response();
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

    // Build the access_denied error response, dispatching on response_mode:
    // - Jwt:      JARM signed JWT delivered via the `response` query parameter.
    // - FormPost: HTTP 200 with an auto-submitting HTML form (OAuth 2.0 Form
    //   Post Response Mode); per RFC 6749 Section 4.1.2.1 errors MUST use the
    //   same delivery mechanism as success responses, so a 302 redirect is
    //   non-compliant here.
    // - Query:    HTTP 302 redirect with `error`/`error_description` query
    //   parameters (RFC 6749 Section 4.1.2.1).
    //
    // Reuses the shared `oauth_error_response` helper (the same one the
    // authorize endpoint uses) so deny-login stays consistent with the rest
    // of the authorization error paths, including the `iss` parameter
    // (RFC 9207) in every mode.
    let client = match db::get_oauth_client_by_client_id(&state.store, &pending.client_id).await {
        Ok(Some(c)) => c,
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    tracing::info!(
        pending_auth = %query.pending_auth,
        "Certification deny-login: returning access_denied"
    );

    crate::handlers::oidc::oauth_error_response(
        &state,
        &client,
        &pending.redirect_uri,
        "access_denied",
        "User rejected authentication",
        pending.state.as_deref(),
        pending.response_mode,
    )
    .await
}

/// Get the certification test user, creating it if it doesn't exist.
async fn get_or_create_cert_user(state: &Arc<AppState>) -> anyhow::Result<db::User> {
    // Try to find existing user first.
    if let Some(user) = db::get_user_by_email(&state.store, CERT_USER_EMAIL).await? {
        return Ok(user);
    }

    // Create new cert user via SCIM (no cfg gate, no special permissions).
    if let Err(e) = db::create_scim_user(
        &state.store,
        None,
        CERT_USER_EMAIL,
        Some("Certification Test User"),
        Some("cert-test"),
        true,
    )
    .await
    {
        // Handle concurrent create races by re-fetching and returning the
        // existing user if another request created it first.
        if let Some(user) = db::get_user_by_email(&state.store, CERT_USER_EMAIL).await? {
            return Ok(user);
        }
        return Err(e.into());
    }

    // Fetch the newly created user to get a full `User` record.
    db::get_user_by_email(&state.store, CERT_USER_EMAIL)
        .await?
        .ok_or_else(|| anyhow::anyhow!("cert user not found after creation"))
}

/// Get the certification test authenticator for `user_id`, creating one if
/// it doesn't exist. Returns the authenticator ID.
async fn get_or_create_cert_authenticator(
    state: &Arc<AppState>,
    user_id: &str,
    user_email: &str,
) -> anyhow::Result<String> {
    let authenticators = db::get_authenticators_for_user(&state.store, user_id).await?;
    if let Some(auth) = authenticators.into_iter().next() {
        return Ok(auth.id);
    }

    // Create a synthetic authenticator with dummy bytes.
    // The public key and credential ID are never used for signature verification —
    // this authenticator exists only so that `issue_authorization_code` has a
    // valid `authenticator_id` to record in the auth code JWT.
    let dummy_credential_id = [0u8; 32];
    let dummy_public_key = [0u8; 64];

    match db::create_authenticator(
        &state.store,
        &db::CreateAuthenticatorParams {
            user_id,
            user_email,
            name: "Certification Test Authenticator",
            credential_id: &dummy_credential_id,
            public_key: &dummy_public_key,
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    {
        Ok(id) => Ok(id),
        Err(e) => {
            // Handle concurrent create races by re-fetching an authenticator
            // if another request created one first.
            let authenticators = db::get_authenticators_for_user(&state.store, user_id).await?;
            if let Some(auth) = authenticators.into_iter().next() {
                return Ok(auth.id);
            }
            Err(e)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;
    use crate::handlers::browser_login::hmac_sha256_base64url;
    use crate::handlers::oidc::build_authorization_success_redirect_url;

    #[test]
    fn test_hmac_valid_token_accepted() {
        let secret = "test-secret-123";
        let pending_auth = "aaaaaaaa-bbbb-7ccc-dddd-eeeeeeeeeeee";
        let token = hmac_sha256_base64url(secret, pending_auth);
        let valid: bool = token.as_bytes().ct_eq(token.as_bytes()).into();
        assert!(valid, "Same HMAC must match itself");
    }

    #[test]
    fn test_hmac_wrong_secret_rejected() {
        let pending_auth = "aaaaaaaa-bbbb-7ccc-dddd-eeeeeeeeeeee";
        let token = hmac_sha256_base64url("correct-secret", pending_auth);
        let expected = hmac_sha256_base64url("wrong-secret", pending_auth);

        let valid: bool = expected.as_bytes().ct_eq(token.as_bytes()).into();
        assert!(!valid, "Different secret must not match");
    }

    #[test]
    fn test_hmac_wrong_message_rejected() {
        let secret = "test-secret-123";
        let token = hmac_sha256_base64url(secret, "pending-auth-1");
        let expected = hmac_sha256_base64url(secret, "pending-auth-2");

        let valid: bool = expected.as_bytes().ct_eq(token.as_bytes()).into();
        assert!(!valid, "Different pending_auth must not match");
    }

    #[test]
    fn test_build_certification_redirect_preserves_existing_query() {
        let redirect = build_authorization_success_redirect_url(
            "https://example.com/callback?existing=1",
            "code123",
            Some("state123"),
            "https://issuer.example.com",
        )
        .expect("redirect should be built successfully");

        let url = url::Url::parse(&redirect).expect("redirect must be a valid URL");
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        assert!(query_pairs.contains(&(String::from("existing"), String::from("1"))));
        assert!(query_pairs.contains(&(String::from("code"), String::from("code123"))));
        assert!(query_pairs.contains(&(String::from("state"), String::from("state123"))));
        assert!(query_pairs.contains(&(
            String::from("iss"),
            String::from("https://issuer.example.com")
        )));
    }

    #[test]
    fn test_build_certification_redirect_invalid_uri_returns_error() {
        let result = build_authorization_success_redirect_url(
            "://not-a-valid-url",
            "code123",
            Some("state123"),
            "https://issuer.example.com",
        );

        assert!(result.is_err(), "invalid redirect URI should return error");
    }

    #[tokio::test]
    async fn test_complete_login_returns_forbidden_with_wrong_token() {
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-owner-forbidden@example.com")
                .await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id: &client.client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: Some("state123"),
                scope: Some("openid"),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                acr_values: None,
                max_age: None,
                prompt: None,
                dpop_jkt: None,
                authorization_details: None,
                response_mode: Default::default(),
                par_request_uri: None,
            },
        )
        .await
        .expect("Failed to create pending auth");

        let resp = crate::test_utils::http_get_full(
            &app,
            &format!("/certification/complete-login?pending_auth={pending_id}&token=invaliddtoken"),
            &[],
        )
        .await;

        assert_eq!(resp.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_complete_login_redirects_to_authorize_with_valid_token() {
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-owner-valid@example.com").await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id: &client.client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: Some("mystate"),
                scope: Some("openid"),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                acr_values: None,
                max_age: None,
                prompt: None,
                dpop_jkt: None,
                authorization_details: None,
                response_mode: Default::default(),
                par_request_uri: None,
            },
        )
        .await
        .expect("Failed to create pending auth");

        let secret = state
            .config()
            .certification_test_token
            .as_ref()
            .expect("token must be set")
            .expose_secret()
            .to_string();
        let token = hmac_sha256_base64url(&secret, &pending_id);

        let resp = crate::test_utils::http_get_full(
            &app,
            &format!("/certification/complete-login?pending_auth={pending_id}&token={token}"),
            &[],
        )
        .await;

        // Should redirect to authorize endpoint with pending_auth
        assert!(
            resp.status == axum::http::StatusCode::FOUND
                || resp.status == axum::http::StatusCode::SEE_OTHER,
            "Expected redirect, got {}",
            resp.status
        );

        let location = resp
            .headers
            .get("location")
            .expect("redirect must have location")
            .to_str()
            .expect("location must be valid string");

        assert!(
            location.contains("pending_auth="),
            "Location must redirect to authorize with pending_auth: {location}"
        );
        assert!(
            location.starts_with("/oauth/authorize"),
            "Location must redirect to authorize endpoint: {location}"
        );

        // Should set a session cookie
        assert!(
            resp.headers.get("set-cookie").is_some(),
            "Response must set a session cookie"
        );
    }

    // ── deny_login tests ───────────────────────────────────────────────

    /// Create a pending OAuth authorization for `client_id` with the given
    /// `response_mode` and `state`, then return a valid certification
    /// deny-login URL (HMAC token included).
    async fn setup_deny_login_url(
        state: &Arc<AppState>,
        client_id: &str,
        response_mode: crate::db::ResponseMode,
        state_param: Option<&str>,
    ) -> String {
        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: state_param,
                scope: Some("openid"),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                acr_values: None,
                max_age: None,
                prompt: None,
                dpop_jkt: None,
                authorization_details: None,
                response_mode,
                par_request_uri: None,
            },
        )
        .await
        .expect("Failed to create pending auth");

        let secret = state
            .config()
            .certification_test_token
            .as_ref()
            .expect("token must be set")
            .expose_secret()
            .to_string();
        let token = hmac_sha256_base64url(&secret, &pending_id);
        format!("/certification/deny-login?pending_auth={pending_id}&token={token}")
    }

    #[tokio::test]
    async fn test_deny_login_returns_forbidden_with_wrong_token() {
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-deny-forbidden@example.com")
                .await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        // Create the pending auth directly so we control the (wrong) token.
        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id: &client.client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: Some("mystate"),
                scope: Some("openid"),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                acr_values: None,
                max_age: None,
                prompt: None,
                dpop_jkt: None,
                authorization_details: None,
                response_mode: crate::db::ResponseMode::Query,
                par_request_uri: None,
            },
        )
        .await
        .expect("Failed to create pending auth");

        let resp = crate::test_utils::http_get_full(
            &app,
            &format!("/certification/deny-login?pending_auth={pending_id}&token=wrong-token"),
            &[],
        )
        .await;

        assert_eq!(
            resp.status,
            axum::http::StatusCode::FORBIDDEN,
            "wrong HMAC token must be rejected"
        );
    }

    #[tokio::test]
    async fn test_deny_login_returns_not_found_for_consumed_auth() {
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-deny-consumed@example.com")
                .await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let url = setup_deny_login_url(
            &state,
            &client.client_id,
            crate::db::ResponseMode::Query,
            None,
        )
        .await;

        // First call consumes the pending auth.
        let resp1 = crate::test_utils::http_get_full(&app, &url, &[]).await;
        assert!(
            resp1.status.is_redirection(),
            "first deny-login should succeed, got {}",
            resp1.status
        );

        // Second call must report the pending auth as gone.
        let resp2 = crate::test_utils::http_get_full(&app, &url, &[]).await;
        assert_eq!(
            resp2.status,
            axum::http::StatusCode::NOT_FOUND,
            "already-consumed pending auth must return 404"
        );
    }

    #[tokio::test]
    async fn test_deny_login_form_post_returns_html_form() {
        // OAuth 2.0 Form Post Response Mode: deny-login MUST return HTTP 200
        // with an auto-submitting HTML form carrying the error parameters —
        // NOT a 302 redirect with query params.
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-deny-formpost@example.com")
                .await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let url = setup_deny_login_url(
            &state,
            &client.client_id,
            crate::db::ResponseMode::FormPost,
            Some("deny-state"),
        )
        .await;

        let resp = crate::test_utils::http_get_full(&app, &url, &[]).await;

        // Must be 200 OK — not a redirect.
        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "form_post deny-login must be HTTP 200, not a redirect: {}",
            resp.body
        );

        // Must NOT carry a Location header (it is not a redirect).
        assert!(
            resp.headers.get("location").is_none(),
            "form_post deny-login must not redirect"
        );

        // Must contain an HTML form targeting the redirect_uri via POST.
        assert!(
            resp.body.contains(r#"method="post""#),
            "form_post deny-login must contain a POST form: {}",
            resp.body
        );
        assert!(
            resp.body.contains("https://example.com/callback"),
            "form_post deny-login form must target the redirect_uri"
        );

        // Must carry the error parameters as hidden inputs.
        assert!(
            resp.body.contains(r#"name="error""#),
            "form_post deny-login must contain a hidden 'error' input"
        );
        assert!(
            resp.body.contains(r#"name="error_description""#),
            "form_post deny-login must contain a hidden 'error_description' input"
        );
        assert!(
            resp.body.contains("access_denied"),
            "form_post deny-login must carry error=access_denied"
        );
        assert!(
            resp.body.contains("User rejected authentication"),
            "form_post deny-login must carry the error_description"
        );

        // RFC 9207: iss must be present.
        assert!(
            resp.body.contains(r#"name="iss""#),
            "form_post deny-login must contain a hidden 'iss' input (RFC 9207)"
        );

        // State must be echoed.
        assert!(
            resp.body.contains("deny-state"),
            "form_post deny-login must echo the state parameter"
        );

        // Content-Type must be HTML.
        let content_type = resp
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/html"),
            "form_post deny-login must be text/html, got: {content_type}"
        );
    }

    #[tokio::test]
    async fn test_deny_login_form_post_omits_state_when_absent() {
        // When no `state` was sent in the authorization request, the
        // form_post response must not include a `state` input.
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user = crate::test_utils::create_test_user(
            &state.store,
            "cert-deny-formpost-nostate@example.com",
        )
        .await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let url = setup_deny_login_url(
            &state,
            &client.client_id,
            crate::db::ResponseMode::FormPost,
            None,
        )
        .await;

        let resp = crate::test_utils::http_get_full(&app, &url, &[]).await;

        assert_eq!(resp.status, axum::http::StatusCode::OK);
        assert!(
            !resp.body.contains(r#"name="state""#),
            "form_post deny-login must omit state when none was provided: {}",
            resp.body
        );
        // error and iss must still be present.
        assert!(resp.body.contains(r#"name="error""#));
        assert!(resp.body.contains(r#"name="iss""#));
    }

    #[tokio::test]
    async fn test_deny_login_query_returns_redirect_with_error() {
        // Query mode: deny-login MUST return a 302 redirect with error and
        // error_description encoded in the query string (RFC 6749 4.1.2.1).
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-deny-query@example.com").await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let url = setup_deny_login_url(
            &state,
            &client.client_id,
            crate::db::ResponseMode::Query,
            Some("q-state"),
        )
        .await;

        let resp = crate::test_utils::http_get_full(&app, &url, &[]).await;

        assert!(
            resp.status.is_redirection(),
            "query deny-login must redirect, got {}",
            resp.status
        );

        let location = resp
            .headers
            .get("location")
            .expect("query deny-login must have Location header")
            .to_str()
            .expect("Location must be valid string");

        let parsed = url::Url::parse(location).expect("Location must be a valid URL");
        let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();

        assert_eq!(parsed.host_str(), Some("example.com"));
        assert_eq!(parsed.path(), "/callback");
        assert!(
            pairs.contains(&("error".to_string(), "access_denied".to_string())),
            "query deny-login must carry error=access_denied: {location}"
        );
        assert!(
            pairs.contains(&(
                "error_description".to_string(),
                "User rejected authentication".to_string()
            )),
            "query deny-login must carry error_description: {location}"
        );
        assert!(
            pairs.contains(&("state".to_string(), "q-state".to_string())),
            "query deny-login must echo state: {location}"
        );
        assert!(
            pairs.contains(&("iss".to_string(), "https://test.example.com".to_string())),
            "query deny-login must include iss (RFC 9207): {location}"
        );
    }

    #[tokio::test]
    async fn test_deny_login_jwt_returns_jarm_redirect() {
        // JARM mode: deny-login MUST return a redirect whose `response`
        // query parameter carries a signed JWT containing the error.
        let (app, state) = crate::test_utils::test_app_with_certification().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cert-deny-jwt@example.com").await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;

        let url = setup_deny_login_url(
            &state,
            &client.client_id,
            crate::db::ResponseMode::Jwt,
            Some("j-state"),
        )
        .await;

        let resp = crate::test_utils::http_get_full(&app, &url, &[]).await;

        assert!(
            resp.status.is_redirection(),
            "jwt deny-login must redirect, got {}",
            resp.status
        );

        let location = resp
            .headers
            .get("location")
            .expect("jwt deny-login must have Location header")
            .to_str()
            .expect("Location must be valid string");

        let parsed = url::Url::parse(location).expect("Location must be a valid URL");
        let response_param: Option<String> = parsed
            .query_pairs()
            .find(|(k, _)| k == "response")
            .map(|(_, v)| v.into_owned());

        let jwt = response_param.expect("jwt deny-login must carry a `response` JWT parameter");

        // The JARM JWT is a three-part base64url-encoded JWT.
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "JARM response must be a compact JWT (header.payload.signature)"
        );

        // Decode the payload and verify it carries the error claims.
        use base64::Engine;
        let payload_segment = parts.get(1).expect("JWT has a payload segment");
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_segment)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_segment))
            .expect("JARM payload must be valid base64");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("JARM payload must be valid JSON");

        assert_eq!(
            payload.get("error").and_then(serde_json::Value::as_str),
            Some("access_denied"),
            "JARM JWT must carry error=access_denied"
        );
        assert_eq!(
            payload
                .get("error_description")
                .and_then(serde_json::Value::as_str),
            Some("User rejected authentication"),
            "JARM JWT must carry error_description"
        );
        assert_eq!(
            payload.get("state").and_then(serde_json::Value::as_str),
            Some("j-state"),
            "JARM JWT must echo state"
        );
        assert_eq!(
            payload.get("iss").and_then(serde_json::Value::as_str),
            Some("https://test.example.com"),
            "JARM JWT must carry iss (the AS issuer)"
        );
        assert_eq!(
            payload.get("aud").and_then(serde_json::Value::as_str),
            Some(client.client_id.as_str()),
            "JARM JWT must be audience-bound to the client"
        );
    }
}
