// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Certification test-mode login handler.
//!
//! Provides `GET /certification/complete-login` — a bypass login path that lets
//! the OpenID Foundation conformance suite at `certification.openid.net` drive
//! the login flow without a physical FIDO2 key. Only registered when
//! `VOUCH_CERTIFICATION_TEST_TOKEN` is set; **never enable in production**.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use axum::http::header;
use jiff::Timestamp;

use crate::{
    AppState, db,
    handlers::browser_login::hmac_sha256_base64url,
    handlers::session::create_session_cookie,
    services::auth::{CreateOAuthTokenParams, create_oauth_access_token},
    services::oidc::ScopeSet,
};

/// Test user email used by the certification endpoint (never a real user).
const CERT_USER_EMAIL: &str = "cert-test@vouch.sh";

/// Query parameters for `GET /certification/complete-login`.
#[derive(Debug, Deserialize)]
pub struct CompleteLoginQuery {
    /// Pending OAuth authorization ID (UUID).
    pub pending_auth: String,
    /// HMAC-SHA256 of `pending_auth`, base64url-encoded (no padding).
    pub token: String,
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
pub async fn complete_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompleteLoginQuery>,
) -> Response {
    // ── 1. Token validation ───────────────────────────────────────────────
    let secret = match state.config().certification_test_token.as_ref() {
        Some(s) => s.expose_secret().to_string(),
        None => {
            tracing::error!("Certification endpoint called but token not configured");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let expected = hmac_sha256_base64url(&secret, &query.pending_auth);

    let token_valid: bool = expected.as_bytes().ct_eq(query.token.as_bytes()).into();
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
        tracing::warn!("Failed to delete previous cert sessions: {e}");
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
/// authorization and redirects to the client's callback URI with
/// `error=access_denied`.
pub async fn deny_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompleteLoginQuery>,
) -> Response {
    // Validate HMAC token.
    let secret = match state.config().certification_test_token.as_ref() {
        Some(s) => s.expose_secret().to_string(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let expected = hmac_sha256_base64url(&secret, &query.pending_auth);
    let token_valid: bool = expected.as_bytes().ct_eq(query.token.as_bytes()).into();
    if !token_valid {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Consume pending authorization.
    let pending =
        match db::consume_pending_oauth_authorization(&state.store, &query.pending_auth).await {
            Ok(Some(p)) => p,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

    // Redirect to callback with access_denied error (RFC 6749 Section 4.1.2.1).
    // When response_mode is JARM, wrap the error in a signed JWT.
    use crate::db::ResponseMode;
    let redirect_url = if pending.response_mode == ResponseMode::Jwt {
        let client = match db::get_oauth_client_by_client_id(&state.store, &pending.client_id).await
        {
            Ok(Some(c)) => c,
            _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        match crate::services::oidc::jarm::build_jarm_error_jwt(
            &state,
            &client,
            "access_denied",
            Some("User rejected authentication"),
            pending.state.as_deref(),
        )
        .await
        {
            Ok(jwt) => crate::handlers::oidc::build_jarm_redirect_url(&pending.redirect_uri, &jwt),
            Err(e) => {
                tracing::error!(error = %e, "Certification deny-login: JARM JWT signing failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        let mut redirect = match url::Url::parse(&pending.redirect_uri) {
            Ok(u) => u,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        {
            let mut q = redirect.query_pairs_mut();
            q.append_pair("error", "access_denied");
            q.append_pair("error_description", "User rejected authentication");
            if let Some(ref s) = pending.state {
                q.append_pair("state", s);
            }
            // RFC 9207: Authorization Response Issuer Identification.
            q.append_pair("iss", &state.config().base_url);
        }
        redirect.to_string()
    };

    tracing::info!(
        pending_auth = %query.pending_auth,
        "Certification deny-login: redirecting with access_denied"
    );

    Redirect::to(&redirect_url).into_response()
}

/// Get the certification test user, creating it if it doesn't exist.
///
/// The cert user is an org-less user (analogous to a consumer `@gmail.com`
/// enrollee). `enroll_user_with_org` with `domain: None` is atomic and
/// idempotent — it returns the existing user if one already exists.
async fn get_or_create_cert_user(state: &Arc<AppState>) -> anyhow::Result<db::User> {
    let result = db::enroll_user_with_org(
        &state.store,
        CERT_USER_EMAIL,
        Some("Certification Test User"),
        None,
    )
    .await?;

    db::get_user_by_id(&state.store, &result.user.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("cert user not found after enrollment"))
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
        user_id,
        user_email,
        "Certification Test Authenticator",
        &dummy_credential_id,
        &dummy_public_key,
        None,  // aaguid
        None,  // user_handle
        false, // attestation_verified
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
}
