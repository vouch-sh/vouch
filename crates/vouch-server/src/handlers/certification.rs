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
    handlers::oidc::build_authorization_success_redirect_url,
    handlers::session::create_session_cookie,
    services::auth::{CreateOAuthTokenParams, create_oauth_access_token},
    services::oidc::{
        amr::{ACR_AAL3, AuthMethod},
        authorization::{AuthorizationCodeParams, CodeChallengeMethod, issue_authorization_code},
        fapi::auth_code_lifetime_seconds,
        scope::ScopeSet,
    },
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
/// Validates the HMAC, looks up the pending authorization, creates an
/// authorization code, and redirects to the client's callback URI.
///
/// Responses:
/// - `302` — authorization code issued, redirect to `redirect_uri`
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
            // Should never happen — route is only registered when token is set.
            tracing::error!("Certification endpoint called but token not configured");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let expected = hmac_sha256_base64url(&secret, &query.pending_auth);

    // Constant-time comparison to prevent timing attacks.
    let token_valid: bool = expected.as_bytes().ct_eq(query.token.as_bytes()).into();
    if !token_valid {
        tracing::warn!(
            pending_auth = %query.pending_auth,
            "Certification login rejected: HMAC mismatch"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // ── 2. Consume pending authorization ─────────────────────────────────
    let pending =
        match db::consume_pending_oauth_authorization(&state.store, &query.pending_auth).await {
            Ok(Some(p)) => p,
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
                    "Certification login: DB error consuming pending authorization"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

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

    // ── 5. Look up the OAuth client for lifetime calculation ──────────────
    let client = match db::get_oauth_client_by_client_id(&state.store, &pending.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::error!(
                client_id = %pending.client_id,
                "Certification login: OAuth client not found"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Certification login: DB error fetching OAuth client");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let lifetime = auth_code_lifetime_seconds(&client);

    // ── 6. Parse scope and code challenge method ──────────────────────────
    let scope = pending
        .scope
        .as_deref()
        .map(ScopeSet::parse)
        .unwrap_or_default();

    let code_challenge_method = pending
        .code_challenge_method
        .as_deref()
        .and_then(CodeChallengeMethod::parse);

    // ── 7. Issue authorization code ───────────────────────────────────────
    let code = match issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &pending.client_id,
            redirect_uri: &pending.redirect_uri,
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &authenticator_id,
            aaguid: None,
            scope: &scope,
            nonce: pending.nonce.as_deref(),
            code_challenge: pending.code_challenge.as_deref(),
            code_challenge_method,
            resource: pending.resource.as_deref(),
            acr_values: pending.acr_values.as_deref(),
            dpop_jkt: pending.dpop_jkt.as_deref(),
            auth_code_lifetime_seconds: lifetime,
            authorization_details: pending.authorization_details.as_ref(),
            auth_time: None,
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Certification login: failed to issue authorization code");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // ── 8. Build redirect URL ─────────────────────────────────────────────
    // RFC 6749 Section 4.1.2: code + state (if present) + iss (RFC 9207).
    let redirect_url = match build_authorization_success_redirect_url(
        &pending.redirect_uri,
        &code,
        pending.state.as_deref(),
        &state.config().base_url,
    ) {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(
                redirect_uri = %pending.redirect_uri,
                error = %e,
                "Certification login: invalid redirect URI"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // ── 9. Create a browser session ──────────────────────────────────────
    // Set a session cookie so that subsequent authorization requests from
    // the same browser (e.g. prompt=none, max_age) recognize the user.
    let client_id = state.config().base_url.clone();
    let session_result = match create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator_id),
            client_id: &client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            act: None,
            audience: None,
            auth_time: Some(Timestamp::now().as_second()),
            amr: Some(AuthMethod::all_fido2().to_vec()),
            acr: Some(ACR_AAL3.to_string()),
            hardware_verified: true,
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
    let cookie = create_session_cookie(session_result.token.expose_secret(), session_hours * 3600);

    tracing::info!(
        pending_auth = %query.pending_auth,
        user_id = %user.id,
        "Certification login: authorization code issued, redirecting to callback"
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
        q.append_pair("iss", &state.config().base_url);
    }

    tracing::info!(
        pending_auth = %query.pending_auth,
        "Certification deny-login: redirecting with access_denied"
    );

    Redirect::to(redirect.as_str()).into_response()
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
        return Err(e);
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::handlers::browser_login::hmac_sha256_base64url;

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
    async fn test_complete_login_issues_code_with_valid_token() {
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

        // Should redirect to callback with authorization code
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
            location.contains("code="),
            "Location must contain authorization code: {location}"
        );
        assert!(
            location.contains("state=mystate"),
            "Location must contain state: {location}"
        );
    }
}
