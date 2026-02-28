// SPDX-License-Identifier: BUSL-1.1
//! Browser-based WebAuthn login handlers.
//!
//! Implements the browser login flow for OAuth authorization (RFC 6749, RFC 9700).
//! When a user accesses `/oauth/authorize` without a valid session, they are
//! redirected to `/login` where they can authenticate using their registered
//! WebAuthn credential (discoverable credential / passkey).
//!
//! ## Endpoints
//!
//! - `GET /login` - Login page with WebAuthn UI
//! - `POST /login/webauthn/start` - Generate WebAuthn challenge
//! - `POST /login/webauthn/complete` - Verify assertion and create session
//!
//! ## Security Features
//!
//! - Origin header validation (CSRF protection)
//! - Challenge expiration (5 minutes)
//! - Single-use challenges
//! - Session binding to authenticator

use super::extractors::ClientInfo;
use crate::AppState;
use crate::crypto::generate_challenge;
use crate::crypto::webauthn_verify;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::handlers::errors::json_error;
use crate::handlers::session::{create_session_cookie, get_auth_context};
use crate::impl_template_response;
use crate::redact_email;
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
use crate::services::oidc::amr::{ACR_AAL3, AuthMethod};
use crate::services::oidc::scope::ScopeSet;
use askama::Template;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    ApiError, BrowserLoginCompleteRequest, BrowserLoginCompleteResponse, BrowserLoginStartRequest,
    BrowserLoginStartResponse,
};

// ============================================================================
// Templates
// ============================================================================

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    /// Pending OAuth authorization ID (if coming from /oauth/authorize).
    pub pending_auth: Option<String>,
    /// OAuth client name (for display).
    pub client_name: Option<String>,
    /// Relying Party ID for WebAuthn.
    pub rp_id: String,
    /// Authentication context for header.
    pub auth: crate::handlers::session::AuthContext,
}

impl_template_response!(LoginTemplate);

// ============================================================================
// Validation Constants
// ============================================================================

/// Maximum encoded length for `credential_id` (base64url).
/// WebAuthn spec allows up to 1023 bytes raw ≈ 1364 chars encoded.
const MAX_CREDENTIAL_ID_LEN: usize = 1400;

/// Maximum encoded length for `authenticator_data` (base64url).
/// Authenticator data is typically 37+ bytes; with extensions it can be larger.
const MAX_AUTHENTICATOR_DATA_LEN: usize = 4 * 1024;

/// Maximum encoded length for `client_data_json` (base64url).
/// Client data JSON is a small JSON object (origin, type, challenge).
const MAX_CLIENT_DATA_JSON_LEN: usize = 4 * 1024;

/// Maximum encoded length for `signature` (base64url).
/// ECDSA/EdDSA signatures are typically under 100 bytes.
const MAX_SIGNATURE_LEN: usize = 1024;

/// Maximum encoded length for `user_handle` (base64url).
/// User handles are 16-byte UUIDs ≈ 22 chars encoded.
const MAX_USER_HANDLE_LEN: usize = 256;

/// Maximum encoded length for the authentication `state` JWT.
const MAX_STATE_TOKEN_LEN: usize = 8 * 1024;

/// Minimum decoded byte length for a valid credential ID.
const MIN_CREDENTIAL_ID_BYTES: usize = 16;

/// Maximum decoded byte length for a valid credential ID (WebAuthn spec).
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;


// ============================================================================
// Authentication State
// ============================================================================

/// Browser authentication state stored between start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct BrowserAuthenticationState {
    /// Challenge bytes.
    challenge: Vec<u8>,
    /// Relying Party ID.
    rp_id: String,
    /// When this challenge was created.
    created_at: i64,
    /// When this challenge expires.
    exp: i64,
    /// Pending OAuth authorization ID (if any).
    pending_auth: Option<String>,
}

impl BrowserAuthenticationState {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::encode_state_token(
            self,
            crate::crypto::jwt::JwtType::BrowserAuthenticationState,
            secret.as_bytes(),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::decode_state_token(
            token,
            crate::crypto::jwt::JwtType::BrowserAuthenticationState,
            secret.as_bytes(),
        )
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /login
///
/// Login page for browser-based WebAuthn authentication.
/// Accepts optional `pending_auth` query parameter to resume OAuth flow after login.
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Pending OAuth authorization ID.
    pending_auth: Option<String>,
}

pub async fn login_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let auth = get_auth_context(&state, &jar).await;

    // Validate pending_auth is a UUID before DB lookup.
    if let Some(ref pending_id) = query.pending_auth
        && uuid::Uuid::try_parse(pending_id).is_err()
    {
        return axum::response::Redirect::to("/login").into_response();
    }

    // If already authenticated and have pending_auth, redirect back to authorize
    if auth.authenticated {
        if let Some(ref pending_id) = query.pending_auth {
            return axum::response::Redirect::to(&format!(
                "/oauth/authorize?pending_auth={}",
                urlencoding::encode(pending_id)
            ))
            .into_response();
        }
        // If authenticated without pending_auth, redirect to home
        return axum::response::Redirect::to("/").into_response();
    }

    // Get client name if we have a pending auth
    let client_name = if let Some(ref pending_id) = query.pending_auth {
        match db::get_pending_oauth_authorization(&state.store, pending_id).await {
            Ok(Some(pending)) => {
                match db::get_oauth_client_by_client_id(&state.store, &pending.client_id).await {
                    Ok(Some(client)) => Some(client.name),
                    _ => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };

    LoginTemplate {
        pending_auth: query.pending_auth,
        client_name,
        rp_id: state.config().rp_id.clone(),
        auth,
    }
    .into_response()
}

/// POST /login/webauthn/start
///
/// Generate a WebAuthn authentication challenge.
/// Uses discoverable credentials (passkeys) so the authenticator identifies the user.
pub async fn browser_login_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BrowserLoginStartRequest>,
) -> Result<Json<BrowserLoginStartResponse>, (StatusCode, Json<ApiError>)> {
    // Validate Origin header for CSRF protection (RFC 9700)
    validate_origin(&headers, &state.config().base_url)?;

    tracing::info!("Browser login start (discoverable credential flow)");

    // Generate challenge
    let challenge = generate_challenge().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate challenge",
        )
    })?;
    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().minutes(5))
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "time_error",
                "Time calculation overflow",
            )
        })?
        .as_second();

    // Create state token
    let auth_state = BrowserAuthenticationState {
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        created_at: now.as_second(),
        exp,
        pending_auth: req.pending_auth,
    };

    let state_token = auth_state
        .encode(state.config().jwt_secret.expose_secret())
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_error",
                &e.to_string(),
            )
        })?;

    Ok(Json(BrowserLoginStartResponse {
        challenge: URL_SAFE_NO_PAD.encode(&challenge),
        rp_id: state.config().rp_id.clone(),
        state: state_token,
        timeout: 300_000, // 5 minutes in milliseconds
        user_verification: "required".to_string(),
    }))
}

/// POST /login/webauthn/complete
///
/// Verify WebAuthn assertion and create session.
///
/// Validation is ordered to fail fast before any database access:
/// 1. Origin header validation (CSRF protection)
/// 2. Field length bounds (reject obviously oversized/empty fields)
/// 3. State JWT decode + expiration check
/// 4. Base64url decode all fields
/// 5. Credential ID byte length validation
/// 6. Client data JSON structure validation (type, origin)
/// 7. Database operations (authenticator lookup, signature verification)
#[allow(clippy::too_many_lines)]
pub async fn browser_login_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    _jar: CookieJar,
    Json(req): Json<BrowserLoginCompleteRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    // ── Phase 1: Origin header validation ────────────────────────────────
    validate_origin(&headers, &state.config().base_url)?;

    tracing::info!("Browser login complete (discoverable credential flow)");

    // Extract client info for audit logging
    let client_info = ClientInfo::from_headers(&headers);

    // ── Phase 2: Field length bounds ─────────────────────────────────────
    // Reject obviously oversized or empty fields before any processing.
    if req.state.len() > MAX_STATE_TOKEN_LEN {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "State token exceeds maximum length",
        ));
    }
    if req.credential_id.is_empty() || req.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Credential ID is empty or exceeds maximum length",
        ));
    }
    if req.authenticator_data.is_empty()
        || req.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_LEN
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Authenticator data is empty or exceeds maximum length",
        ));
    }
    if req.client_data_json.is_empty() || req.client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data JSON is empty or exceeds maximum length",
        ));
    }
    if req.signature.is_empty() || req.signature.len() > MAX_SIGNATURE_LEN {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Signature is empty or exceeds maximum length",
        ));
    }
    if req.user_handle.is_empty() || req.user_handle.len() > MAX_USER_HANDLE_LEN {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "User handle is empty or exceeds maximum length",
        ));
    }

    // ── Phase 3: State JWT decode + expiration ───────────────────────────
    let auth_state =
        BrowserAuthenticationState::decode(&req.state, state.config().jwt_secret.expose_secret())
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    let now = Timestamp::now().as_second();
    if now > auth_state.exp {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "expired",
            "Authentication session expired",
        ));
    }

    // ── Phase 4: Base64url decode all fields ─────────────────────────────
    let credential_id = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid credential_id",
        )
    })?;

    let authenticator_data = URL_SAFE_NO_PAD
        .decode(&req.authenticator_data)
        .map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid authenticator_data",
            )
        })?;

    let client_data_json = URL_SAFE_NO_PAD.decode(&req.client_data_json).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid client_data_json",
        )
    })?;

    let signature = URL_SAFE_NO_PAD.decode(&req.signature).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid signature",
        )
    })?;

    let user_handle = URL_SAFE_NO_PAD.decode(&req.user_handle).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid user_handle",
        )
    })?;

    // ── Phase 5: Credential ID byte length validation ────────────────────
    if credential_id.len() < MIN_CREDENTIAL_ID_BYTES
        || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Credential ID length is outside the valid range (16-1023 bytes)",
        ));
    }

    // ── Phase 6: Client data JSON structure validation ───────────────────
    // Parse and validate client data before any DB or crypto operations.
    let client_data_str = std::str::from_utf8(&client_data_json).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data JSON is not valid UTF-8",
        )
    })?;

    #[derive(serde::Deserialize)]
    struct ClientData {
        origin: String,
        #[serde(rename = "type")]
        typ: String,
    }

    let client_data: ClientData = serde_json::from_str(client_data_str).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            &format!("Client data JSON is malformed: {e}"),
        )
    })?;

    if client_data.typ != "webauthn.get" {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data type must be 'webauthn.get'",
        ));
    }

    if client_data.origin != state.config().base_url {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data origin mismatch",
        ));
    }

    // Parse user_handle as UUID to identify the user
    let user_id = Uuid::from_slice(&user_handle).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_user_handle",
            "Invalid user handle format",
        )
    })?;

    // Helper to log failed login attempts
    let log_failure = |user_id: &str, authenticator_id: Option<&str>, reason: &str| {
        let params = AuthEventParams {
            user_id: user_id.to_string(),
            event_type: AuthEventType::LoginFailed,
            authenticator_id: authenticator_id.map(String::from),
            client_ip: client_info.client_ip.clone(),
            user_agent: client_info.user_agent.clone(),
            client_hostname: None,
            client_os: None,
            client_arch: None,
            client_version: None,
            success: false,
            failure_reason: Some(reason.to_string()),
        };
        let audit = state.audit.clone();
        tokio::spawn(async move {
            if let Err(e) = db::insert_auth_event(&audit, &params, None).await {
                tracing::warn!("Failed to log auth event: {}", e);
            }
        });
    };

    // Look up authenticator and verify ownership (single JOIN query)
    use crate::services::auth::{AuthenticatorLookupParams, lookup_and_verify_authenticator};
    let lookup_result = lookup_and_verify_authenticator(
        &state,
        AuthenticatorLookupParams {
            credential_id: &credential_id,
            user_id,
        },
    )
    .await
    .map_err(|e| {
        let reason = match &e {
            crate::services::ServiceError::NotFound(entity) => {
                format!("{entity}_not_found")
            }
            crate::services::ServiceError::Forbidden(_) => "user_mismatch".to_string(),
            _ => "lookup_error".to_string(),
        };
        log_failure(&user_id.to_string(), None, &reason);
        // Return generic error to prevent credential enumeration
        json_error(
            StatusCode::UNAUTHORIZED,
            "auth_failed",
            "Authentication failed",
        )
    })?;

    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // Server-side WebAuthn signature verification
    let expected_origin = format!("https://{}", auth_state.rp_id);
    let expected_challenge = URL_SAFE_NO_PAD.encode(&auth_state.challenge);
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);

    let verification_result = webauthn_verify::verify_assertion(
        &authenticator_data,
        &client_data_json,
        &signature,
        &authenticator.public_key,
        &auth_state.rp_id,
        &expected_challenge,
        &expected_origin,
        stored_counter,
        true, // require_user_verification
    )
    .map_err(|e| {
        log_failure(&user.id, Some(&authenticator.id), &e.to_string());
        json_error(
            StatusCode::UNAUTHORIZED,
            "auth_failed",
            "Authentication failed",
        )
    })?;

    tracing::info!(
        "Browser WebAuthn assertion verified for user {}: counter={}, uv={}",
        redact_email(&user.email),
        verification_result.counter,
        verification_result.user_verified
    );

    // Update counter in database (WebAuthn counter is u32, stored as i32)
    let new_counter = verification_result.counter as i32;
    db::update_authenticator_counter(&state.store, &authenticator.id, new_counter)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Issue an OAuth access token (RFC 9068) — the server acts as both issuer and audience
    let client_id = state.config().base_url.clone();
    let auth_now = Timestamp::now();
    let session_result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            client_id: &client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            act: None,
            audience: None,
            auth_time: Some(auth_now.as_second()),
            amr: Some(AuthMethod::all_fido2().to_vec()),
            acr: Some(ACR_AAL3.to_string()),
        },
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            &e.to_string(),
        )
    })?;
    let token = session_result.token;

    // Log successful login event (fire-and-forget, consistent with failure path)

    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        client_ip: client_info.client_ip,
        user_agent: client_info.user_agent,
        client_hostname: None,
        client_os: None,
        client_arch: None,
        client_version: None,
        success: true,
        failure_reason: None,
    };
    let audit = state.audit.clone();
    tokio::spawn(async move {
        if let Err(e) = db::insert_auth_event(&audit, &auth_event_params, None).await {
            tracing::warn!("Failed to log auth event: {}", e);
        }
    });

    tracing::info!(
        "Browser login successful for user: {}",
        redact_email(&user.email)
    );

    // Create session cookie
    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let cookie = create_session_cookie(token.expose_secret(), session_hours * 3600);

    // Determine redirect URL
    let redirect_url = if let Some(pending_id) = auth_state.pending_auth {
        format!(
            "/oauth/authorize?pending_auth={}",
            urlencoding::encode(&pending_id)
        )
    } else {
        "/".to_string()
    };

    // Return JSON response with cookie header
    let response = BrowserLoginCompleteResponse {
        success: true,
        redirect_url: Some(redirect_url),
        error: None,
    };

    Ok(([(header::SET_COOKIE, cookie.to_string())], Json(response)).into_response())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate Origin header for CSRF protection (RFC 9700).
fn validate_origin(
    headers: &HeaderMap,
    expected_origin: &str,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let origin = headers
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            json_error(
                StatusCode::FORBIDDEN,
                "missing_origin",
                "Origin header required",
            )
        })?;

    if origin != expected_origin {
        tracing::warn!(
            "Origin mismatch: got '{}', expected '{}'",
            origin,
            expected_origin
        );
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Request origin mismatch",
        ));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_browser_auth_state_encode_decode() {
        let secret = "test-secret";
        let now = jiff::Timestamp::now().as_second();
        let state = BrowserAuthenticationState {
            challenge: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            created_at: now,
            exp: now + 300,
            pending_auth: Some("pending-123".to_string()),
        };

        let encoded = state.encode(secret).expect("Failed to encode state");
        let decoded =
            BrowserAuthenticationState::decode(&encoded, secret).expect("Failed to decode state");

        assert_eq!(decoded.challenge, vec![1, 2, 3, 4]);
        assert_eq!(decoded.rp_id, "example.com");
        assert_eq!(decoded.pending_auth, Some("pending-123".to_string()));
    }

    // ========================================================================
    // Login Page — pending_auth Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_login_page_rejects_non_uuid_pending_auth() {
        // Non-UUID pending_auth should redirect to /login (stripping the bad param)
        let (app, _state) = crate::test_utils::test_app().await;

        let resp = crate::test_utils::http_get_full(
            &app,
            "/login?pending_auth=not-a-uuid",
            &[],
        )
        .await;

        assert_eq!(resp.status, axum::http::StatusCode::SEE_OTHER);
        let location = resp
            .headers
            .get("location")
            .expect("redirect should have location header")
            .to_str()
            .expect("location should be valid string");
        assert_eq!(location, "/login");
    }

    #[tokio::test]
    async fn test_login_page_accepts_valid_uuid_pending_auth() {
        // Valid UUID pending_auth should not redirect to /login
        let (app, _state) = crate::test_utils::test_app().await;

        let resp = crate::test_utils::http_get_full(
            &app,
            "/login?pending_auth=aaaaaaaa-bbbb-7ccc-dddd-eeeeeeeeeeee",
            &[],
        )
        .await;

        // Should render the login page (200), not redirect to /login
        assert_eq!(resp.status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_page_no_pending_auth_renders_ok() {
        // No pending_auth at all should render the login page
        let (app, _state) = crate::test_utils::test_app().await;

        let resp = crate::test_utils::http_get_full(&app, "/login", &[]).await;

        assert_eq!(resp.status, axum::http::StatusCode::OK);
    }

    // ========================================================================
    // Browser Auth State Tests
    // ========================================================================

    #[test]
    fn test_browser_auth_state_decode_wrong_secret() {
        let now = jiff::Timestamp::now().as_second();
        let state = BrowserAuthenticationState {
            challenge: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            created_at: now,
            exp: now + 300,
            pending_auth: None,
        };

        let encoded = state
            .encode("correct-secret")
            .expect("Failed to encode state");
        let result = BrowserAuthenticationState::decode(&encoded, "wrong-secret");

        assert!(result.is_err());
    }
}
