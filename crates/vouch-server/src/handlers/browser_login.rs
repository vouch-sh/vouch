// SPDX-License-Identifier: Apache-2.0 OR MIT
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

use crate::AppState;
use crate::crypto::generate_challenge;
use crate::crypto::hash_token;
use crate::db::ClientInfo;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::error::ServiceError;
use crate::handlers::extractors::ValidJson;
use crate::handlers::session::{create_session_cookie, get_auth_context};
use crate::impl_template_response;
use crate::redact_email;
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenIssuanceProof,
    create_oauth_access_token,
};
use crate::services::oidc::ScopeSet;
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
use vouch_common::encoding::ConvertEncoding;
use vouch_common::fido2_types::Challenge;
use vouch_common::{
    BrowserLoginCompleteRequest, BrowserLoginCompleteResponse, BrowserLoginStartRequest,
    BrowserLoginStartResponse, protocol,
};

/// Compute an HMAC-SHA256 tag over `message` using `secret`, returning the
/// result base64url-encoded (no padding). Used by the certification test-mode
/// login link to bind the link to a specific pending authorization ID.
pub(crate) fn hmac_sha256_base64url(secret: &str, message: &str) -> String {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, message.as_bytes());
    URL_SAFE_NO_PAD.encode(tag.as_ref())
}

// ============================================================================
// Templates
// ============================================================================

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
#[allow(dead_code, reason = "fields rendered via Askama template macros")]
pub(crate) struct LoginTemplate {
    /// Pending OAuth authorization ID (if coming from /oauth/authorize).
    pub pending_auth: Option<String>,
    /// OAuth client name (for display).
    pub client_name: Option<String>,
    /// Relying Party ID for WebAuthn.
    pub rp_id: String,
    /// Authentication context for header.
    pub auth: crate::handlers::session::AuthContext,
    /// URL for the certification test-mode login link.
    /// `Some` only when `VOUCH_CERTIFICATION_TEST_TOKEN` is set and there is a pending auth.
    pub cert_login_url: Option<String>,
    /// URL for the certification test-mode deny link (returns access_denied).
    pub cert_deny_url: Option<String>,
    /// RFC 7591 client logo_uri (HTTPS only). Shown when coming from an OAuth flow.
    pub logo_uri: Option<String>,
    /// RFC 7591 client policy_uri (HTTPS only). Shown when coming from an OAuth flow.
    pub policy_uri: Option<String>,
    /// RFC 7591 client tos_uri (HTTPS only). Shown when coming from an OAuth flow.
    pub tos_uri: Option<String>,
}

impl_template_response!(LoginTemplate);

// ============================================================================
// Validation Constants
// ============================================================================

/// Maximum decoded byte length for `authenticator_data`.
/// Authenticator data is typically 37+ bytes; with extensions it can be larger.
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 3 * 1024;

/// Maximum decoded byte length for `client_data_json`.
/// Client data JSON is a small JSON object (origin, type, challenge).
const MAX_CLIENT_DATA_JSON_BYTES: usize = 3 * 1024;

/// Maximum decoded byte length for `signature`.
/// ECDSA/EdDSA signatures are typically under 100 bytes.
const MAX_SIGNATURE_BYTES: usize = 768;

/// Maximum decoded byte length for `user_handle`.
/// User handles are 16-byte UUIDs.
const MAX_USER_HANDLE_BYTES: usize = 192;

/// Maximum length for the authentication `state` JWT.
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
    async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(
                self,
                crate::crypto::jwt::JwtType::BrowserAuthenticationState,
            )
            .await
    }

    async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        signer
            .decode_state_token(
                token,
                crate::crypto::jwt::JwtType::BrowserAuthenticationState,
            )
            .await
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
pub(crate) struct LoginQuery {
    /// Pending OAuth authorization ID.
    pending_auth: Option<String>,
}

/// The pending CLI device authorization this browser session must release, if
/// any. `complete_enrollment_after_identity` records it against the session
/// token when an already-enrolled user runs `vouch enroll`; the assertion in
/// [`browser_login_complete`] is what authorizes it.
///
/// `Ok(None)` when there is no session cookie, no enrollment session for it, or
/// the enrollment session carries no device authorization — all ordinary for a
/// plain login.
///
/// # Errors
///
/// Propagates storage failures instead of reporting them as "nothing pending".
/// Collapsing the two would strand the waiting CLI: the caller could skip the
/// assertion form, or issue a session while the device request stays pending,
/// with nothing on screen to explain why.
async fn pending_device_auth(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<db::EnrollmentSession>, ServiceError> {
    let Some(cookie) = jar.get(vouch_common::SESSION_COOKIE_NAME) else {
        return Ok(None);
    };
    let session =
        db::get_enrollment_session_by_token_hash(&state.store, &hash_token(cookie.value())).await?;
    Ok(session.filter(|s| s.device_auth_id.is_some()))
}

pub(crate) async fn login_page(
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

    // Look up pending auth to check prompt and get client name.
    let pending = if let Some(ref pending_id) = query.pending_auth {
        db::get_pending_oauth_authorization(&state.store, pending_id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // OIDC Core Section 3.1.2.1: prompt=login requires re-authentication
    // even if the user has a valid session. RFC 9470: max_age also forces
    // re-authentication when the session age exceeds the requested value.
    // Only skip the login form when the pending auth does NOT require
    // forced re-auth.
    // A session created by `vouch enroll` for an already-enrolled user is
    // authenticated but not hardware-verified, and a CLI is waiting on the
    // assertion. Skipping the form here would leave it polling forever, so a
    // lookup failure forces the form too: rendering it needlessly costs the
    // user one touch, skipping it strands the CLI until it times out.
    let device_auth_pending = match pending_device_auth(&state, &jar).await {
        Ok(pending) => pending.is_some(),
        Err(e) => {
            tracing::error!("Failed to check for a pending device authorization: {e}");
            true
        }
    };

    let requires_reauth = pending
        .as_ref()
        .is_some_and(|p| p.prompt.as_deref() == Some("login") || p.max_age.is_some())
        || device_auth_pending;

    if auth.authenticated && !requires_reauth {
        if let Some(ref pending_id) = query.pending_auth {
            return axum::response::Redirect::to(&format!(
                "/oauth/authorize?pending_auth={}",
                urlencoding::encode(pending_id)
            ))
            .into_response();
        }
        return axum::response::Redirect::to("/").into_response();
    }

    let (client_name, logo_uri, policy_uri, tos_uri) = match &pending {
        Some(p) => match db::get_oauth_client_by_client_id(&state.store, &p.client_id).await {
            Ok(Some(client)) => {
                let meta = client.registration_metadata.as_ref();
                let extract = |key: &str| -> Option<String> {
                    meta.and_then(|m| m.get(key))
                        .and_then(|v| v.as_str())
                        .filter(|s| s.starts_with("https://"))
                        .map(String::from)
                };
                (
                    Some(client.name),
                    extract("logo_uri"),
                    extract("policy_uri"),
                    extract("tos_uri"),
                )
            }
            _ => (None, None, None, None),
        },
        None => (None, None, None, None),
    };

    // Build the certification test-mode login link when the feature is enabled.
    // The link embeds an HMAC of the pending_auth ID so only the server can
    // generate valid links. This is only set when both the token is configured
    // AND there is a pending authorization to complete.
    let cert_login_url = match (
        &state.config().certification_test_token,
        &query.pending_auth,
    ) {
        (Some(secret), Some(pending_id)) => {
            let token = hmac_sha256_base64url(secret.expose_secret(), pending_id);
            let encoded_pending_id = urlencoding::encode(pending_id);
            let encoded_token = urlencoding::encode(&token);
            Some(format!(
                "/certification/complete-login?pending_auth={encoded_pending_id}&token={encoded_token}"
            ))
        }
        _ => None,
    };

    let cert_deny_url = match (
        &state.config().certification_test_token,
        &query.pending_auth,
    ) {
        (Some(secret), Some(pending_id)) => {
            let token = hmac_sha256_base64url(secret.expose_secret(), pending_id);
            let encoded_pending_id = urlencoding::encode(pending_id);
            let encoded_token = urlencoding::encode(&token);
            Some(format!(
                "/certification/deny-login?pending_auth={encoded_pending_id}&token={encoded_token}"
            ))
        }
        _ => None,
    };

    LoginTemplate {
        pending_auth: query.pending_auth,
        client_name,
        rp_id: state.config().rp_id.clone(),
        auth,
        cert_login_url,
        cert_deny_url,
        logo_uri,
        policy_uri,
        tos_uri,
    }
    .into_response()
}

/// POST /login/webauthn/start
///
/// Generate a WebAuthn authentication challenge.
/// Uses discoverable credentials (passkeys) so the authenticator identifies the user.
pub(crate) async fn browser_login_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BrowserLoginStartRequest>,
) -> Result<Json<BrowserLoginStartResponse>, ServiceError> {
    // Validate Origin header for CSRF protection (RFC 9700)
    validate_origin(&headers, &state.config().base_url)?;

    tracing::info!("Browser login start (discoverable credential flow)");

    // Generate challenge
    let challenge = generate_challenge().map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate challenge",
        )
    })?;
    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().minutes(5))
        .map_err(|_| {
            ServiceError::api(
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

    let state_token = auth_state.encode(&state.state_signer).await.map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            e.to_string(),
        )
    })?;

    Ok(Json(BrowserLoginStartResponse {
        challenge: Challenge::from_slice(&challenge).to_base64url(),
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
/// The binary fields arrive decoded: [`BrowserLoginCompleteRequest`] types
/// them as `Encoded<_, Base64Url>`, so a malformed base64url value is rejected
/// by [`ValidJson`] before the handler runs.
///
/// Validation is ordered to fail fast before any database access:
/// 1. Origin header validation (CSRF protection)
/// 2. Field length bounds (reject obviously oversized/empty fields)
/// 3. State JWT decode + expiration check
/// 4. Credential ID byte length validation
/// 5. Client data JSON structure validation (type, origin)
/// 6. Database operations (authenticator lookup, signature verification)
#[expect(
    clippy::too_many_lines,
    reason = "FAPI 2.0 browser login orchestrates assertion verification and session issuance"
)]
pub(crate) async fn browser_login_complete(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    headers: HeaderMap,
    jar: CookieJar,
    ValidJson(req): ValidJson<BrowserLoginCompleteRequest>,
) -> Result<Response, ServiceError> {
    // ── Phase 1: Origin header validation ────────────────────────────────
    validate_origin(&headers, &state.config().base_url)?;

    tracing::info!("Browser login complete (discoverable credential flow)");

    // ── Phase 2: Field length bounds ─────────────────────────────────────
    // Reject obviously oversized or empty fields before any processing.
    if req.state.len() > MAX_STATE_TOKEN_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "State token exceeds maximum length",
        ));
    }
    if req.authenticator_data.is_empty()
        || req.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Authenticator data is empty or exceeds maximum length",
        ));
    }
    if req.client_data_json.is_empty() || req.client_data_json.len() > MAX_CLIENT_DATA_JSON_BYTES {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data JSON is empty or exceeds maximum length",
        ));
    }
    if req.signature.is_empty() || req.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Signature is empty or exceeds maximum length",
        ));
    }
    if req.user_handle.is_empty() || req.user_handle.len() > MAX_USER_HANDLE_BYTES {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "User handle is empty or exceeds maximum length",
        ));
    }
    // Credential ID byte-length bounds are enforced here, before the
    // single-use challenge state is consumed in Phase 3b. An empty string
    // is valid base64url that decodes to `vec![]`, so without this check a
    // crafted request with an empty (or out-of-range) `credential_id` would
    // consume and invalidate the victim's state token before failing.
    if req.credential_id.len() < MIN_CREDENTIAL_ID_BYTES
        || req.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Credential ID length is outside the valid range (16-1023 bytes)",
        ));
    }

    // ── Phase 3: State JWT decode + expiration ───────────────────────────
    let auth_state = BrowserAuthenticationState::decode(&req.state, &state.state_signer)
        .await
        .map_err(|e| ServiceError::api(StatusCode::BAD_REQUEST, "invalid_state", e.to_string()))?;

    let now = Timestamp::now().as_second();
    if now > auth_state.exp {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "expired",
            "Authentication session expired",
        ));
    }

    // ── Phase 3b: Atomic single-use challenge consume ─────────────────────
    // Mark the authentication state JWT consumed before any side effects.
    // The returned `ChallengeStateClaim` witness is the structural proof
    // threaded into the TokenIssuanceProof below — the only path to
    // `GrantProof::BrowserLogin`. Two concurrent requests with the same
    // state JWT collide on the deterministic PRIMARY KEY; only one wins.
    let expires_at = Timestamp::from_second(auth_state.exp).unwrap_or_else(|_| Timestamp::now());
    let challenge_claim =
        match db::try_consume_challenge_state(&state.store, &req.state, expires_at).await {
            Ok(claim) => claim,
            Err(db::ClaimError::AlreadyConsumed) => {
                return Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "state_already_used",
                    "Authentication state has already been used",
                ));
            }
            Err(e) => {
                tracing::error!("Failed to mark browser login state used: {e}");
                return Err(ServiceError::Internal(
                    "Failed to mark authentication state used".to_string(),
                ));
            }
        };

    // ── Phase 5: Client data JSON structure validation ───────────────────
    // Parse and validate client data before any DB or crypto operations.
    let client_data_str = std::str::from_utf8(&req.client_data_json).map_err(|_| {
        ServiceError::api(
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
        tracing::debug!("Client data JSON parse error: {e}");
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data JSON is malformed",
        )
    })?;

    if client_data.typ != protocol::CLIENT_DATA_TYPE_GET {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data type must be 'webauthn.get'",
        ));
    }

    if client_data.origin != state.config().base_url {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Client data origin mismatch",
        ));
    }

    // Parse user_handle as UUID to identify the user
    let user_id = Uuid::from_slice(&req.user_handle).map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_user_handle",
            "Invalid user handle format",
        )
    })?;

    // Helper to log failed login attempts. The email feeds the audit row's
    // `email_domain`/`email_hmac` columns (never stored raw); without it the
    // event is invisible to org-scoped audit queries, which filter on domain.
    let log_failure =
        |user_id: &str, email: Option<&str>, authenticator_id: Option<&str>, reason: &str| {
            let params = AuthEventParams {
                user_id: user_id.to_string(),
                event_type: AuthEventType::LoginFailed,
                authenticator_id: authenticator_id.map(String::from),
                success: false,
                failure_reason: Some(reason.to_string()),
                client: client_info.clone(),
                ..AuthEventParams::default()
            };
            db::spawn_audit_event(&state.audit, params, email.map(String::from));
        };

    // Look up authenticator and verify ownership (single JOIN query)
    use crate::services::auth::{AuthenticatorLookupParams, lookup_and_verify_authenticator};
    let lookup_result = lookup_and_verify_authenticator(
        &state,
        AuthenticatorLookupParams {
            credential_id: req.credential_id.as_bytes(),
            user_id,
        },
    )
    .await
    .map_err(|e| {
        let reason = match &e {
            crate::error::ServiceError::NotFound(entity) => {
                format!("{entity}_not_found")
            }
            crate::error::ServiceError::Forbidden(_) => "user_mismatch".to_string(),
            _ => "lookup_error".to_string(),
        };
        // Credential lookup failed — no user row was loaded, so no email.
        log_failure(&user_id.to_string(), None, None, &reason);
        // Return generic error to prevent credential enumeration
        ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "auth_failed",
            "Authentication failed",
        )
    })?;

    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // Server-side WebAuthn signature verification (offloaded to a blocking
    // thread — see verify_login_assertion for rationale).
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);

    use crate::services::auth::{LoginAssertionParams, verify_login_assertion};
    let verification_result = verify_login_assertion(LoginAssertionParams {
        authenticator_data: req.authenticator_data.into_bytes(),
        client_data_json: req.client_data_json.into_bytes(),
        signature: req.signature.into_bytes(),
        public_key: authenticator.public_key.clone(),
        rp_id: auth_state.rp_id.clone(),
        // Browser sets clientDataJSON.origin to the calling page's origin
        // (the server's base_url), which may be a subdomain of rp_id.
        expected_origin: state.config().base_url.to_string(),
        challenge: auth_state.challenge.clone(),
        stored_counter,
        // Tolerate loopback origin variations only in development (no TLS).
        origin_policy: state.config().as_ref().into(),
    })
    .await
    .map_err(|e| {
        log_failure(
            &user.id,
            Some(&user.email),
            Some(&authenticator.id),
            &e.to_string(),
        );
        ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "auth_failed",
            "Authentication failed",
        )
    })?;

    tracing::info!(
        "Browser WebAuthn assertion verified for user {}: counter={}, uv={}",
        redact_email(&user.email),
        verification_result.new_counter,
        verification_result.user_verified
    );

    // WebAuthn counter is u32; stored bit-identical as i32. Real authenticators never
    // approach 2^31 uses, and bitwise reinterpret preserves DB monotonicity comparisons.
    let new_counter = verification_result.new_counter.cast_signed();
    db::update_authenticator_counter(&state.store, &authenticator.id, new_counter).await?;

    // Release a CLI waiting on `vouch enroll`: the assertion just verified is
    // the possession proof the upstream IdP sign-in cannot provide, so the
    // device authorization is authorized from here.
    if let Some(enrollment) = pending_device_auth(&state, &jar).await?
        && let Some(ref device_auth_id) = enrollment.device_auth_id
    {
        // The enrollment session must belong to whoever just asserted;
        // otherwise a stale cookie would approve another user's device
        // authorization using this user's hardware proof.
        if enrollment.user_id == user.id {
            db::authorize_device_auth(
                &state.store,
                db::AuthorizeDeviceAuthParams {
                    id: device_auth_id,
                    user_id: &user.id,
                    user_email: &user.email,
                    authenticator_id: &authenticator.id,
                    hardware_verified: true,
                },
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to authorize device auth '{device_auth_id}': {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "device_auth_failed",
                    "Failed to complete CLI authorization",
                )
            })?;

            db::spawn_audit_event(
                &state.audit,
                AuthEventParams {
                    user_id: user.id.clone(),
                    event_type: AuthEventType::DeviceAuthApproved,
                    authenticator_id: Some(authenticator.id.clone()),
                    success: true,
                    client: client_info.clone(),
                    ..AuthEventParams::default()
                },
                Some(user.email.clone()),
            );
        } else {
            tracing::warn!(
                target: "security",
                "Enrollment session belongs to a different user than the one asserting; \
                 refusing to approve the device authorization"
            );
        }
    }

    // Issue an OAuth access token (RFC 9068) — the server acts as both issuer and audience
    let client_id = state.config().base_url.to_string();
    let auth_now = Timestamp::now();

    // Snapshot org domain at session creation so the federation claims are a
    // session-time snapshot rather than current-state lookups. Fail closed:
    // the snapshot is captured exactly once, so silently dropping a transient
    // DB error here would permanently degrade the session's `hd` claim.
    let org_domain = if let Some(ref org_id) = user.org_id {
        db::get_organization_domain(&state.store, org_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to snapshot org domain: {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Failed to create session",
                )
            })?
    } else {
        None
    };

    let session_result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            client_id: &client_id,
            scope: Some(ScopeSet::all()),
            dpop_proof: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(auth_now.as_second()),
            hardware_verification: crate::services::auth::HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: authenticator.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
        },
        TokenIssuanceProof {
            grant: GrantProof::BrowserLogin(challenge_claim),
            client_auth: ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
            sender_constraint: SenderConstraintProof::no_registered_client(),
        },
    )
    .await
    .map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            e.to_string(),
        )
    })?;
    let token = session_result.token;

    // Log successful login event (fire-and-forget, consistent with failure path)
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        success: true,
        client: client_info,
        ..AuthEventParams::default()
    };
    db::spawn_audit_event(&state.audit, auth_event_params, Some(user.email.clone()));

    crate::infra::metrics::record_auth_event("browser_login_success");

    tracing::info!(
        "Browser login successful for user: {}",
        redact_email(&user.email)
    );

    // Create session cookie
    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let cookie = create_session_cookie(token.expose_secret(), session_hours.saturating_mul(3600));

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
pub(crate) fn validate_origin(
    headers: &HeaderMap,
    expected_origin: &str,
) -> Result<(), ServiceError> {
    let origin = headers
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            ServiceError::api(
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
        return Err(ServiceError::api(
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
    #![expect(
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    #[tokio::test]
    async fn test_browser_auth_state_encode_decode() {
        let signer = crate::crypto::jwt::StateTokenSigner::local(b"test-secret".to_vec());
        let now = jiff::Timestamp::now().as_second();
        let state = BrowserAuthenticationState {
            challenge: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            created_at: now,
            exp: now + 300,
            pending_auth: Some("pending-123".to_string()),
        };

        let encoded = state.encode(&signer).await.expect("Failed to encode state");
        let decoded = BrowserAuthenticationState::decode(&encoded, &signer)
            .await
            .expect("Failed to decode state");

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

        let resp =
            crate::test_utils::http_get_full(&app, "/login?pending_auth=not-a-uuid", &[]).await;

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
    // prompt=login Re-authentication Tests (OIDC Core Section 3.1.2.1)
    // ========================================================================

    #[tokio::test]
    async fn test_login_page_prompt_login_forces_reauth() {
        // OIDC Core Section 3.1.2.1: prompt=login must show the login page
        // even when the user already has a valid session.
        let (app, state) = crate::test_utils::test_app().await;

        let user = crate::test_utils::create_test_user(&state.store, "reauth@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;
        let session_token =
            crate::test_utils::create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Create a pending auth with prompt=login
        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id: &client.client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: None,
                scope: Some("openid"),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                acr_values: None,
                max_age: None,
                prompt: Some("login"),
                dpop_jkt: None,
                authorization_details: None,
                response_mode: Default::default(),
                par_request_uri: None,
            },
        )
        .await
        .expect("Failed to create pending auth");

        // Visit /login with session cookie and prompt=login pending auth
        let resp = crate::test_utils::http_get_full(
            &app,
            &format!("/login?pending_auth={pending_id}"),
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        // Must show the login page (200), NOT redirect to /oauth/authorize
        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "prompt=login must show login page even with valid session"
        );
    }

    #[tokio::test]
    async fn test_login_page_no_prompt_redirects_with_session() {
        // Without prompt=login, an authenticated user with pending_auth
        // should be redirected back to /oauth/authorize.
        let (app, state) = crate::test_utils::test_app().await;

        let user = crate::test_utils::create_test_user(&state.store, "no-reauth@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;
        let session_token =
            crate::test_utils::create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Create a pending auth WITHOUT prompt=login
        let pending_id = crate::db::create_pending_oauth_authorization(
            &state.store,
            crate::db::CreatePendingOAuthParams {
                client_id: &client.client_id,
                redirect_uri: "https://example.com/callback",
                response_type: "code",
                state: None,
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
            &format!("/login?pending_auth={pending_id}"),
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        // Should redirect to /oauth/authorize (not show login page)
        assert!(
            resp.status == axum::http::StatusCode::FOUND
                || resp.status == axum::http::StatusCode::SEE_OTHER,
            "Without prompt=login, should redirect with session: {}",
            resp.status
        );
        let location = resp
            .headers
            .get("location")
            .expect("redirect should have location header")
            .to_str()
            .expect("valid string");
        assert!(
            location.contains("/oauth/authorize"),
            "Should redirect to /oauth/authorize: {location}"
        );
    }

    #[tokio::test]
    async fn test_login_page_shows_form_when_device_auth_pending() {
        // A returning user running `vouch enroll` arrives here already
        // carrying a session cookie. Redirecting them away because they look
        // authenticated would leave the CLI polling until it times out — the
        // assertion is what authorizes the waiting device request.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "cli-assert@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let session_token =
            crate::test_utils::create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let expires: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
        let device_auth_id = crate::db::create_device_auth_request(
            &state.store,
            "login-page-device-hash",
            "LGPG-CODE",
            None,
            expires,
            0,
        )
        .await
        .expect("create device auth");

        crate::db::create_enrollment_session(
            &state.store,
            &user.id,
            &user.email,
            &crate::crypto::hash_token(&session_token),
            Some(&device_auth_id),
            expires,
        )
        .await
        .expect("create enrollment session");

        let resp = crate::test_utils::http_get_full(
            &app,
            "/login",
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "an authenticated session with a device authorization waiting must \
             still be shown the assertion form, got a redirect"
        );
    }

    // ========================================================================
    // Browser Auth State Tests
    // ========================================================================

    /// `credential_id` and friends are `Encoded<_, Base64Url>`, so a malformed
    /// value is a deserialization failure. `ValidJson` reports it in the JSON
    /// envelope `login.js` reads out of `errResp.message`.
    #[tokio::test]
    async fn test_browser_login_complete_rejects_malformed_base64url() {
        let (app, state) = crate::test_utils::test_app().await;

        let dummy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 32]);
        let body = serde_json::json!({
            "state": "state-token",
            "credential_id": "!!not-base64url!!",
            "authenticator_data": dummy,
            "client_data_json": dummy,
            "signature": dummy,
            "user_handle": dummy,
        })
        .to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
        assert!(
            resp_body.contains("invalid_request"),
            "expected 'invalid_request' in body, got: {resp_body}"
        );
        assert!(
            resp_body.contains("credential_id"),
            "the rejection must name the offending field, got: {resp_body}"
        );
    }

    /// The rejection body must be JSON — the browser calls `.json()` on it and
    /// shows `errResp.message`. Axum's own rejection answers `text/plain`.
    #[tokio::test]
    async fn test_browser_login_complete_rejection_is_json() {
        let (app, state) = crate::test_utils::test_app().await;

        // Omit every field but `state`.
        let body = serde_json::json!({ "state": "state-token" }).to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
        let parsed: serde_json::Value =
            serde_json::from_str(&resp_body).expect("rejection body must be JSON");
        assert_eq!(
            parsed.get("code").and_then(serde_json::Value::as_str),
            Some("invalid_request"),
            "{resp_body}"
        );
        assert!(
            parsed
                .get("message")
                .is_some_and(serde_json::Value::is_string),
            "browser reads errResp.message: {resp_body}"
        );
    }

    #[tokio::test]
    async fn test_browser_auth_state_decode_wrong_secret() {
        let signer = crate::crypto::jwt::StateTokenSigner::local(b"correct-secret".to_vec());
        let wrong_signer = crate::crypto::jwt::StateTokenSigner::local(b"wrong-secret".to_vec());
        let now = jiff::Timestamp::now().as_second();
        let state = BrowserAuthenticationState {
            challenge: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            created_at: now,
            exp: now + 300,
            pending_auth: None,
        };

        let encoded = state.encode(&signer).await.expect("Failed to encode state");
        let result = BrowserAuthenticationState::decode(&encoded, &wrong_signer).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_browser_login_complete_rejects_replayed_state() {
        // Pre-consume a valid state JWT, then submit `POST
        // /login/webauthn/complete` with that JWT. The Phase 3b consume
        // must reject the request with 400 + `state_already_used` before
        // any base64 decoding, DB lookup, or WebAuthn verification work
        // happens. This guards against a regression where the consume
        // call is reordered or removed.
        let (app, state) = crate::test_utils::test_app().await;

        // Build a valid BrowserAuthenticationState JWT signed by the test
        // signer, with a far-future expiry.
        let now = jiff::Timestamp::now();
        let exp = now.as_second().saturating_add(300);
        let auth_state = BrowserAuthenticationState {
            challenge: vec![0u8; 32],
            rp_id: state.config().rp_id.clone(),
            created_at: now.as_second(),
            exp,
            pending_auth: None,
        };
        let state_jwt = auth_state
            .encode(&state.state_signer)
            .await
            .expect("encode auth state");

        // Pre-consume the state JWT to simulate a prior successful login.
        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let _claim = crate::db::try_consume_challenge_state(&state.store, &state_jwt, expires_at)
            .await
            .expect("pre-consume must succeed");

        // POST to `/login/webauthn/complete` with the already-consumed state
        // and length-bounded dummy fields. The replay check runs in Phase 3b,
        // before any of these values is used, so base64url-of-zero-bytes
        // fields are sufficient to reach it.
        let dummy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 32]);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": dummy,
            "authenticator_data": dummy,
            "client_data_json": dummy,
            "signature": dummy,
            "user_handle": dummy,
        })
        .to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "replay must be rejected with 400, got {status}: {resp_body}"
        );
        assert!(
            resp_body.contains("state_already_used"),
            "expected 'state_already_used' in response body, got: {resp_body}"
        );
    }

    /// Regression for the empty-`credential_id` denial-of-service. An empty
    /// string is valid base64url (it decodes to `vec![]`), so the request
    /// survives deserialization. The credential ID length bound must be
    /// enforced in Phase 2 — BEFORE the single-use challenge state is
    /// consumed in Phase 3b — otherwise an attacker can invalidate a victim's
    /// state token by sending a crafted request with an empty `credential_id`,
    /// preventing the victim from completing authentication.
    ///
    /// Guarantees:
    /// 1. The request is rejected with 400 `invalid_input`.
    /// 2. The state token is NOT consumed (a direct consume still succeeds).
    #[tokio::test]
    async fn test_browser_login_complete_empty_credential_id_rejects_without_consuming_state() {
        let (app, state) = crate::test_utils::test_app().await;

        // Fresh, unconsumed state JWT signed by the test signer.
        let now = jiff::Timestamp::now();
        let exp = now.as_second().saturating_add(300);
        let auth_state = BrowserAuthenticationState {
            challenge: vec![0u8; 32],
            rp_id: state.config().rp_id.clone(),
            created_at: now.as_second(),
            exp,
            pending_auth: None,
        };
        let state_jwt = auth_state
            .encode(&state.state_signer)
            .await
            .expect("encode auth state");

        // Length-bounded dummy fields so Phase 2 advances to the credential_id
        // check rather than rejecting on an earlier field.
        let dummy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 32]);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": "",
            "authenticator_data": dummy,
            "client_data_json": dummy,
            "signature": dummy,
            "user_handle": dummy,
        })
        .to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;

        // Guarantee 1: rejected before state consumption.
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "empty credential_id must be rejected: {resp_body}"
        );
        assert!(
            resp_body.contains("invalid_input"),
            "expected 'invalid_input' in rejection body, got: {resp_body}"
        );

        // Guarantee 2: the single-use challenge state was NOT consumed by the
        // rejected request — a direct consume must still succeed.
        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let consume =
            crate::db::try_consume_challenge_state(&state.store, &state_jwt, expires_at).await;
        assert!(
            consume.is_ok(),
            "state token was consumed by the rejected empty-credential_id \
             request (DoS regression): {consume:?}"
        );
    }

    /// A non-empty but below-minimum `credential_id` (here, 8 bytes; the spec
    /// minimum is 16) is also malformed and must be rejected in Phase 2 without
    /// consuming state. This locks in the full-range fix rather than only the
    /// empty-string case.
    #[tokio::test]
    async fn test_browser_login_complete_short_credential_id_rejects_without_consuming_state() {
        let (app, state) = crate::test_utils::test_app().await;

        let now = jiff::Timestamp::now();
        let exp = now.as_second().saturating_add(300);
        let auth_state = BrowserAuthenticationState {
            challenge: vec![0u8; 32],
            rp_id: state.config().rp_id.clone(),
            created_at: now.as_second(),
            exp,
            pending_auth: None,
        };
        let state_jwt = auth_state
            .encode(&state.state_signer)
            .await
            .expect("encode auth state");

        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let dummy = enc(&[0u8; 32]);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": enc(&[0u8; 8]), // 8 bytes < MIN_CREDENTIAL_ID_BYTES (16)
            "authenticator_data": dummy,
            "client_data_json": dummy,
            "signature": dummy,
            "user_handle": dummy,
        })
        .to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "short credential_id must be rejected: {resp_body}"
        );
        assert!(
            resp_body.contains("invalid_input"),
            "expected 'invalid_input' in rejection body, got: {resp_body}"
        );

        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let consume =
            crate::db::try_consume_challenge_state(&state.store, &state_jwt, expires_at).await;
        assert!(
            consume.is_ok(),
            "state token was consumed by the rejected short-credential_id \
             request (DoS regression): {consume:?}"
        );
    }

    #[tokio::test]
    async fn test_login_failed_audit_event_is_org_visible() {
        // Browser login audit events were inserted with a `None` email,
        // leaving `email_domain`/`email_hmac` NULL — invisible to org-scoped
        // audit queries, whose domain `IN` filter never matches NULL. Drive a
        // real signature-verification failure through the endpoint and assert
        // the resulting login_failed row is found by a domain-scoped query.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "audit-event@example.com").await;
        let credential_id: Vec<u8> = b"browser-login-audit-cred".to_vec();
        crate::db::create_authenticator(
            &state.store,
            &crate::db::CreateAuthenticatorParams {
                user_id: &user.id,
                user_email: &user.email,
                name: "Test Key",
                credential_id: &credential_id,
                public_key: &[0u8; 32],
                aaguid: None,
                user_handle: Some(user.id.as_bytes()),
                attestation_verified: false,
            },
        )
        .await
        .expect("create authenticator");

        // Fresh (unconsumed) state JWT.
        let now = jiff::Timestamp::now();
        let auth_state = BrowserAuthenticationState {
            challenge: vec![0u8; 32],
            rp_id: state.config().rp_id.clone(),
            created_at: now.as_second(),
            exp: now.as_second().saturating_add(300),
            pending_auth: None,
        };
        let state_jwt = auth_state
            .encode(&state.state_signer)
            .await
            .expect("encode auth state");

        let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");
        let client_data = serde_json::json!({
            "origin": state.config().base_url,
            "type": "webauthn.get",
        })
        .to_string();

        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": enc(&credential_id),
            "authenticator_data": enc(&[0u8; 37]),
            "client_data_json": enc(client_data.as_bytes()),
            "signature": enc(&[0u8; 64]),
            "user_handle": enc(user_uuid.as_bytes()),
        })
        .to_string();

        let (status, resp_body) = crate::test_utils::http_post_json(
            &app,
            "/login/webauthn/complete",
            &body,
            &[("Origin", state.config().base_url.as_str())],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "invalid signature must fail authentication: {resp_body}"
        );

        // The audit event is spawned fire-and-forget; poll briefly.
        let filter = crate::db::AuditEventFilter {
            event_types: Some(vec!["login_failed".to_string()]),
            email_domains: Some(vec!["example.com".to_string()]),
            user_id: Some(user.id.clone()),
            ..crate::db::AuditEventFilter::default()
        };
        let mut events = Vec::new();
        for _ in 0..100 {
            events = state
                .audit
                .query_events(&filter)
                .await
                .expect("query audit events");
            if !events.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            events.len(),
            1,
            "login_failed must be visible to an org-scoped (email_domains) audit query"
        );
        let event = events.first().expect("one event");
        assert_eq!(event.email_domain.as_deref(), Some("example.com"));
    }
}
