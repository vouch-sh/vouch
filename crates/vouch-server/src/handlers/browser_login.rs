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
use crate::assurance::HardwareVerification;
use crate::crypto::generate_challenge;
use crate::crypto::hash_token;
use crate::db::ClientInfo;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::error::ServiceError;
use crate::handlers::extractors::ValidJson;
use crate::handlers::session::{create_session_cookie, get_auth_context};
use crate::handlers::{ClientDataError, ClientDataProof};
use crate::impl_template_response;
use crate::infra::i18n::Tr;
use crate::redact_email;
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenBinding,
    TokenIssuanceProof, create_oauth_access_token,
};
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization::{
    AuthorizationSessionState, Prompt, PromptSet, check_session_for_authorization,
};
use askama::Template;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
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
// Login Completion
// ============================================================================

/// A `POST /login/webauthn/complete` body whose configuration-dependent
/// checks have run.
///
/// Field lengths and encodings are enforced by the request types themselves
/// (`vouch_common::encoding::Bounds`), so what is left here is the handful of
/// checks that need the server's configuration or the decoded state token.
/// [`LoginCompletion::validate`] consumes the raw request and is the only way to
/// build one, and [`db::try_consume_challenge_state`] takes one as an
/// argument — so the single-use state cannot be consumed before those checks
/// have run.
struct LoginCompletion {
    /// The request body itself.
    req: BrowserLoginCompleteRequest,
    /// `req.client_data_json` named `webauthn.get` and this server's origin.
    #[expect(
        dead_code,
        reason = "the field carries no data; requiring it is what makes omitting the check a compile error"
    )]
    client_data: ClientDataProof,
    /// Decoded contents of `req.state`.
    auth_state: BrowserAuthenticationState,
    /// `auth_state.exp` as a timestamp, for the consumed row's TTL.
    expires_at: Timestamp,
    /// `req.user_handle` parsed as the user's UUID.
    user_id: Uuid,
}

impl db::ChallengeState for LoginCompletion {
    fn state_jwt(&self) -> &str {
        self.req.state.as_str()
    }

    fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl LoginCompletion {
    /// Check the client data against this server's configuration, parse the
    /// user handle, and decode the state token.
    ///
    /// # Errors
    ///
    /// Returns a 400 `ServiceError` for client data that is not JSON or names
    /// the wrong ceremony type or origin, a user handle that is not a UUID, or
    /// a state token that fails to decode or has expired.
    async fn validate(
        req: BrowserLoginCompleteRequest,
        state: &AppState,
    ) -> Result<Self, ServiceError> {
        let client_data = ClientDataProof::verify(
            &req.client_data_json,
            protocol::CLIENT_DATA_TYPE_GET,
            &state.config().base_url,
        )
        .map_err(|e| {
            let message = match e {
                ClientDataError::NotUtf8 => "Client data JSON is not valid UTF-8",
                ClientDataError::Malformed(err) => {
                    tracing::debug!("Client data JSON parse error: {err}");
                    "Client data JSON is malformed"
                }
                ClientDataError::WrongType => "Client data type must be 'webauthn.get'",
                ClientDataError::WrongOrigin(_) => "Client data origin mismatch",
            };
            ServiceError::api(StatusCode::BAD_REQUEST, "invalid_input", message)
        })?;

        let user_id = Uuid::from_slice(&req.user_handle).map_err(|_| {
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_user_handle",
                Tr::new("login-error-invalid-user-handle").to_string(),
            )
        })?;

        let auth_state =
            BrowserAuthenticationState::decode(req.state.as_str(), &state.state_signer)
                .await
                .map_err(|e| {
                    ServiceError::api(StatusCode::BAD_REQUEST, "invalid_state", e.to_string())
                })?;

        let now = Timestamp::now().as_second();
        if now > auth_state.exp {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "expired",
                Tr::new("login-error-session-expired").to_string(),
            ));
        }

        let expires_at =
            Timestamp::from_second(auth_state.exp).unwrap_or_else(|_| Timestamp::now());

        Ok(Self {
            req,
            client_data,
            auth_state,
            expires_at,
            user_id,
        })
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

    // `prompt` is a space-delimited set (OIDC Core 3.1.2.1), so `login` can
    // arrive alongside other values (e.g. `login consent`). Parse it with the
    // same `PromptSet` the authorize handler uses rather than matching the
    // whole string, so any set containing `login` forces the assertion form.
    let requires_reauth = pending.as_ref().is_some_and(|p| {
        let prompt_requests_login = p
            .prompt
            .as_deref()
            .and_then(|raw| PromptSet::parse(raw).ok())
            .is_some_and(|set| set.contains(Prompt::Login));
        prompt_requests_login || p.max_age.is_some()
    }) || device_auth_pending;

    if !requires_reauth {
        if let Some(ref pending_id) = query.pending_auth {
            // Bounce back to /oauth/authorize only when the gate that endpoint
            // applies would accept the session. `auth.authenticated` is the
            // wrong question here: an enrollment bootstrap session (upstream
            // IdP sign-in, no FIDO2) holds a valid cookie but is not
            // hardware-verified, so deciding from it bounced the user to an
            // endpoint that refuses the session — consuming the single-use
            // pending id on the way (#1168). Asking the same predicate keeps
            // the two endpoints from disagreeing. NeedsAuth falls through to
            // the assertion form; so does a store failure, where rendering the
            // form needlessly costs one touch but redirecting could strand
            // the flow.
            let session_token = jar
                .get(vouch_common::SESSION_COOKIE_NAME)
                .map(|c| c.value());
            let authorized = match check_session_for_authorization(&state, session_token).await {
                Ok(AuthorizationSessionState::Authenticated { .. }) => true,
                Ok(AuthorizationSessionState::NeedsAuth) => false,
                Err(e) => {
                    tracing::error!("Session check failed at /login; rendering the form: {e}");
                    false
                }
            };
            if authorized {
                return axum::response::Redirect::to(&format!(
                    "/oauth/authorize?pending_auth={}",
                    urlencoding::encode(pending_id)
                ))
                .into_response();
            }
        } else if get_auth_context(&state, &jar).await.authenticated {
            // Without a pending authorization a signed-in user has nothing to
            // do here — IdP sign-in is the whole bar for the browser UI, so a
            // bootstrap session goes home like any other.
            return axum::response::Redirect::to("/").into_response();
        }
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

    // Only the rendered form needs the header context, and building it costs
    // a session and a user lookup that the session gate above already did.
    // Reaching this point means the form is being shown.
    let auth = get_auth_context(&state, &jar).await;

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
    Json(req): Json<BrowserLoginStartRequest>,
) -> Result<Json<BrowserLoginStartResponse>, ServiceError> {
    // Validate Origin header for CSRF protection (RFC 9700)
    tracing::info!("Browser login start (discoverable credential flow)");

    // Generate challenge
    let challenge = generate_challenge().map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            Tr::new("login-error-challenge-failed").to_string(),
        )
    })?;
    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().minutes(5))
        .map_err(|_| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "time_error",
                Tr::new("login-error-time-overflow").to_string(),
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

/// Record a failed browser-login attempt. The email feeds the audit row's
/// `email_domain`/`email_hmac` columns (never stored raw); without it the
/// event is invisible to org-scoped audit queries, which filter on domain.
async fn log_login_failure(
    audit: &db::audit::AuditStore,
    client: ClientInfo,
    user_id: &str,
    email: Option<&str>,
    authenticator_id: Option<&str>,
    reason: &str,
) {
    let params = AuthEventParams {
        user_id: user_id.to_string(),
        event_type: AuthEventType::LoginFailed,
        authenticator_id: authenticator_id.map(String::from),
        success: false,
        failure_reason: Some(reason.to_string()),
        client,
        ..AuthEventParams::default()
    };
    db::record_auth_event(audit, params, email.map(String::from)).await;
}

/// POST /login/webauthn/complete
///
/// Verify WebAuthn assertion and create session.
///
/// Origin header validation (CSRF protection) runs first, then
/// [`LoginCompletion::validate`] runs every check that reads only the
/// request body. Consuming the single-use challenge state needs the checked
/// request as an argument, so a malformed request cannot invalidate the state
/// token it carries and lock the user out of the flow.
#[expect(
    clippy::too_many_lines,
    reason = "FAPI 2.0 browser login orchestrates assertion verification and session issuance"
)]
pub(crate) async fn browser_login_complete(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    jar: CookieJar,
    ValidJson(req): ValidJson<BrowserLoginCompleteRequest>,
) -> Result<Response, ServiceError> {
    tracing::info!("Browser login complete (discoverable credential flow)");

    let checked = LoginCompletion::validate(req, &state).await?;

    // Mark the authentication state JWT consumed before any side effects.
    // The returned `ChallengeStateClaim` witness is the structural proof
    // threaded into the TokenIssuanceProof below — the only path to
    // `GrantProof::BrowserLogin`. Two concurrent requests with the same
    // state JWT collide on the deterministic PRIMARY KEY; only one wins.
    let challenge_claim = match db::try_consume_challenge_state(&state.store, &checked).await {
        Ok(claim) => claim,
        Err(db::ClaimError::AlreadyConsumed) => {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "state_already_used",
                Tr::new("login-error-state-already-used").to_string(),
            ));
        }
        Err(e) => {
            tracing::error!("Failed to mark browser login state used: {e}");
            return Err(ServiceError::Internal(
                "Failed to mark authentication state used".to_string(),
            ));
        }
    };

    let LoginCompletion {
        req,
        auth_state,
        user_id,
        client_data: _,
        expires_at: _,
    } = checked;

    // Look up authenticator and verify ownership (single JOIN query)
    use crate::services::auth::{AuthenticatorLookupParams, lookup_and_verify_authenticator};
    let lookup_result = match lookup_and_verify_authenticator(
        &state,
        AuthenticatorLookupParams {
            credential_id: req.credential_id.as_bytes(),
            user_id,
        },
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            let reason = match &e {
                crate::error::ServiceError::NotFound(entity) => {
                    format!("{entity}_not_found")
                }
                crate::error::ServiceError::Forbidden(_) => "user_mismatch".to_string(),
                _ => "lookup_error".to_string(),
            };
            // Credential lookup failed — no user row was loaded, so no email.
            log_login_failure(
                &state.audit,
                client_info.clone(),
                &user_id.to_string(),
                None,
                None,
                &reason,
            )
            .await;
            // Return generic error to prevent credential enumeration
            return Err(ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "auth_failed",
                Tr::new("login-error-auth-failed").to_string(),
            ));
        }
    };

    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // Server-side WebAuthn signature verification (offloaded to a blocking
    // thread — see verify_login_assertion for rationale).
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);

    use crate::services::auth::{LoginAssertionParams, verify_login_assertion};
    let verification_result = match verify_login_assertion(LoginAssertionParams {
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
    {
        Ok(result) => result,
        Err(e) => {
            log_login_failure(
                &state.audit,
                client_info.clone(),
                &user.id,
                Some(&user.email),
                Some(&authenticator.id),
                &e.to_string(),
            )
            .await;
            return Err(ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "auth_failed",
                Tr::new("login-error-auth-failed").to_string(),
            ));
        }
    };

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

    // The instant the assertion above verified, stamped by the verifier
    // itself. It backs both the browser session and the device approval, so
    // the token the device-code grant later mints reports the ceremony
    // instant rather than the CLI's poll instant.
    let auth_now = verification_result.verified_at;

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
                    verification: db::DeviceApproval::Observed(auth_now),
                },
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to authorize device auth '{device_auth_id}': {e}");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "device_auth_failed",
                    Tr::new("login-error-device-auth-failed").to_string(),
                )
            })?;

            db::record_auth_event(
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
            )
            .await;
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

    // Org domain, read once at session creation for the federation claims.
    // Fail closed: silently dropping a transient DB error here would
    // permanently degrade the session's `hd` claim.
    let org_domain = match user.org_id.as_deref() {
        Some(org_id) => {
            db::get_user_org_domain(&state.store, &user.id, org_id, user.org_domain.as_deref())
                .await
                .map_err(|e| {
                    tracing::error!("Failed to snapshot org domain: {e}");
                    ServiceError::api(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "db_error",
                        Tr::new("login-error-session-create-failed").to_string(),
                    )
                })?
        }
        None => None,
    };

    let session_result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            client_id: &client_id,
            scope: Some(ScopeSet::all()),
            binding: TokenBinding::Bearer,
            act: None,
            audience: None,
            hardware_verification: HardwareVerification::Verified {
                auth_time: Some(auth_now.as_second()),
            },
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: authenticator.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
            source_code_hash: None,
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

    // Log successful login event (consistent with failure path)
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        success: true,
        client: client_info,
        ..AuthEventParams::default()
    };
    db::record_auth_event(&state.audit, auth_event_params, Some(user.email.clone())).await;

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
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

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
    async fn test_login_page_prompt_login_consent_forces_reauth_with_idp_session() {
        // OIDC Core 3.1.2.1: `prompt` is a space-delimited set, so `login`
        // within `login consent` requests re-auth exactly as a bare `login`
        // does. With an IdP-only (not hardware-verified) session the authorize
        // endpoint stores the combined prompt verbatim; /login must recognise
        // `login` inside the set and show the assertion form.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "idp-reauth@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                verification: crate::test_utils::TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;

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
                prompt: Some("login consent"),
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

        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "prompt=login within `login consent` must show the login form; \
             got {} with location {:?}",
            resp.status,
            resp.headers.get("location")
        );
    }

    #[tokio::test]
    async fn test_login_page_shows_form_for_bootstrap_session_without_prompt() {
        // Issue #1168: an enrollment bootstrap session (upstream IdP sign-in,
        // no FIDO2) holds a valid cookie but is not hardware-verified, and
        // /oauth/authorize refuses it. With a default (no prompt, no max_age)
        // pending auth, /login must render the assertion form rather than
        // bounce the user to an endpoint that will turn them away — and it
        // must leave the single-use pending id unspent for the round trip.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "bootstrap-form@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                verification: crate::test_utils::TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;

        let pending_id = crate::test_utils::create_test_pending_auth(
            &state.store,
            crate::test_utils::TestPendingAuthSpec {
                client_id: &client.client_id,
                ..Default::default()
            },
        )
        .await;

        let resp = crate::test_utils::http_get_full(
            &app,
            &format!("/login?pending_auth={pending_id}"),
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "a session /oauth/authorize would refuse must get the assertion \
             form, not a redirect; got {} with location {:?}",
            resp.status,
            resp.headers.get("location")
        );
        assert!(
            crate::db::get_pending_oauth_authorization(&state.store, &pending_id)
                .await
                .expect("pending lookup")
                .is_some(),
            "rendering the form must not spend the single-use pending id"
        );
    }

    #[tokio::test]
    async fn test_login_page_redirects_bootstrap_session_home_no_pending() {
        // Without a pending authorization a signed-in user has nothing to do
        // at /login: IdP sign-in is the whole bar for the browser UI, so a
        // bootstrap (NotVerified) session goes home like a verified one.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "bootstrap-home@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                verification: crate::test_utils::TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;

        let resp = crate::test_utils::http_get_full(
            &app,
            "/login",
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert!(
            resp.status.is_redirection(),
            "a signed-in session skips the form, got {}",
            resp.status
        );
        let location = resp
            .headers
            .get("location")
            .expect("redirect location")
            .to_str()
            .expect("ascii location");
        assert_eq!(location, "/");
    }

    #[tokio::test]
    async fn test_login_page_redirects_verified_session_home() {
        // A hardware-verified session has nothing left to prove at /login.
        let (app, state) = crate::test_utils::test_app().await;

        let user =
            crate::test_utils::create_test_user(&state.store, "verified-home@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let resp = crate::test_utils::http_get_full(
            &app,
            "/login",
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert!(
            resp.status.is_redirection(),
            "a verified session skips the form, got {}",
            resp.status
        );
        let location = resp
            .headers
            .get("location")
            .expect("redirect location")
            .to_str()
            .expect("ascii location");
        assert_eq!(location, "/");
    }

    #[tokio::test]
    async fn test_login_page_no_prompt_redirects_with_session() {
        // Without prompt=login, an authenticated user with pending_auth
        // should be redirected back to /oauth/authorize.
        let (app, state) = crate::test_utils::test_app().await;

        let user = crate::test_utils::create_test_user(&state.store, "no-reauth@example.com").await;
        let auth_id = crate::test_utils::create_test_authenticator(&state.store, &user.id).await;
        let client = crate::test_utils::create_test_oauth_client(&state.store, &user.id).await;
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

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
        let session_token = crate::test_utils::create_test_session_with(
            &state,
            crate::test_utils::TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

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
        let _claim =
            crate::db::consume_challenge_state_for_test(&state.store, &state_jwt, expires_at)
                .await
                .expect("pre-consume must succeed");

        // POST to `/login/webauthn/complete` with the already-consumed state.
        // The body checks in Phases 2 and 3 precede the replay check, so the
        // fields must be well-formed; none of their values is used beyond that.
        let dummy = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": URL_SAFE_NO_PAD.encode([0u8; 16]),
            "authenticator_data": dummy,
            "client_data_json": valid_client_data(),
            "signature": dummy,
            "user_handle": URL_SAFE_NO_PAD.encode(Uuid::now_v7().as_bytes()),
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

    // ── a rejected body must leave the challenge state unconsumed ────────
    //
    // Field lengths are rejected during deserialization and the remaining
    // checks are what build a `LoginCompletion`, which the consume takes as an
    // argument. Either way the rejection happens first, so the user can retry
    // the same login with the same state token.

    /// POST `/login/webauthn/complete` with a fresh state JWT and valid
    /// dummies for every field but the two under test, then assert the
    /// rejection carries `expected_code` and left the state token unconsumed.
    async fn assert_rejected_with_state_intact(
        credential_id: &str,
        client_data_json: &str,
        expected_code: &str,
    ) {
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

        let dummy = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": credential_id,
            "authenticator_data": dummy,
            "client_data_json": client_data_json,
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
            resp_body.contains(expected_code),
            "expected '{expected_code}' in rejection body, got: {resp_body}"
        );

        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let consume =
            crate::db::consume_challenge_state_for_test(&state.store, &state_jwt, expires_at).await;
        assert!(
            consume.is_ok(),
            "a rejected request consumed the challenge state: {consume:?}"
        );
    }

    /// Well-formed base64url client data carrying a valid `webauthn.get` for
    /// this server, so a test can vary one field at a time.
    fn valid_client_data() -> String {
        URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://test.example.com"}"#,
        )
    }

    /// An empty string is valid base64url decoding to `vec![]`. The
    /// `CredentialIdData` bound rejects it while the body is deserialized, so
    /// the handler never runs and `invalid_request` is the extractor's code.
    #[tokio::test]
    async fn test_browser_login_empty_credential_id_leaves_state_unconsumed() {
        assert_rejected_with_state_intact("", &valid_client_data(), "invalid_request").await;
    }

    /// Below the 16-byte minimum, which locks in the whole range rather than
    /// only the empty case.
    #[tokio::test]
    async fn test_browser_login_short_credential_id_leaves_state_unconsumed() {
        let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert_rejected_with_state_intact(&short, &valid_client_data(), "invalid_request").await;
    }

    #[tokio::test]
    async fn test_browser_login_malformed_client_data_leaves_state_unconsumed() {
        let credential_id = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        assert_rejected_with_state_intact(&credential_id, &not_json, "invalid_input").await;
    }

    #[tokio::test]
    async fn test_browser_login_foreign_origin_leaves_state_unconsumed() {
        let credential_id = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let foreign = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://evil.example.com"}"#,
        );
        assert_rejected_with_state_intact(&credential_id, &foreign, "invalid_input").await;
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

        // The audit event is awaited before the response, so it is
        // visible immediately.
        let filter = crate::db::AuditEventFilter {
            event_types: Some(vec!["login_failed".to_string()]),
            email_domains: Some(vec!["example.com".to_string()]),
            user_id: Some(user.id.clone()),
            ..crate::db::AuditEventFilter::default()
        };
        let events = state
            .audit
            .query_events(&filter)
            .await
            .expect("query audit events");
        assert_eq!(
            events.len(),
            1,
            "login_failed must be visible to an org-scoped (email_domains) audit query"
        );
        let event = events.first().expect("one event");
        assert_eq!(event.email_domain.as_deref(), Some("example.com"));
    }
}
