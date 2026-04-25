// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enrollment handlers for browser-based device authorization flow.

use super::extractors::ClientInfo;
use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::handlers::HasVersion;
use crate::impl_template_response;
use askama::Template;
use axum::{
    Form, Json,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{BrowserRegisterCompleteRequest, BrowserRegisterStartResponse};

use super::session::AuthContext;
use super::{
    create_session_cookie, extract_session_from_cookie, generate_random_bytes, hash_token,
    validate_registration_attestation,
};
use crate::redact_email;
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
use crate::services::error::ServiceError;
use crate::services::idp::IdentityResult;
use crate::services::oidc::ScopeSet;

// ============================================================================
// Templates
// ============================================================================

/// Device code entry page template.
#[derive(Template)]
#[template(path = "device_verify.html")]
pub struct DeviceVerifyTemplate {
    pub error: Option<String>,
}

/// WebAuthn registration page template.
#[derive(Template)]
#[template(path = "enroll_webauthn.html")]
pub struct EnrollWebauthnTemplate {
    pub email: String,
    pub state: String,
    pub rp_id: String,
}

/// Key management page template (shown after OAuth callback).
/// Authentication is via cookie, not state token in template.
#[derive(Template)]
#[template(path = "enroll_keys.html")]
pub struct EnrollKeysTemplate {
    pub rp_id: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Success page template.
#[derive(Template)]
#[template(path = "success.html")]
pub struct SuccessTemplate;

/// Error page template.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: Option<String>,
}

/// SAML POST binding auto-submit form template.
///
/// Rendered when the upstream IdP uses SAML POST binding. The page
/// auto-submits via `onload` JavaScript; the `<noscript>` fallback
/// handles browsers without JavaScript.
#[derive(Template)]
#[template(path = "saml_post_form.html")]
pub struct SamlPostFormTemplate {
    pub action_url: String,
    pub saml_request: String,
    pub relay_state: String,
}

impl_template_response!(
    DeviceVerifyTemplate,
    EnrollWebauthnTemplate,
    EnrollKeysTemplate,
    SuccessTemplate,
    ErrorTemplate,
    SamlPostFormTemplate,
);

// ============================================================================
// Request/Response Types
// ============================================================================

/// Form data for user code submission.
#[derive(Debug, Deserialize)]
pub struct UserCodeForm {
    user_code: String,
}

/// Query params for OIDC callback.
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// OIDC token response.
#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    access_token: String,
}

/// Client data JSON structure from `WebAuthn` response.
#[derive(Deserialize)]
#[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    typ: String,
}

/// Browser registration state stored between `WebAuthn` start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct BrowserRegistrationState {
    device_auth_id: String,
    user_id: Uuid,
    user_email: String,
    /// Serialized webauthn-rs PasskeyRegistration state for verification.
    webauthn_state: webauthn_rs::prelude::PasskeyRegistration,
    /// RFC 8725 §3.11: Issued at time for expiration enforcement.
    iat: i64,
    /// RFC 8725 §3.11: Expiration time (5 minutes).
    exp: i64,
}

impl BrowserRegistrationState {
    async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(self, crate::crypto::jwt::JwtType::BrowserRegistrationState)
            .await
    }

    async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        signer
            .decode_state_token(token, crate::crypto::jwt::JwtType::BrowserRegistrationState)
            .await
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Show device code entry page.
/// GET /device
pub async fn device_verify_page() -> impl IntoResponse {
    DeviceVerifyTemplate { error: None }
}

/// Handle device code submission.
/// POST /device
pub async fn device_verify_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserCodeForm>,
) -> Response {
    // Normalize user code (uppercase, strip whitespace, ensure dash)
    let user_code = form.user_code.to_uppercase().trim().to_string();
    let user_code = if user_code.chars().count() == 8 && !user_code.contains('-') {
        format!(
            "{}-{}",
            user_code.chars().take(4).collect::<String>(),
            user_code.chars().skip(4).collect::<String>()
        )
    } else {
        user_code
    };

    // Validate user code format before DB lookup.
    // Valid codes are "XXXX-XXXX" where X is from the device code alphabet
    // (consonants: BCDFGHJKLMNPQRSTVWXZ). Reject anything else immediately.
    if !is_valid_user_code_format(&user_code) {
        return DeviceVerifyTemplate {
            error: Some("Invalid code. Please check and try again.".to_string()),
        }
        .into_response();
    }

    // Look up device auth request
    let request = match db::get_device_auth_by_user_code(&state.store, &user_code).await {
        Ok(Some(req)) => req,
        Ok(None) => {
            return DeviceVerifyTemplate {
                error: Some("Invalid code. Please check and try again.".to_string()),
            }
            .into_response();
        }
        Err(_) => {
            return DeviceVerifyTemplate {
                error: Some("An error occurred. Please try again.".to_string()),
            }
            .into_response();
        }
    };

    // Check if expired
    let now = Timestamp::now();
    if now > request.expires_at {
        return DeviceVerifyTemplate {
            error: Some("This code has expired. Please request a new one.".to_string()),
        }
        .into_response();
    }

    // Check if already used
    if request.status != db::DeviceAuthStatus::Pending {
        return DeviceVerifyTemplate {
            error: Some("This code has already been used.".to_string()),
        }
        .into_response();
    }

    // No upstream IdP → go directly to WebAuthn; otherwise → initiate auth
    let Some(upstream) = state.upstream_idp.as_ref() else {
        // No IdP configured - go directly to WebAuthn registration
        let random_bytes = match generate_random_bytes(32) {
            Ok(bytes) => bytes,
            Err(_) => {
                return ErrorTemplate {
                    title: "Error".to_string(),
                    message: "Failed to generate secure random state".to_string(),
                    back_url: None,
                }
                .into_response();
            }
        };
        let oidc_state = URL_SAFE_NO_PAD.encode(random_bytes);

        let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

        if let Err(e) = db::create_oidc_state(
            &state.store,
            &oidc_state,
            &request.id,
            "", // No nonce for non-IdP flow
            "", // No PKCE for non-IdP flow
            state_expires,
        )
        .await
        {
            tracing::error!("Failed to create state: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session state".to_string(),
                back_url: None,
            }
            .into_response();
        }

        return EnrollWebauthnTemplate {
            email: "new user".to_string(),
            state: oidc_state,
            rp_id: state.config().rp_id.clone(),
        }
        .into_response();
    };

    let auth_request = match upstream.initiate_auth(state.config().as_ref()) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to initiate auth: {e:#}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to start authentication".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.store,
        &auth_request.state_key,
        &request.id,
        &auth_request.nonce,
        &auth_request.code_verifier,
        state_expires,
    )
    .await
    {
        tracing::error!("Failed to create auth state: {}", e);
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to create session state".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Use 303 See Other (not 307) to ensure browser converts POST to GET
    // A 307 would preserve the POST method and body, sending user_code to the IdP
    match auth_request.action {
        crate::services::idp::AuthAction::Redirect { url } => Redirect::to(&url).into_response(),
        crate::services::idp::AuthAction::PostForm {
            action_url,
            saml_request,
            relay_state,
        } => SamlPostFormTemplate {
            action_url,
            saml_request,
            relay_state,
        }
        .into_response(),
    }
}

/// Handle OIDC callback.
/// GET /oauth/callback
#[expect(
    clippy::too_many_lines,
    reason = "axum handler; OIDC callback orchestrates IdP exchange and enrollment"
)]
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OidcCallbackParams>,
) -> Response {
    // Check for error response
    if let Some(error) = params.error {
        let desc = params
            .error_description
            .unwrap_or_else(|| "Unknown error".to_string());
        return ErrorTemplate {
            title: error,
            message: desc,
            back_url: None,
        }
        .into_response();
    }

    // Get authorization code and state
    let Some(code) = params.code else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Missing authorization code".to_string(),
            back_url: None,
        }
        .into_response();
    };

    let Some(oidc_state) = params.state else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Missing state parameter".to_string(),
            back_url: None,
        }
        .into_response();
    };

    // Validate state length before DB lookup.
    // OIDC state is base64url-encoded 32 random bytes (43 chars).
    if oidc_state.len() > 128 {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Invalid state parameter".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Verify state
    let stored_state = match db::get_oidc_state(&state.store, &oidc_state).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid state".to_string(),
                back_url: None,
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to verify OIDC state: {e:#}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to verify state".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Check if state expired
    let now = Timestamp::now();
    if now > stored_state.expires_at {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "State has expired".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Exchange code for tokens using discovered OIDC token endpoint.
    // This handler is OIDC-specific: SAML responses go to POST /saml/acs (Phase 2).
    let Some(crate::services::idp::UpstreamIdp::Oidc(oidc_provider)) = state.upstream_idp.as_ref()
    else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "OIDC not configured. If using SAML, responses should be \
                      sent to /saml/acs, not /oauth/callback."
                .to_string(),
            back_url: None,
        }
        .into_response();
    };
    let config = state.config();
    let client_id = config.oidc_client_id.as_ref().map_or("", String::as_str);
    let client_secret = config.oidc_client_secret_exposed().unwrap_or("");
    let redirect_uri = format!("{}/oauth/callback", config.base_url);

    let token_url = oidc_provider.token_endpoint.as_str();

    // RFC 7636: Include code_verifier in token exchange (PKCE).
    // Build form params dynamically to only include code_verifier when present.
    let mut form_params = vec![
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    if !stored_state.code_verifier.is_empty() {
        form_params.push(("code_verifier", stored_state.code_verifier.as_str()));
    }

    let token_response = match state
        .http_client
        .post(token_url)
        .form(&form_params)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to complete authentication".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        tracing::error!("Token exchange failed: {}", error_text);
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to complete authentication".to_string(),
            back_url: None,
        }
        .into_response();
    }

    let tokens: OidcTokenResponse = match token_response.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to parse token response: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to complete authentication".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Verify ID token: signature, issuer, audience, nonce, email_verified,
    // and extract domain (OIDC Core Section 3.1.3.7).
    let identity = match crate::services::idp::oidc::verify_id_token(
        &state.http_client,
        oidc_provider,
        &tokens.id_token,
        client_id,
        &stored_state.nonce,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("ID token verification failed: {e:#}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to verify identity token".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    complete_enrollment_after_identity(&state, &stored_state, &oidc_state, identity).await
}

pub(crate) async fn complete_enrollment_after_identity(
    state: &Arc<AppState>,
    stored_state: &db::OidcState,
    state_key: &str,
    identity: IdentityResult,
) -> Response {
    // Check domain restriction.
    // For Google consumers (no `hd` claim), `identity.domain` is `None`,
    // so `email_domain` becomes "" and will never match an allowed domain.
    if let Some(domains) = state
        .config()
        .allowed_domains
        .as_ref()
        .filter(|d| !d.is_empty())
    {
        let email_domain = identity.domain.as_deref().unwrap_or("");
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(email_domain)) {
            let allowed_list = domains.join(", ");
            return ErrorTemplate {
                title: "Domain Not Allowed".to_string(),
                message: format!(
                    "Only users from the following domains can enroll: {}. Your email ({}) is not from an allowed domain.",
                    allowed_list,
                    identity.email
                ),
                back_url: None,
            }
            .into_response();
        }
    }

    // Enroll user with organization in a single atomic transaction.
    // This ensures that if org creation succeeds but user creation fails,
    // the entire operation is rolled back to prevent orphaned state.
    let enrollment = match db::enroll_user_with_org(
        &state.store,
        &identity.email,
        None,
        identity.domain.as_deref(),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to enroll user: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create user".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    let user = enrollment.user;

    // Create session for this user (using session cookie instead of enrollment cookie)
    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let duration = Span::new().hours(session_hours);
    let expires = match now.checked_add(duration) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to calculate session expiration: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Get authenticator (if any) for session claims
    let existing_auths = db::get_authenticators_for_user(&state.store, &user.id)
        .await
        .unwrap_or_default();
    let authenticator_id = existing_auths.first().map(|a| a.id.clone());

    // Issue an OAuth access token for the enrollment session.
    // This session is created after upstream IdP auth (OIDC/SAML) but BEFORE
    // FIDO2 WebAuthn registration — do NOT claim AAL3 or FIDO2 amr here.
    // The proper FIDO2 claims are set later in browser_register_complete.
    let client_id_for_token = state.config().base_url.clone();
    let session_result = match create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: authenticator_id.as_deref(),
            client_id: &client_id_for_token,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(now.as_second()),
            hardware_verification: crate::services::auth::HardwareVerification::NotVerified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to create session: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };
    let token = session_result.token;
    let token_hash = hash_token(token.expose_secret());

    // Handle CLI-initiated device auth flow
    let is_cli_flow = !stored_state.device_auth_id.is_empty()
        && !stored_state.device_auth_id.starts_with("DIRECT-");

    if is_cli_flow {
        if let Some(ref auth_id) = authenticator_id {
            // User already has a registered key — authorize the device auth
            // immediately so the CLI stops polling.
            if let Err(e) = db::authorize_device_auth(
                &state.store,
                &stored_state.device_auth_id,
                &user.id,
                &identity.email,
                auth_id,
            )
            .await
            {
                tracing::warn!("Failed to authorize device auth: {}", e);
            }
        } else {
            // No key yet — store the device_auth_id in an enrollment session
            // so browser_register_complete can authorize it after WebAuthn registration.
            if let Err(e) = db::create_enrollment_session(
                &state.store,
                &user.id,
                &identity.email,
                &token_hash,
                Some(&stored_state.device_auth_id),
                expires,
            )
            .await
            {
                tracing::warn!("Failed to create enrollment session for CLI: {}", e);
            }
        }
    }

    // Delete state only after enrollment/session creation succeeds.
    if let Err(e) = db::delete_oidc_state(&state.store, state_key).await {
        tracing::warn!("Failed to delete state: {e}");
    }

    tracing::info!(
        "Session created for user: {}",
        redact_email(&identity.email)
    );
    tracing::debug!("Setting session cookie and redirecting to /enroll/keys");

    // Create session cookie and redirect to keys page
    let cookie = create_session_cookie(token.expose_secret(), session_hours * 3600);

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/enroll/keys")
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Serve the key management page.
/// GET /enroll/keys
/// Authentication is via session cookie (set by oidc_callback).
pub async fn enroll_keys_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    tracing::debug!("enroll_keys_page: checking for session cookie");

    // Get session from cookie
    match extract_session_from_cookie(&state, &jar).await {
        Ok(token) => {
            let email = token.email.clone().unwrap_or_default();
            tracing::debug!(
                "enroll_keys_page: found valid session for {}",
                redact_email(&email)
            );
            // Look up user to check org membership
            let (has_org, is_org_admin) = match db::get_user_by_id(&state.store, &token.sub).await {
                Ok(Some(user)) => (user.org_id.is_some(), user.is_org_admin),
                _ => (false, false),
            };
            let auth = AuthContext {
                authenticated: true,
                user_id: Some(token.sub),
                user_email: Some(email),
                has_org,
                is_org_admin,
            };
            EnrollKeysTemplate {
                rp_id: state.config().rp_id.clone(),
                auth,
            }
            .into_response()
        }
        Err(err) => {
            tracing::warn!(
                error = ?err,
                "enroll_keys_page: session extraction failed, redirecting to /enroll/start"
            );
            // No valid session - redirect to sign in
            Redirect::to("/enroll/start").into_response()
        }
    }
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
/// Authentication is via session cookie (set by oidc_callback).
pub async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<BrowserRegisterStartResponse>, ServiceError> {
    // Get session from cookie
    let token = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let user_id = Uuid::parse_str(&token.sub).map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            e.to_string(),
        )
    })?;

    let user_email = token.email.clone().unwrap_or_default();

    // Get device_auth_id from enrollment session if available (for CLI polling).
    // Look up by session token hash, since oidc_callback stores the
    // enrollment session keyed to the same token.
    let device_auth_id = match jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value())
    {
        Some(cookie_val) => {
            let token_hash = hash_token(cookie_val);
            let enrollment_session =
                db::get_enrollment_session_by_token_hash(&state.store, &token_hash)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to look up enrollment session: {}", e);
                        ServiceError::api(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "db_error",
                            "Failed to look up enrollment session",
                        )
                    })?;
            enrollment_session
                .and_then(|es| es.device_auth_id)
                .unwrap_or_default()
        }
        None => String::new(),
    };

    tracing::debug!(
        "browser_register_start: resolved device_auth_id='{}'",
        if device_auth_id.is_empty() {
            "(empty)"
        } else {
            &device_auth_id
        }
    );

    // Get any existing credentials for this user to exclude them
    let existing_auths = db::get_authenticators_for_user(&state.store, &token.sub).await?;

    tracing::info!(
        "browser_register_start: user {} has {} existing credentials",
        redact_email(&user_email),
        existing_auths.len()
    );

    let exclude_credentials: Vec<webauthn_rs::prelude::CredentialID> = existing_auths
        .iter()
        .map(|a| webauthn_rs::prelude::CredentialID::from(a.credential_id.clone()))
        .collect();

    // Build exclude_credential_ids for browser (base64url encoded)
    let exclude_credential_ids: Vec<String> = existing_auths
        .iter()
        .map(|a| {
            let encoded = URL_SAFE_NO_PAD.encode(&a.credential_id);
            tracing::debug!(
                "Excluding credential: {} (len={})",
                encoded,
                a.credential_id.len()
            );
            encoded
        })
        .collect();

    // Use webauthn-rs to generate proper registration options with cryptographic verification
    let (mut ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user_email, &user_email, Some(exclude_credentials))
        .map_err(|e| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "webauthn_error",
                e.to_string(),
            )
        })?;

    // Request direct attestation so the browser forwards the x5c certificate
    // chain. This enables attestation chain validation against pinned Yubico
    // root CAs and AAGUID extraction from the leaf certificate.
    ccr.public_key.attestation = Some(webauthn_rs_proto::AttestationConveyancePreference::Direct);

    // Signal that only cross-platform security keys (USB/NFC) are accepted.
    // This suppresses the macOS "Scan QR Code" (hybrid/caBLE) option and
    // platform authenticator prompts (Touch ID, Windows Hello).
    if let Some(ref mut sel) = ccr.public_key.authenticator_selection {
        sel.authenticator_attachment =
            Some(webauthn_rs_proto::AuthenticatorAttachment::CrossPlatform);
    } else {
        ccr.public_key.authenticator_selection =
            Some(webauthn_rs_proto::AuthenticatorSelectionCriteria {
                authenticator_attachment: Some(
                    webauthn_rs_proto::AuthenticatorAttachment::CrossPlatform,
                ),
                ..Default::default()
            });
    }
    ccr.public_key.hints = Some(vec![
        webauthn_rs_proto::PublicKeyCredentialHints::SecurityKey,
    ]);

    // Create registration state with webauthn verification state
    let now = jiff::Timestamp::now();
    let reg_exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map_or(now.as_second() + 300, |t| t.as_second());
    let reg_state = BrowserRegistrationState {
        device_auth_id,
        user_id,
        user_email: user_email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: reg_exp,
    };

    let state_token = reg_state.encode(&state.state_signer).await.map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            e.to_string(),
        )
    })?;

    // Extract challenge from webauthn-rs generated options
    // The challenge is exposed via the public_key.challenge field
    let challenge_bytes: &[u8] = ccr.public_key.challenge.as_ref();
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    Ok(Json(BrowserRegisterStartResponse {
        challenge,
        rp_id: state.config().rp_id.clone(),
        rp_name: state.config().rp_name.clone(),
        user_id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
        user_email: user_email.clone(),
        user_display_name: user_email,
        algorithms: vec![-7, -257], // ES256, RS256
        state: state_token,
        exclude_credential_ids,
    }))
}

/// Maximum encoded length for `credential_id` (base64url).
/// WebAuthn spec allows up to 1023 bytes raw ≈ 1364 chars encoded.
const MAX_CREDENTIAL_ID_LEN: usize = 1400;

/// Maximum encoded length for `attestation_object` (base64url).
/// Hardware key attestations with certificate chains are typically under 4 KB.
const MAX_ATTESTATION_OBJECT_LEN: usize = 16 * 1024;

/// Maximum encoded length for `client_data_json` (base64url).
/// Client data JSON is a small JSON object (origin, type, challenge).
const MAX_CLIENT_DATA_JSON_LEN: usize = 4 * 1024;

/// Maximum encoded length for the registration `state` JWT.
const MAX_STATE_TOKEN_LEN: usize = 8 * 1024;

/// Minimum decoded byte length for a valid credential ID.
const MIN_CREDENTIAL_ID_BYTES: usize = 16;

/// Maximum decoded byte length for a valid credential ID (WebAuthn spec).
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// Complete browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/complete
///
/// Validation is ordered to fail fast before any database access:
/// 1. Field length bounds (reject obviously oversized/empty fields)
/// 2. State JWT decode + expiration check
/// 3. Base64url decode all fields
/// 4. Credential ID byte length validation
/// 5. Client data JSON structure validation (type, origin)
/// 6. Hardware attestation validation (reject software passkeys)
/// 7. WebAuthn cryptographic verification
/// 8. Database operations (duplicate check, store, authorize)
#[expect(
    clippy::too_many_lines,
    reason = "axum handler; FIDO2 registration completion: attestation, db, session"
)]
pub async fn browser_register_complete(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    Json(req): Json<BrowserRegisterCompleteRequest>,
) -> Result<impl IntoResponse, ServiceError> {
    // ── Phase 1: Field length bounds ────────────────────────────────────
    // Reject obviously oversized or empty fields before any processing.
    if req.state.len() > MAX_STATE_TOKEN_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "State token exceeds maximum length",
        ));
    }
    if req.credential_id.is_empty() || req.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential ID is empty or exceeds maximum length",
        ));
    }
    if req.attestation_object.is_empty()
        || req.attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_attestation",
            "Attestation object is empty or exceeds maximum length",
        ));
    }
    if req.client_data_json.is_empty() || req.client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data JSON is empty or exceeds maximum length",
        ));
    }

    // ── Phase 2: State JWT decode + expiration ──────────────────────────
    let reg_state = BrowserRegistrationState::decode(&req.state, &state.state_signer)
        .await
        .map_err(|e| ServiceError::api(StatusCode::BAD_REQUEST, "invalid_state", e.to_string()))?;

    // ── Phase 3: Base64url decode all fields ────────────────────────────
    let credential_id_bytes = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|e| {
        ServiceError::api(StatusCode::BAD_REQUEST, "invalid_credential", e.to_string())
    })?;

    let attestation_object = URL_SAFE_NO_PAD
        .decode(&req.attestation_object)
        .map_err(|e| {
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_attestation",
                e.to_string(),
            )
        })?;

    let client_data_json = URL_SAFE_NO_PAD.decode(&req.client_data_json).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            e.to_string(),
        )
    })?;

    // ── Phase 4: Credential ID byte length validation ───────────────────
    if credential_id_bytes.len() < MIN_CREDENTIAL_ID_BYTES
        || credential_id_bytes.len() > MAX_CREDENTIAL_ID_BYTES
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential ID length is outside the valid range (16-1023 bytes)",
        ));
    }

    // ── Phase 5: Client data JSON structure validation ──────────────────
    // Parse and validate the client data before any DB or crypto operations.
    let client_data_str = std::str::from_utf8(&client_data_json).map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data JSON is not valid UTF-8",
        )
    })?;

    let client_data: ClientData = serde_json::from_str(client_data_str).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            format!("Client data JSON is malformed: {e}"),
        )
    })?;

    if client_data.typ != "webauthn.create" {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data type must be 'webauthn.create'",
        ));
    }

    // Verify the origin matches the server's base URL.
    let expected_origin = &state.config().base_url;
    if client_data.origin != *expected_origin {
        tracing::warn!(
            "Origin mismatch: got '{}', expected '{}'",
            client_data.origin,
            expected_origin
        );
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data origin does not match the server",
        ));
    }

    // ── Phase 6: Hardware attestation validation ────────────────────────
    // Reject software passkeys, platform authenticators, and disallowed AAGUIDs.
    let validated = validate_registration_attestation(
        &attestation_object,
        &state.config().allowed_aaguids,
        state.config().require_attestation_cert,
    )?;

    // ── Phase 6b: Extract x5c certs before attestation_object is moved ─
    let x5c_certs = crate::attestation::extract_x5c_from_attestation(&attestation_object);

    // ── Phase 7: WebAuthn cryptographic verification ────────────────────
    use webauthn_rs::prelude::Base64UrlSafeData;
    let reg_credential = webauthn_rs_proto::RegisterPublicKeyCredential {
        id: req.credential_id.clone(),
        raw_id: Base64UrlSafeData::from(credential_id_bytes.clone()),
        response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation_object),
            client_data_json: Base64UrlSafeData::from(client_data_json),
            transports: None,
        },
        extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    };

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &reg_state.webauthn_state)
        .map_err(|e| {
            tracing::warn!("WebAuthn verification failed: {}", e);
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "attestation_failed",
                format!("Attestation verification failed: {e}"),
            )
        })?;

    // ── Phase 8: Database operations ────────────────────────────────────
    // All cheap validation passed — now check for duplicate credentials.
    if let Some(_existing) =
        db::get_authenticator_by_credential_id(&state.store, &credential_id_bytes).await?
    {
        tracing::warn!(
            "Rejected duplicate credential registration for user: {}",
            reg_state.user_id
        );
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "credential_already_registered",
            "This security key is already registered",
        ));
    }

    // Extract COSE public key and convert to raw CBOR bytes for storage
    // This ensures compatibility with our server-side WebAuthn verification
    let cose_key = passkey.get_public_key();

    let public_key_cbor = crate::crypto::cose::cose_key_to_cbor(cose_key).map_err(|e| {
        tracing::error!("Failed to serialize COSE key to CBOR: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cbor_error",
            "Failed to serialize key",
        )
    })?;

    // Use the credential_id from the passkey (parsed by webauthn-rs from the attestation)
    // rather than the one from the request, to ensure consistency with what the YubiKey has stored.
    let cred_id_to_store = passkey.cred_id().to_vec();

    // ── Phase 8b: x5c attestation chain validation (browser enrollment) ──
    // The browser enrollment path uses webauthn-rs for verification, so we
    // additionally validate the x5c chain here for attestation_verified status.
    let mut validated = validated;
    if let Some(x5c_certs) = x5c_certs {
        match crate::crypto::attestation_chain::validate_attestation_chain(
            &x5c_certs,
            validated.aaguid.as_deref(),
        ) {
            Ok(_chain_result) => {
                validated.attestation_verified = true;
                tracing::info!(
                    attestation_verified = true,
                    "Browser enrollment: x5c chain validated"
                );
            }
            Err(e) => {
                if state.config().require_attestation_cert {
                    tracing::warn!(
                        "Browser enrollment: x5c chain validation \
                         failed (fatal, require_attestation_cert=true): {e}"
                    );
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "attestation_chain_invalid",
                        "Attestation certificate chain could not be \
                         verified against trusted roots. Only genuine \
                         hardware authenticators with valid attestation \
                         chains are accepted.",
                    ));
                }
                tracing::warn!(
                    "Browser enrollment: x5c chain validation \
                     failed (non-fatal): {e}"
                );
            }
        }
    }

    // Store the authenticator with verified credential
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let authenticator_id = db::create_authenticator(
        &state.store,
        &reg_state.user_id.to_string(),
        &reg_state.user_email,
        &validated.device_name,
        &cred_id_to_store,
        &public_key_cbor,
        validated.aaguid.as_deref(),
        Some(&user_handle),
        validated.attestation_verified,
    )
    .await?;

    // Mark device authorization as complete (only for CLI-initiated flows)
    if reg_state.device_auth_id.is_empty() {
        tracing::debug!(
            "browser_register_complete: no device_auth_id, skipping device auth authorization \
             (direct browser enrollment)"
        );
    } else {
        db::authorize_device_auth(
            &state.store,
            &reg_state.device_auth_id,
            &reg_state.user_id.to_string(),
            &reg_state.user_email,
            &authenticator_id,
        )
        .await
        .inspect_err(|e| {
            tracing::error!(
                "Failed to authorize device auth '{}': {}",
                reg_state.device_auth_id,
                e
            );
        })?;
    }

    // Log enrollment event (fire-and-forget)
    let auth_event_params = AuthEventParams {
        user_id: reg_state.user_id.to_string(),
        event_type: AuthEventType::Enrollment,
        authenticator_id: Some(authenticator_id.clone()),
        success: true,
        ..AuthEventParams::default()
    }
    .with_client_info(client_info);
    let audit = state.audit.clone();
    let user_email_for_audit = reg_state.user_email.clone();
    tokio::spawn(async move {
        if let Err(e) =
            db::insert_auth_event(&audit, &auth_event_params, Some(&user_email_for_audit)).await
        {
            tracing::warn!("Failed to log enrollment event: {}", e);
        }
    });

    crate::infra::metrics::record_auth_event("enrollment");

    tracing::info!(
        "Enrollment complete for: {} with {} (AAGUID: {})",
        redact_email(&reg_state.user_email),
        validated.device_name,
        validated.aaguid.as_deref().unwrap_or("unknown")
    );

    // Create a session for the browser so the user stays logged in
    let session_hours = i64::try_from(state.config().session_hours).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid session hours",
        )
    })?;

    // Issue an OAuth access token (RFC 9068) — the server acts as both issuer and audience
    let enroll_client_id = state.config().base_url.clone();
    let user_id_str = reg_state.user_id.to_string();
    let session_result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user_id_str,
            email: &reg_state.user_email,
            authenticator_id: Some(&authenticator_id),
            client_id: &enroll_client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: None,
            hardware_verification: crate::services::auth::HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
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

    // Return success template with session cookie
    let cookie = create_session_cookie(token.expose_secret(), session_hours * 3600);
    let html = SuccessTemplate.render().map_err(|e| {
        tracing::error!("Template render error: {}", e);
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "render_error",
            "Failed to render template",
        )
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::from(html))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

// ============================================================================
// Direct Enrollment (Browser-only, no CLI)
// ============================================================================

/// Prefix for direct enrollment user codes (no CLI device authorization).
/// The full user_code will be `DIRECT-{random}` to ensure uniqueness.
const DIRECT_ENROLL_PREFIX: &str = "DIRECT-";

/// Start direct browser enrollment (no CLI required).
/// GET /enroll/start
///
/// This initiates OIDC authentication directly from the browser,
/// without requiring the CLI to create a device authorization request.
/// After successful enrollment, the user can download the CLI and login.
pub async fn direct_enroll_start(State(state): State<Arc<AppState>>) -> Response {
    let Some(upstream) = state.upstream_idp.as_ref() else {
        return ErrorTemplate {
            title: "Not Configured".to_string(),
            message: "Identity provider is not configured. Please contact your administrator."
                .to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    };

    let now = Timestamp::now();

    // Create a "virtual" device auth request for direct enrollment
    // This allows us to reuse the existing OIDC callback flow
    let expires_at = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    // Generate unique codes for this direct enrollment attempt
    // user_code needs to be unique per the database constraint
    let (suffix_bytes, hash_bytes) = match (generate_random_bytes(8), generate_random_bytes(16)) {
        (Ok(s), Ok(h)) => (s, h),
        _ => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to generate secure random codes".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };
    let unique_suffix = URL_SAFE_NO_PAD.encode(suffix_bytes);
    let user_code = format!("{}{}", DIRECT_ENROLL_PREFIX, unique_suffix);
    let device_code_hash = format!(
        "{}{}",
        DIRECT_ENROLL_PREFIX,
        URL_SAFE_NO_PAD.encode(hash_bytes)
    );

    let device_auth_id = match db::create_device_auth_request(
        &state.store,
        &device_code_hash,
        &user_code,
        None,
        expires_at,
        5,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to create direct enrollment request: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to start enrollment. Please try again.".to_string(),
                back_url: Some("/".to_string()),
            }
            .into_response();
        }
    };

    // Initiate upstream IdP authentication (upstream is guaranteed Some from guard above)
    let auth_request = match upstream.initiate_auth(state.config().as_ref()) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to initiate auth for direct enrollment: {e:#}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to start enrollment. Please try again.".to_string(),
                back_url: Some("/".to_string()),
            }
            .into_response();
        }
    };

    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.store,
        &auth_request.state_key,
        &device_auth_id,
        &auth_request.nonce,
        &auth_request.code_verifier,
        state_expires,
    )
    .await
    {
        tracing::error!("Failed to create auth state: {}", e);
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to start enrollment. Please try again.".to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    }

    match auth_request.action {
        crate::services::idp::AuthAction::Redirect { url } => Redirect::to(&url).into_response(),
        crate::services::idp::AuthAction::PostForm {
            action_url,
            saml_request,
            relay_state,
        } => SamlPostFormTemplate {
            action_url,
            saml_request,
            relay_state,
        }
        .into_response(),
    }
}

/// Check if a device auth request is for direct enrollment.
pub fn is_direct_enrollment(device_auth: &db::DeviceAuthRequest) -> bool {
    device_auth.user_code.starts_with(DIRECT_ENROLL_PREFIX)
}

/// Characters used for user code generation (consonants only, no ambiguous chars).
/// Must match the alphabet in `device.rs`.
const USER_CODE_CHARS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Validate that a user code matches the expected `XXXX-XXXX` format
/// where each character is from the device code alphabet.
///
/// This rejects obviously invalid codes before hitting the database.
fn is_valid_user_code_format(code: &str) -> bool {
    let bytes = code.as_bytes();
    // Must be exactly 9 characters: 4 letters, dash, 4 letters
    if bytes.len() != 9 {
        return false;
    }
    if bytes.get(4).copied() != Some(b'-') {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .all(|(_, &b)| USER_CODE_CHARS.contains(&b))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]

    use super::*;
    use crate::test_utils::{http_post_json, test_app};
    use axum::http::StatusCode;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uuid::Uuid;

    /// Build a valid `BrowserRegistrationState` JWT using the test signer.
    ///
    /// Uses `webauthn.start_passkey_registration` to obtain a real
    /// `PasskeyRegistration` value — the struct cannot be constructed any
    /// other way because its fields are private to webauthn-rs.
    async fn make_valid_state_token(state: &AppState) -> String {
        let user_id = Uuid::now_v7();
        let (_ccr, webauthn_state) = state
            .webauthn
            .start_passkey_registration(user_id, "test@example.com", "test@example.com", None)
            .expect("start_passkey_registration");

        let now = jiff::Timestamp::now();
        let reg_state = BrowserRegistrationState {
            device_auth_id: String::new(),
            user_id,
            user_email: "test@example.com".to_string(),
            webauthn_state,
            iat: now.as_second(),
            exp: now.as_second() + 300,
        };

        reg_state
            .encode(&state.state_signer)
            .await
            .expect("encode state")
    }

    /// Build a minimal valid base64url credential_id (16 zero bytes).
    fn valid_credential_id() -> String {
        URL_SAFE_NO_PAD.encode([0u8; 16])
    }

    /// Build a minimal valid base64url attestation_object (1 non-empty byte).
    fn valid_attestation_object() -> String {
        URL_SAFE_NO_PAD.encode([0u8; 1])
    }

    /// Build a minimal valid base64url client_data_json.
    fn valid_client_data_json() -> String {
        let json =
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://test.example.com"}"#;
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    // ── test_enrollment_complete_missing_state ───────────────────────────────

    #[tokio::test]
    async fn test_enrollment_complete_missing_state() {
        let (app, _state) = test_app().await;

        // Omit the `state` field entirely — serde will fail to deserialize.
        let body = serde_json::json!({
            "credential_id": valid_credential_id(),
            "attestation_object": valid_attestation_object(),
            "client_data_json": valid_client_data_json(),
        })
        .to_string();

        let (status, _body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

        // Missing required JSON field → 422 Unprocessable Entity (axum extractor error)
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── test_enrollment_complete_invalid_state_token ─────────────────────────

    #[tokio::test]
    async fn test_enrollment_complete_invalid_state_token() {
        let (app, _state) = test_app().await;

        let body = serde_json::json!({
            "state": "not-a-jwt",
            "credential_id": valid_credential_id(),
            "attestation_object": valid_attestation_object(),
            "client_data_json": valid_client_data_json(),
        })
        .to_string();

        let (status, resp_body) =
            http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            resp_body.contains("invalid_state"),
            "expected 'invalid_state' in body, got: {resp_body}"
        );
    }

    // ── test_enrollment_complete_missing_credential_id ───────────────────────

    #[tokio::test]
    async fn test_enrollment_complete_missing_credential_id() {
        let (app, state) = test_app().await;

        let valid_state = make_valid_state_token(&state).await;

        // Omit `credential_id` — serde will fail to deserialize.
        let body = serde_json::json!({
            "state": valid_state,
            "attestation_object": valid_attestation_object(),
            "client_data_json": valid_client_data_json(),
        })
        .to_string();

        let (status, _body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── test_enrollment_complete_oversized_credential_id ─────────────────────

    #[tokio::test]
    async fn test_enrollment_complete_oversized_credential_id() {
        let (app, state) = test_app().await;

        let valid_state = make_valid_state_token(&state).await;

        // Build a credential_id that exceeds MAX_CREDENTIAL_ID_LEN (1400 chars).
        let oversized = "A".repeat(MAX_CREDENTIAL_ID_LEN + 1);

        let body = serde_json::json!({
            "state": valid_state,
            "credential_id": oversized,
            "attestation_object": valid_attestation_object(),
            "client_data_json": valid_client_data_json(),
        })
        .to_string();

        let (status, resp_body) =
            http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            resp_body.contains("invalid_credential"),
            "expected 'invalid_credential' in body, got: {resp_body}"
        );
    }

    // ── test_enrollment_complete_invalid_base64_credential_id ────────────────

    #[tokio::test]
    async fn test_enrollment_complete_invalid_base64_credential_id() {
        let (app, state) = test_app().await;

        let valid_state = make_valid_state_token(&state).await;

        // "!!" is not valid base64url.
        let body = serde_json::json!({
            "state": valid_state,
            "credential_id": "!!not-base64url!!",
            "attestation_object": valid_attestation_object(),
            "client_data_json": valid_client_data_json(),
        })
        .to_string();

        let (status, resp_body) =
            http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            resp_body.contains("invalid_credential"),
            "expected 'invalid_credential' in body, got: {resp_body}"
        );
    }
}
