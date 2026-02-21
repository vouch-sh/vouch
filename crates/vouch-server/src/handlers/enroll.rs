// SPDX-License-Identifier: BUSL-1.1
//! Enrollment handlers for browser-based device authorization flow.

use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::extractors::ClientInfo;
use crate::impl_template_response;
use askama::Template;
use axum::{
    Form, Json,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{ApiError, BrowserRegisterCompleteRequest, BrowserRegisterStartResponse};

use super::common::AuthContext;
use super::{
    create_session_cookie, extract_session_from_cookie, generate_random_bytes, hash_token,
    json_error, validate_registration_attestation,
};
use crate::redact_email;

// ============================================================================
// COSE Key Serialization
// ============================================================================

/// Convert a webauthn-rs `COSEKey` to raw CBOR bytes for storage.
///
/// This produces the same format expected by our WebAuthn verification code:
/// a CBOR map with keys: 1 (kty), 3 (alg), -1 (curve/n), -2 (x/e), -3 (y).
fn cose_key_to_cbor(
    key: &webauthn_rs::prelude::COSEKey,
) -> Result<Vec<u8>, (StatusCode, Json<ApiError>)> {
    use ciborium::Value;
    use webauthn_rs::prelude::{COSEKeyType, ECDSACurve, EDDSACurve};

    let map: Vec<(Value, Value)> = match &key.key {
        COSEKeyType::EC_EC2(ec2) => {
            // COSE EC2 key: {1: 2 (kty), 3: alg, -1: curve, -2: x, -3: y}
            let alg = key.type_ as i64;
            let curve = match ec2.curve {
                ECDSACurve::SECP256R1 => 1,
                ECDSACurve::SECP384R1 => 2,
                ECDSACurve::SECP521R1 => 3,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(2.into())), // kty = EC2
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Integer(curve.into()),
                ), // curve
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(ec2.x.to_vec()),
                ), // x
                (
                    Value::Integer((-3_i64).into()),
                    Value::Bytes(ec2.y.to_vec()),
                ), // y
            ]
        }
        COSEKeyType::RSA(rsa) => {
            // COSE RSA key: {1: 3 (kty), 3: alg, -1: n, -2: e}
            let alg = key.type_ as i64;
            vec![
                (Value::Integer(1.into()), Value::Integer(3.into())), // kty = RSA
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Bytes(rsa.n.to_vec()),
                ), // n
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(rsa.e.to_vec()),
                ), // e
            ]
        }
        COSEKeyType::EC_OKP(okp) => {
            // COSE OKP key: {1: 1 (kty), 3: alg, -1: curve, -2: x}
            let alg = key.type_ as i64;
            let curve = match okp.curve {
                EDDSACurve::ED25519 => 6,
                EDDSACurve::ED448 => 7,
            };
            vec![
                (Value::Integer(1.into()), Value::Integer(1.into())), // kty = OKP
                (Value::Integer(3.into()), Value::Integer(alg.into())), // alg
                (
                    Value::Integer((-1_i64).into()),
                    Value::Integer(curve.into()),
                ), // curve
                (
                    Value::Integer((-2_i64).into()),
                    Value::Bytes(okp.x.to_vec()),
                ), // x
            ]
        }
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut buf).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cbor_error",
            &e.to_string(),
        )
    })?;

    Ok(buf)
}

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

impl_template_response!(
    DeviceVerifyTemplate,
    EnrollWebauthnTemplate,
    EnrollKeysTemplate,
    SuccessTemplate,
    ErrorTemplate,
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
    #[allow(dead_code)]
    access_token: String,
}

/// OIDC ID token claims (minimal).
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[allow(dead_code)]
    nonce: Option<String>,
    /// Google Workspace hosted domain (e.g., "acme.com").
    /// Only present for Workspace accounts, not consumer Gmail.
    hd: Option<String>,
}

/// Client data JSON structure from `WebAuthn` response.
#[derive(Deserialize)]
#[allow(dead_code)]
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
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &crate::jwt::JwtType::BrowserRegistrationState.to_header(),
            self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.required_spec_claims.clear();
        let data = decode::<Self>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        // RFC 8725 §3.11: Validate typ header
        if data.header.typ.as_deref()
            != Some(crate::jwt::JwtType::BrowserRegistrationState.as_header_str())
        {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        }
        Ok(data.claims)
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Show device code entry page.
/// GET /device
#[allow(clippy::unused_async)]
pub async fn device_verify_page() -> impl IntoResponse {
    DeviceVerifyTemplate { error: None }
}

/// Handle device code submission.
/// POST /device
#[allow(clippy::unused_async)]
pub async fn device_verify_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserCodeForm>,
) -> Response {
    // Normalize user code (uppercase, ensure dash)
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

    // Look up device auth request
    let request = match db::get_device_auth_by_user_code(&state.db, &user_code).await {
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
    let expires_at = request.expires_at.to_jiff();

    if now > expires_at {
        return DeviceVerifyTemplate {
            error: Some("This code has expired. Please request a new one.".to_string()),
        }
        .into_response();
    }

    // Check if already used
    if request.status != "pending" {
        return DeviceVerifyTemplate {
            error: Some("This code has already been used.".to_string()),
        }
        .into_response();
    }

    // Check if OIDC is configured
    if !state.config().oidc_configured() {
        // No OIDC configured - go directly to WebAuthn registration
        // Generate state token for WebAuthn
        let oidc_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));

        // Store state
        let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

        if let Err(e) = db::create_oidc_state(
            &state.db,
            &oidc_state,
            &request.id,
            "", // No nonce for non-OIDC flow
            &state_expires.to_string(),
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

        // Show WebAuthn registration page without email (will prompt for it)
        return EnrollWebauthnTemplate {
            email: "new user".to_string(),
            state: oidc_state,
            rp_id: state.config().rp_id.clone(),
        }
        .into_response();
    }

    // OIDC configured - redirect to OIDC provider
    let config = state.config();
    let oidc_issuer = config.oidc_issuer_url.as_ref().map_or("", String::as_str);
    let client_id = config.oidc_client_id.as_ref().map_or("", String::as_str);

    // Generate state and nonce
    let oidc_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));
    let nonce = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));

    // Store state
    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.db,
        &oidc_state,
        &request.id,
        &nonce,
        &state_expires.to_string(),
    )
    .await
    {
        tracing::error!("Failed to create OIDC state: {}", e);
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to create session state".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Build redirect URL
    let redirect_uri = format!("{}/oauth/callback", state.config().base_url);
    let auth_url = format!(
        "{}/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}&prompt=login",
        oidc_issuer,
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&oidc_state),
        urlencoding::encode(&nonce)
    );

    tracing::info!("Redirecting to OIDC authorization URL: {}", auth_url);

    // Use 303 See Other (not 307) to ensure browser converts POST to GET
    // A 307 would preserve the POST method and body, sending user_code to Google
    Redirect::to(&auth_url).into_response()
}

/// Handle OIDC callback.
/// GET /oauth/callback
#[allow(clippy::unused_async, clippy::too_many_lines)]
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

    // Verify state
    let stored_state = match db::get_oidc_state(&state.db, &oidc_state).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid state".to_string(),
                back_url: None,
            }
            .into_response();
        }
        Err(_) => {
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
    let expires_at = stored_state.expires_at.to_jiff();

    if now > expires_at {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "State has expired".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Exchange code for tokens
    let config = state.config();
    let oidc_issuer = config.oidc_issuer_url.as_ref().map_or("", String::as_str);
    let client_id = config.oidc_client_id.as_ref().map_or("", String::as_str);
    let client_secret = config.oidc_client_secret_exposed().unwrap_or("");
    let redirect_uri = format!("{}/oauth/callback", config.base_url);

    let token_url = format!(
        "{}/token",
        oidc_issuer.replace("accounts.google.com", "oauth2.googleapis.com")
    );

    let client = match vouch_common::http::server_client(&format!(
        "vouch-server/{}",
        env!("CARGO_PKG_VERSION")
    )) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create HTTP client: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to complete authentication".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };
    let token_response = match client
        .post(&token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", &code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect_uri),
        ])
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

    // Decode ID token (just extract claims, skip signature verification for now as we trust the token endpoint)
    let id_token_parts: Vec<&str> = tokens.id_token.split('.').collect();
    if id_token_parts.len() != 3 {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Invalid ID token".to_string(),
            back_url: None,
        }
        .into_response();
    }

    let Ok(claims_json) = URL_SAFE_NO_PAD.decode(id_token_parts.get(1).unwrap_or(&"")) else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Invalid ID token".to_string(),
            back_url: None,
        }
        .into_response();
    };

    let claims: IdTokenClaims = match serde_json::from_slice(&claims_json) {
        Ok(c) => c,
        Err(_) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid ID token claims".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    if !claims.email_verified {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Email not verified".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Check domain restriction
    if let Some(domains) = state
        .config()
        .allowed_domains
        .as_ref()
        .filter(|d| !d.is_empty())
    {
        let email_domain = claims.email.split('@').nth(1).unwrap_or("");
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(email_domain)) {
            let allowed_list = domains.join(", ");
            return ErrorTemplate {
                title: "Domain Not Allowed".to_string(),
                message: format!(
                    "Only users from the following domains can enroll: {}. Your email ({}) is not from an allowed domain.",
                    allowed_list,
                    claims.email
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
        &state.db,
        &claims.email,
        None,
        claims.hd.as_deref(),
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
    let existing_auths = db::get_authenticators_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let authenticator_id = existing_auths.first().map(|a| a.id.clone());

    let session_result = match crate::services::auth::create_login_session(
        &state,
        crate::services::auth::CreateSessionParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: authenticator_id.as_deref(),
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
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
    let token_hash = hash_token(&token);

    // Handle CLI-initiated device auth flow
    let is_cli_flow = !stored_state.device_auth_id.is_empty()
        && !stored_state.device_auth_id.starts_with("DIRECT-");

    if is_cli_flow {
        if let Some(ref auth_id) = authenticator_id {
            // User already has a registered key — authorize the device auth
            // immediately so the CLI stops polling.
            if let Err(e) = db::authorize_device_auth(
                &state.db,
                &stored_state.device_auth_id,
                &user.id,
                &claims.email,
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
                &state.db,
                &user.id,
                &claims.email,
                &token_hash,
                Some(&stored_state.device_auth_id),
                &expires.to_string(),
            )
            .await
            {
                tracing::warn!("Failed to create enrollment session for CLI: {}", e);
            }
        }
    }

    // Delete the OIDC state (it's been consumed)
    if let Err(e) = db::delete_oidc_state(&state.db, &oidc_state).await {
        tracing::warn!("Failed to delete OIDC state: {e}");
    }

    tracing::info!("Session created for user: {}", redact_email(&claims.email));
    tracing::debug!("Setting vouch_session cookie and redirecting to /enroll/keys");

    // Create session cookie and redirect to keys page
    let cookie = create_session_cookie(&token, session_hours * 3600);

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/enroll/keys")
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Serve the key management page.
/// GET /enroll/keys
/// Authentication is via vouch_session cookie (set by oidc_callback).
pub async fn enroll_keys_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    tracing::debug!("enroll_keys_page: checking for session cookie");

    // Get session from vouch_session cookie
    match extract_session_from_cookie(&state, &jar).await {
        Ok(session) => {
            tracing::debug!(
                "enroll_keys_page: found valid session for {}",
                redact_email(&session.claims.email)
            );
            // Look up user to check org membership
            let (has_org, is_org_admin) =
                match db::get_user_by_id(&state.db, &session.claims.sub).await {
                    Ok(Some(user)) => (user.org_id.is_some(), user.is_org_admin),
                    _ => (false, false),
                };
            let auth = AuthContext {
                authenticated: true,
                user_id: Some(session.claims.sub),
                user_email: Some(session.claims.email),
                has_org,
                is_org_admin,
            };
            EnrollKeysTemplate {
                rp_id: state.config().rp_id.clone(),
                auth,
            }
            .into_response()
        }
        Err(_) => {
            tracing::debug!(
                "enroll_keys_page: no valid session found, redirecting to /enroll/start"
            );
            // No valid session - redirect to sign in
            Redirect::to("/enroll/start").into_response()
        }
    }
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
/// Authentication is via vouch_session cookie (set by oidc_callback).
#[allow(clippy::unused_async)]
pub async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<BrowserRegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    // Get session from vouch_session cookie
    let session = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let user_id = Uuid::parse_str(&session.claims.sub).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            &e.to_string(),
        )
    })?;

    let user_email = session.claims.email.clone();

    // Get device_auth_id from enrollment session if available (for CLI polling).
    // Look up by vouch_session token hash, since oidc_callback stores the
    // enrollment session keyed to the same token.
    let device_auth_id = match jar.get("vouch_session").map(|c| c.value()) {
        Some(token) => {
            let token_hash = hash_token(token);
            db::get_enrollment_session_by_token_hash(&state.db, &token_hash)
                .await
                .ok()
                .flatten()
                .and_then(|es| es.device_auth_id)
                .unwrap_or_default()
        }
        None => String::new(),
    };

    // Get any existing credentials for this user to exclude them
    let existing_auths = db::get_authenticators_for_user(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        "browser_register_start: user {} has {} existing credentials",
        redact_email(&session.claims.email),
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
    let (ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user_email, &user_email, Some(exclude_credentials))
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "webauthn_error",
                &e.to_string(),
            )
        })?;

    // Create registration state with webauthn verification state
    let now = jiff::Timestamp::now();
    let reg_exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 300);
    let reg_state = BrowserRegistrationState {
        device_auth_id,
        user_id,
        user_email: user_email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: reg_exp,
    };

    let state_token = reg_state
        .encode(state.config().jwt_secret.expose_secret())
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_error",
                &e.to_string(),
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

/// Complete browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/complete
#[allow(clippy::unused_async, clippy::too_many_lines)]
pub async fn browser_register_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BrowserRegisterCompleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    // Extract client info from headers (for auth event logging)
    let client_info = ClientInfo::from_headers(&headers);

    // Decode state containing webauthn verification state
    let reg_state =
        BrowserRegistrationState::decode(&req.state, state.config().jwt_secret.expose_secret())
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Decode credential data from base64url
    let credential_id_bytes = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            &e.to_string(),
        )
    })?;

    // Check for duplicate credential registration before proceeding
    if let Some(_existing) = db::get_authenticator_by_credential_id(&state.db, &credential_id_bytes)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
    {
        tracing::warn!(
            "Rejected duplicate credential registration for user: {}",
            reg_state.user_id
        );
        return Err(json_error(
            StatusCode::CONFLICT,
            "credential_already_registered",
            "This security key is already registered",
        ));
    }

    let attestation_object = URL_SAFE_NO_PAD
        .decode(&req.attestation_object)
        .map_err(|e| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_attestation",
                &e.to_string(),
            )
        })?;

    let client_data_json = URL_SAFE_NO_PAD.decode(&req.client_data_json).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            &e.to_string(),
        )
    })?;

    // Build the RegisterPublicKeyCredential for webauthn-rs verification
    use webauthn_rs::prelude::Base64UrlSafeData;
    let reg_credential = webauthn_rs_proto::RegisterPublicKeyCredential {
        id: req.credential_id.clone(),
        raw_id: Base64UrlSafeData::from(credential_id_bytes.clone()),
        response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation_object.clone()),
            client_data_json: Base64UrlSafeData::from(client_data_json),
            transports: None,
        },
        extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    };

    // Log raw attestation object for debugging
    // Use webauthn-rs to verify the attestation
    // This performs cryptographic verification of:
    // - Challenge matches
    // - Origin/RP ID matches
    // - Attestation signature is valid
    // - User presence (UP) and user verification (UV) flags
    // Use webauthn-rs to verify the attestation
    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &reg_state.webauthn_state)
        .map_err(|e| {
            tracing::warn!("WebAuthn verification failed: {}", e);
            json_error(
                StatusCode::BAD_REQUEST,
                "attestation_failed",
                &format!("Attestation verification failed: {e}"),
            )
        })?;

    // Validate attestation (hardware-only, extract device info)
    let validated = validate_registration_attestation(&attestation_object)?;

    // Extract COSE public key and convert to raw CBOR bytes for storage
    // This ensures compatibility with our server-side WebAuthn verification
    let cose_key = passkey.get_public_key();

    let public_key_cbor = cose_key_to_cbor(cose_key)?;

    // Use the credential_id from the passkey (parsed by webauthn-rs from the attestation)
    // rather than the one from the request, to ensure consistency with what the YubiKey has stored.
    let cred_id_to_store = passkey.cred_id().to_vec();

    // Store the authenticator with verified credential
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let authenticator_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        &validated.device_name,
        &cred_id_to_store,
        &public_key_cbor,
        validated.aaguid.as_deref(),
        Some(&user_handle),
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Mark device authorization as complete
    db::authorize_device_auth(
        &state.db,
        &reg_state.device_auth_id,
        &reg_state.user_id.to_string(),
        &reg_state.user_email,
        &authenticator_id,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Log enrollment event (fire-and-forget)
    let auth_event_params = AuthEventParams {
        user_id: reg_state.user_id.to_string(),
        event_type: AuthEventType::Enrollment,
        authenticator_id: Some(authenticator_id.clone()),
        client_ip: client_info.client_ip,
        user_agent: client_info.user_agent,
        client_hostname: None, // Browser enrollment doesn't have hostname
        client_os: None,
        client_arch: None,
        client_version: None,
        success: true,
        failure_reason: None,
    };
    let db = state.db.clone();
    tokio::spawn(async move {
        if let Err(e) = db::insert_auth_event(&db, &auth_event_params).await {
            tracing::warn!("Failed to log enrollment event: {}", e);
        }
    });

    tracing::info!(
        "Enrollment complete for: {} with {} (AAGUID: {})",
        redact_email(&reg_state.user_email),
        validated.device_name,
        validated.aaguid.as_deref().unwrap_or("unknown")
    );

    // Create a session for the browser so the user stays logged in
    let session_hours = i64::try_from(state.config().session_hours).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid session hours",
        )
    })?;

    let session_result = crate::services::auth::create_login_session(
        &state,
        crate::services::auth::CreateSessionParams {
            user_id: &reg_state.user_id.to_string(),
            email: &reg_state.user_email,
            authenticator_id: Some(&authenticator_id),
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
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

    // Return success template with session cookie
    let cookie = create_session_cookie(&token, session_hours * 3600);
    let html = SuccessTemplate.render().map_err(|e| {
        tracing::error!("Template render error: {}", e);
        json_error(
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
    // Check if OIDC is configured
    if !state.config().oidc_configured() {
        return ErrorTemplate {
            title: "Not Configured".to_string(),
            message: "Identity provider is not configured. Please contact your administrator."
                .to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    }

    let now = Timestamp::now();

    // Create a "virtual" device auth request for direct enrollment
    // This allows us to reuse the existing OIDC callback flow
    let expires_at = now
        .checked_add(Span::new().minutes(10))
        .unwrap_or(now)
        .to_string();

    // Generate unique codes for this direct enrollment attempt
    // user_code needs to be unique per the database constraint
    let unique_suffix = URL_SAFE_NO_PAD.encode(generate_random_bytes(8));
    let user_code = format!("{}{}", DIRECT_ENROLL_PREFIX, unique_suffix);
    let device_code_hash = format!(
        "{}{}",
        DIRECT_ENROLL_PREFIX,
        URL_SAFE_NO_PAD.encode(generate_random_bytes(16))
    );

    let device_auth_id = match db::create_device_auth_request(
        &state.db,
        &device_code_hash,
        &user_code,
        &expires_at,
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

    // Build OIDC authorization URL
    let config = state.config();
    let oidc_issuer = config.oidc_issuer_url.as_ref().map_or("", String::as_str);
    let client_id = config.oidc_client_id.as_ref().map_or("", String::as_str);

    // Generate state and nonce
    let oidc_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));
    let nonce = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));

    // Store state
    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.db,
        &oidc_state,
        &device_auth_id,
        &nonce,
        &state_expires.to_string(),
    )
    .await
    {
        tracing::error!("Failed to create OIDC state: {}", e);
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to start enrollment. Please try again.".to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    }

    // Build authorization URL
    // Google's OIDC authorization endpoint is /o/oauth2/v2/auth (not /authorize)
    let redirect_uri = format!("{}/oauth/callback", state.config().base_url);
    let auth_url = format!(
        "{}/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}&prompt=login",
        oidc_issuer,
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&oidc_state),
        urlencoding::encode(&nonce)
    );

    tracing::info!(
        "Direct enrollment: redirecting to OIDC authorization URL: {}",
        auth_url
    );

    Redirect::to(&auth_url).into_response()
}

/// Check if a device auth request is for direct enrollment.
#[allow(dead_code)]
pub fn is_direct_enrollment(device_auth: &db::DeviceAuthRequest) -> bool {
    device_auth.user_code.starts_with(DIRECT_ENROLL_PREFIX)
}
