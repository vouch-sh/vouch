//! Enrollment handlers for browser-based device authorization flow.

use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType, EnrollmentSession};
use crate::extractors::ClientInfo;
use crate::impl_template_response;
use askama::Template;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{
    Form, Json,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    ApiError, BrowserRegisterCompleteRequest, BrowserRegisterStartResponse,
    extract_aaguid_from_attestation, validate_hardware_attestation,
};

use super::{generate_random_bytes, json_error};

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
// Enrollment Session Cookie Management
// ============================================================================

/// Enrollment session cookie name.
const ENROLL_COOKIE_NAME: &str = "vouch_enroll";

/// Enrollment session duration (30 minutes).
const ENROLL_SESSION_MINUTES: i64 = 30;

/// Create an enrollment session cookie.
/// Returns the Set-Cookie header value, or None on failure.
async fn create_enrollment_session_cookie(
    state: &AppState,
    user_id: &str,
    user_email: &str,
    device_auth_id: Option<&str>,
) -> Option<String> {
    // Generate random token
    let mut token_bytes = [0u8; 32];
    aws_rand::fill(&mut token_bytes).ok()?;
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    // Hash for storage
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Calculate expiration
    let expires = Timestamp::now()
        .checked_add(Span::new().minutes(ENROLL_SESSION_MINUTES))
        .ok()?;
    let expires_str = expires.strftime("%Y-%m-%d %H:%M:%S").to_string();

    // Store session
    db::create_enrollment_session(
        &state.db,
        user_id,
        user_email,
        &token_hash,
        device_auth_id,
        &expires_str,
    )
    .await
    .ok()?;

    // Build cookie with security attributes
    // Use SameSite=Lax (not Strict) because the redirect from Google OAuth
    // would otherwise prevent the cookie from being sent on the subsequent navigation
    Some(format!(
        "{}={}; Path=/enroll; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        ENROLL_COOKIE_NAME,
        token,
        ENROLL_SESSION_MINUTES * 60
    ))
}

/// Get enrollment session from cookie.
/// Returns the session if valid, None otherwise.
pub async fn get_enrollment_session_from_cookie(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<EnrollmentSession> {
    // Get Cookie header
    let cookie_header = match headers.get(header::COOKIE) {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => {
                tracing::debug!("get_enrollment_session: cookie header not valid UTF-8");
                return None;
            }
        },
        None => {
            tracing::debug!("get_enrollment_session: no Cookie header present");
            return None;
        }
    };

    tracing::debug!(
        "get_enrollment_session: looking for {} cookie",
        ENROLL_COOKIE_NAME
    );

    // Parse cookies to find vouch_enroll
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", ENROLL_COOKIE_NAME)) {
            tracing::debug!(
                "get_enrollment_session: found {} cookie",
                ENROLL_COOKIE_NAME
            );

            // Hash the token to look up session
            let token_hash = hex::encode(digest::digest(&SHA256, value.as_bytes()));

            // Look up session
            let session =
                match db::get_enrollment_session_by_token_hash(&state.db, &token_hash).await {
                    Ok(Some(s)) => {
                        tracing::debug!("get_enrollment_session: found session in database");
                        s
                    }
                    Ok(None) => {
                        tracing::debug!("get_enrollment_session: session not found in database");
                        continue;
                    }
                    Err(e) => {
                        tracing::debug!("get_enrollment_session: database error: {}", e);
                        continue;
                    }
                };

            // Check if expired
            // SQLite stores timestamps without timezone, so we append 'Z' to parse as UTC
            let expires_with_tz = format!("{}Z", session.expires_at.replace(' ', "T"));
            let expires: Timestamp = match expires_with_tz.parse() {
                Ok(ts) => ts,
                Err(e) => {
                    tracing::debug!("get_enrollment_session: failed to parse expiration: {}", e);
                    continue;
                }
            };

            if expires > Timestamp::now() {
                // Update last used timestamp
                let _ = db::touch_enrollment_session(&state.db, &session.id).await;
                return Some(session);
            } else {
                tracing::debug!("get_enrollment_session: session expired");
            }
        }
    }

    tracing::debug!(
        "get_enrollment_session: {} cookie not found in header",
        ENROLL_COOKIE_NAME
    );
    None
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
    pub email: String,
    pub rp_id: String,
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
}

impl BrowserRegistrationState {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let data = decode::<Self>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
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
    let expires_at: Timestamp = match request.expires_at.parse() {
        Ok(ts) => ts,
        Err(_) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid request state".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

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
    if !state.config.oidc_configured() {
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
            rp_id: state.config.rp_id.clone(),
        }
        .into_response();
    }

    // OIDC configured - redirect to OIDC provider
    let oidc_issuer = state
        .config
        .oidc_issuer_url
        .as_ref()
        .map_or("", String::as_str);
    let client_id = state
        .config
        .oidc_client_id
        .as_ref()
        .map_or("", String::as_str);

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
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);
    let auth_url = format!(
        "{}/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}",
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
    let expires_at: Timestamp = match stored_state.expires_at.parse() {
        Ok(ts) => ts,
        Err(_) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid state".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    if now > expires_at {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "State has expired".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Exchange code for tokens
    let oidc_issuer = state
        .config
        .oidc_issuer_url
        .as_ref()
        .map_or("", String::as_str);
    let client_id = state
        .config
        .oidc_client_id
        .as_ref()
        .map_or("", String::as_str);
    let client_secret = state.config.oidc_client_secret_exposed().unwrap_or("");
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);

    let token_url = format!(
        "{}/token",
        oidc_issuer.replace("accounts.google.com", "oauth2.googleapis.com")
    );

    let client = reqwest::Client::new();
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
    if let Some(domains) = &state.config.allowed_domains {
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

    // Handle organization based on hosted domain
    let (org_id, is_first_user) = if let Some(domain) = &claims.hd {
        // Workspace user - get or create organization
        match db::get_or_create_org_by_domain(&state.db, domain, None, None).await {
            Ok((org, is_new)) => (Some(org.id), is_new),
            Err(e) => {
                tracing::error!("Failed to get/create organization: {}", e);
                return ErrorTemplate {
                    title: "Error".to_string(),
                    message: "Failed to process organization".to_string(),
                    back_url: None,
                }
                .into_response();
            }
        }
    } else {
        // Personal account (e.g., gmail.com) - no organization
        (None, false)
    };

    // First user from a domain becomes the org admin
    let is_org_admin = is_first_user && org_id.is_some();

    // Create or get user with organization
    let user = match db::upsert_user_with_org(
        &state.db,
        &claims.email,
        None,
        org_id.as_deref(),
        is_org_admin,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to create/get user: {}", e);
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create user".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Create enrollment session cookie
    let cookie = match create_enrollment_session_cookie(
        &state,
        &user.id,
        &claims.email,
        Some(&stored_state.device_auth_id),
    )
    .await
    {
        Some(c) => c,
        None => {
            tracing::error!("Failed to create enrollment session");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Delete the OIDC state (it's been consumed)
    let _ = db::delete_oidc_state(&state.db, &oidc_state).await;

    tracing::info!("Enrollment session created for: {}", claims.email);
    tracing::debug!("Setting cookie and redirecting to /enroll/keys");

    // Redirect to keys page with session cookie
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/enroll/keys")
        .header(header::SET_COOKIE, &cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Serve the key management page.
/// GET /enroll/keys
/// Authentication is via cookie (set by oidc_callback).
pub async fn enroll_keys_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    tracing::debug!("enroll_keys_page: checking for enrollment session cookie");

    // Get enrollment session from cookie
    let session = match get_enrollment_session_from_cookie(&state, &headers).await {
        Some(s) => {
            tracing::debug!("enroll_keys_page: found valid session for {}", s.user_email);
            s
        }
        None => {
            tracing::debug!(
                "enroll_keys_page: no valid session found, redirecting to /enroll/start"
            );
            // No valid session - redirect to start enrollment
            return Redirect::to("/enroll/start").into_response();
        }
    };

    EnrollKeysTemplate {
        email: session.user_email,
        rp_id: state.config.rp_id.clone(),
    }
    .into_response()
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
/// Authentication is via cookie (set by oidc_callback).
#[allow(clippy::unused_async)]
pub async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<BrowserRegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    // Get enrollment session from cookie
    let enroll_session = get_enrollment_session_from_cookie(&state, &headers)
        .await
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired enrollment session",
            )
        })?;

    let user_id = Uuid::parse_str(&enroll_session.user_id).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            &e.to_string(),
        )
    })?;

    let user_email = enroll_session.user_email.clone();
    let device_auth_id = enroll_session.device_auth_id.clone().unwrap_or_default();

    // Get any existing credentials for this user to exclude them
    let existing_auths = db::get_authenticators_for_user(&state.db, &enroll_session.user_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    let exclude_credentials: Vec<webauthn_rs::prelude::CredentialID> = existing_auths
        .iter()
        .map(|a| webauthn_rs::prelude::CredentialID::from(a.credential_id.clone()))
        .collect();

    // Build exclude_credential_ids for browser (base64url encoded)
    let exclude_credential_ids: Vec<String> = existing_auths
        .iter()
        .map(|a| URL_SAFE_NO_PAD.encode(&a.credential_id))
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
    let reg_state = BrowserRegistrationState {
        device_auth_id,
        user_id,
        user_email: user_email.clone(),
        webauthn_state,
    };

    let state_token = reg_state
        .encode(state.config.jwt_secret.expose_secret())
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
        rp_id: state.config.rp_id.clone(),
        rp_name: state.config.rp_name.clone(),
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
        BrowserRegistrationState::decode(&req.state, state.config.jwt_secret.expose_secret())
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

    // Use webauthn-rs to verify the attestation
    // This performs cryptographic verification of:
    // - Challenge matches
    // - Origin/RP ID matches
    // - Attestation signature is valid
    // - User presence (UP) and user verification (UV) flags
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

    // Validate attestation format - reject software passkeys and platform authenticators
    let validation = validate_hardware_attestation(&attestation_object);
    if let (Some(code), Some(message)) = (validation.error_code(), validation.error_message()) {
        tracing::warn!("Rejected registration: {}", code);
        return Err(json_error(StatusCode::BAD_REQUEST, code, message));
    }

    // Extract AAGUID from the attestation object (for logging, not blocking)
    // We parse it ourselves since webauthn-rs doesn't expose the AAGUID directly
    let aaguid = extract_aaguid_from_attestation(&attestation_object);

    // Determine device name from AAGUID if known
    let device_name = aaguid
        .as_deref()
        .and_then(vouch_common::lookup_device_model)
        .unwrap_or("Security Key");

    // Extract COSE public key and convert to raw CBOR bytes for storage
    // This ensures compatibility with our server-side WebAuthn verification
    let cose_key = passkey.get_public_key();
    let public_key_cbor = cose_key_to_cbor(cose_key)?;

    // Store the authenticator with verified credential
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let authenticator_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        device_name,
        &credential_id_bytes,
        &public_key_cbor,
        aaguid.as_deref(),
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

    // Log enrollment event
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
    if let Err(e) = db::insert_auth_event(&state.db, &auth_event_params).await {
        tracing::warn!("Failed to log enrollment event: {}", e);
    }

    tracing::info!(
        "Enrollment complete for: {} with {} (AAGUID: {})",
        reg_state.user_email,
        device_name,
        aaguid.as_deref().unwrap_or("unknown")
    );

    Ok(SuccessTemplate)
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
    if !state.config.oidc_configured() {
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
    let oidc_issuer = state
        .config
        .oidc_issuer_url
        .as_ref()
        .map_or("", String::as_str);
    let client_id = state
        .config
        .oidc_client_id
        .as_ref()
        .map_or("", String::as_str);

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
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);
    let auth_url = format!(
        "{}/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}",
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
