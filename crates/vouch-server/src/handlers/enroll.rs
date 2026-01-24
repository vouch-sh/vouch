//! Enrollment handlers for browser-based device authorization flow.

use crate::AppState;
use crate::db;
use askama::Template;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{ApiError, BrowserRegisterCompleteRequest, BrowserRegisterStartResponse};

// ============================================================================
// Templates
// ============================================================================

/// Device code entry page template.
#[derive(Template)]
#[template(path = "device_verify.html")]
pub struct DeviceVerifyTemplate {
    pub error: Option<String>,
}

impl IntoResponse for DeviceVerifyTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// WebAuthn registration page template.
#[derive(Template)]
#[template(path = "enroll_webauthn.html")]
pub struct EnrollWebauthnTemplate {
    pub email: String,
    pub state: String,
    pub rp_id: String,
}

impl IntoResponse for EnrollWebauthnTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Success page template.
#[derive(Template)]
#[template(path = "success.html")]
pub struct SuccessTemplate;

impl IntoResponse for SuccessTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Error page template.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: Option<String>,
}

impl IntoResponse for ErrorTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

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
// Helper Functions
// ============================================================================

/// Generate random bytes.
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// JSON error response helper.
fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
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

    Redirect::temporary(&auth_url).into_response()
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
    let client_secret = state
        .config
        .oidc_client_secret
        .as_ref()
        .map_or("", String::as_str);
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

    // Store email in state for WebAuthn registration
    // Update the OIDC state to include the email (we'll use a new state token)
    let new_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));
    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    // Create new state with email embedded
    if let Err(e) = db::create_oidc_state(
        &state.db,
        &new_state,
        &stored_state.device_auth_id,
        &claims.email, // Store email in nonce field
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

    // Delete old state
    let _ = db::delete_oidc_state(&state.db, &oidc_state).await;

    // Show WebAuthn registration page
    EnrollWebauthnTemplate {
        email: claims.email,
        state: new_state,
        rp_id: state.config.rp_id.clone(),
    }
    .into_response()
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
#[allow(clippy::unused_async)]
pub async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<vouch_common::BrowserRegisterStartRequest>,
) -> Result<Json<BrowserRegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    // Verify state token
    let oidc_state = db::get_oidc_state(&state.db, &req.oidc_state)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "Invalid state token",
            )
        })?;

    // Check if expired
    let now = Timestamp::now();
    let expires_at: Timestamp = oidc_state.expires_at.parse().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid timestamp",
        )
    })?;

    if now > expires_at {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "expired_state",
            "State has expired",
        ));
    }

    // Get device auth request to verify it's still valid
    let device_auth = db::get_device_auth_by_id(&state.db, &oidc_state.device_auth_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid request",
            )
        })?;

    if device_auth.status != "pending" {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "already_used",
            "This code has already been used",
        ));
    }

    // Get email from nonce field (set during OIDC callback)
    let user_email = if oidc_state.nonce.is_empty() {
        // Non-OIDC flow - use a placeholder email for now
        "user@localhost".to_string()
    } else {
        oidc_state.nonce.clone()
    };

    // Create or get user
    let user = db::upsert_user(&state.db, &user_email, None)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    let user_id = Uuid::parse_str(&user.id).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            &e.to_string(),
        )
    })?;

    // Get any existing credentials for this user to exclude them
    let existing_auths = db::get_authenticators_for_user(&state.db, &user.id)
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
        device_auth_id: device_auth.id,
        user_id,
        user_email: user_email.clone(),
        webauthn_state,
    };

    let state_token = reg_state.encode(&state.config.jwt_secret).map_err(|e| {
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
    }))
}

/// Complete browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/complete
#[allow(clippy::unused_async, clippy::too_many_lines)]
pub async fn browser_register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BrowserRegisterCompleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    // Decode state containing webauthn verification state
    let reg_state = BrowserRegistrationState::decode(&req.state, &state.config.jwt_secret)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Decode credential data from base64url
    let credential_id_bytes = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            &e.to_string(),
        )
    })?;

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

    // Extract AAGUID from the attestation object
    // We parse it ourselves since webauthn-rs doesn't expose the AAGUID directly
    let aaguid = extract_aaguid_from_attestation(&attestation_object);

    // Determine device name from AAGUID if known
    let device_name = aaguid
        .as_deref()
        .and_then(vouch_common::lookup_device_model)
        .unwrap_or("Security Key");

    // Serialize the passkey for storage (contains COSE public key)
    let passkey_json = serde_json::to_vec(&passkey).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            &e.to_string(),
        )
    })?;

    // Store the authenticator with verified credential
    let authenticator_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        device_name,
        &credential_id_bytes,
        &passkey_json,
        aaguid.as_deref(),
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

    tracing::info!(
        "Enrollment complete for: {} with {} (AAGUID: {})",
        reg_state.user_email,
        device_name,
        aaguid.as_deref().unwrap_or("unknown")
    );

    Ok(SuccessTemplate)
}

/// Extract AAGUID from CBOR-encoded attestation object.
///
/// The attestation object structure (CBOR map):
/// - `fmt`: attestation statement format
/// - `attStmt`: attestation statement
/// - `authData`: authenticator data containing AAGUID and credential public key
///
/// The authData structure:
/// - rpIdHash: 32 bytes (SHA-256 of RP ID)
/// - flags: 1 byte
/// - signCount: 4 bytes (big-endian)
/// - attestedCredentialData (if AT flag set):
///   - aaguid: 16 bytes
///   - credIdLen: 2 bytes (big-endian)
///   - credId: credIdLen bytes
///   - credentialPublicKey: COSE-encoded public key
fn extract_aaguid_from_attestation(attestation: &[u8]) -> Option<String> {
    if attestation.len() < 37 {
        return None;
    }

    // Parse the CBOR attestation object
    let value: ciborium::Value = ciborium::from_reader(attestation).ok()?;

    // Extract authData from the map
    let auth_data = value.as_map().and_then(|m| {
        m.iter()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .and_then(|(_, v)| v.as_bytes())
    })?;

    // Extract AAGUID from authenticator data
    vouch_common::extract_aaguid_from_auth_data(auth_data)
}
