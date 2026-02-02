// SPDX-License-Identifier: BUSL-1.1
//! Authentication handlers for registration and login.

use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::extractors::ClientInfo;
use crate::webauthn_verify;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use headers::authorization::{Authorization, Bearer};
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    ApiError, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest, LoginStartResponse,
    Raw, RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest,
    RegisterStartResponse, SessionStatus, fido2_types::Challenge,
};

use super::{
    clear_session_cookie, generate_challenge, hash_token, json_error,
    validate_registration_attestation,
};

// ============================================================================
// Registration State (stored temporarily)
// ============================================================================

/// Registration state stored between start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationState {
    user_id: Uuid,
    user_name: String,
    device_name: String,
    challenge: Challenge<Raw>,
    rp_id: String,
}

impl RegistrationState {
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
// Authentication State (stored temporarily)
// ============================================================================

/// Authentication state stored between start and complete.
/// Simplified for discoverable credentials - no user lookup needed upfront.
#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationState {
    challenge: Challenge<Raw>,
    rp_id: String,
}

impl AuthenticationState {
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
// JWT Session Claims
// ============================================================================

/// JWT claims for session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject (user ID).
    pub sub: String,
    /// User email.
    pub email: String,
    /// Authenticator ID used for this session.
    /// Optional for OIDC-authenticated users who haven't registered a security key yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_id: Option<String>,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// Start registration - generate challenge and return to client.
///
/// This endpoint requires authentication. Users must first enroll via OIDC
/// (`vouch enroll`) to register their first key. After that, they can add
/// additional keys via this endpoint after logging in with an existing key.
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    // Require authentication
    let session = super::extract_session(&state, auth_header, &jar).await?;
    let user_id = Uuid::parse_str(&session.claims.sub).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            &e.to_string(),
        )
    })?;
    let user_email = &session.claims.email;

    tracing::info!(
        "Registration start for authenticated user: {} (adding key: {})",
        user_email,
        req.name
    );

    // Verify user exists (should always exist if they have a valid session)
    let user = db::get_user_by_id(&state.db, &session.claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    // Get existing credentials to exclude
    let existing_auths = db::get_authenticators_for_user(&state.db, &user.id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    let exclude_credential_ids: Vec<vouch_common::CredentialId<vouch_common::Raw>> = existing_auths
        .iter()
        .map(|a| a.credential_id.clone().into())
        .collect();

    // Generate challenge
    let challenge = generate_challenge();

    // Create state token
    let challenge: Challenge<Raw> = challenge.into();
    let reg_state = RegistrationState {
        user_id,
        user_name: user.email.clone(),
        device_name: req.name,
        challenge: challenge.clone(),
        rp_id: state.config.rp_id.clone(),
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

    Ok(Json(RegisterStartResponse {
        challenge,
        rp_id: state.config.rp_id.clone(),
        rp_name: state.config.rp_name.clone(),
        user_id,
        user_name: user.email,
        algorithms: vec![-7], // ES256
        state: state_token,
        exclude_credential_ids,
    }))
}

/// Complete registration - verify attestation and store credential.
pub async fn register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterCompleteRequest>,
) -> Result<Json<RegisterCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Registration complete");

    // Decode state
    let reg_state = RegistrationState::decode(&req.state, state.config.jwt_secret.expose_secret())
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // For now, we do basic validation and trust the CLI's local verification
    // In production, use webauthn-rs to verify the attestation
    if req.credential_id.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "credential_id is empty",
        ));
    }

    if req.public_key.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "public_key is empty",
        ));
    }

    // Check for duplicate credential registration
    if let Some(_existing) = db::get_authenticator_by_credential_id(&state.db, &req.credential_id)
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

    // Validate attestation (hardware-only, extract device info)
    let validated = validate_registration_attestation(&req.attestation_object)?;

    // Store the authenticator
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let device_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        &reg_state.device_name,
        &req.credential_id,
        &req.public_key,
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

    tracing::info!("Registered new authenticator: {}", device_id);

    Ok(Json(RegisterCompleteResponse {
        device_id: Uuid::parse_str(&device_id).map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "uuid_error",
                &e.to_string(),
            )
        })?,
        message: "Registration successful".to_string(),
    }))
}

/// Start login - generate challenge for discoverable credential authentication.
/// No email lookup needed - the YubiKey identifies the user via user_handle.
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login start (discoverable credential flow)");

    // Generate challenge
    let challenge = generate_challenge();

    // Create state token (simplified - no user info needed upfront)
    let challenge: Challenge<Raw> = challenge.into();
    let auth_state = AuthenticationState {
        challenge: challenge.clone(),
        rp_id: state.config.rp_id.clone(),
    };

    let state_token = auth_state
        .encode(state.config.jwt_secret.expose_secret())
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_error",
                &e.to_string(),
            )
        })?;

    Ok(Json(LoginStartResponse {
        challenge,
        rp_id: state.config.rp_id.clone(),
        state: state_token,
    }))
}

/// Complete login - verify assertion and issue session token.
/// Uses discoverable credential flow: credential_id and user_handle identify the user.
#[allow(clippy::too_many_lines)]
pub async fn login_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<Json<LoginCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login complete (discoverable credential flow)");

    // Extract client info from headers
    let client_info = ClientInfo::from_headers(&headers);

    // Get client context from request (sent by CLI)
    let client_ctx = req.client_context.as_ref();

    // Decode state (only contains challenge and rp_id)
    let auth_state =
        AuthenticationState::decode(&req.state, state.config.jwt_secret.expose_secret())
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Parse user_handle as UUID to identify the user
    let user_id = Uuid::from_slice(&req.user_handle).map_err(|_| {
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
            client_hostname: client_ctx.and_then(|c| c.hostname.clone()),
            client_os: client_ctx.and_then(|c| c.os.clone()),
            client_arch: client_ctx.and_then(|c| c.arch.clone()),
            client_version: client_ctx.and_then(|c| c.cli_version.clone()),
            success: false,
            failure_reason: Some(reason.to_string()),
        };
        // Spawn to avoid blocking the response
        let db = state.db.clone();
        tokio::spawn(async move {
            if let Err(e) = db::insert_auth_event(&db, &params).await {
                tracing::warn!("Failed to log auth event: {}", e);
            }
        });
    };

    // Get the authenticator by credential_id
    tracing::info!(
        "login_complete: credential_id_hex={} (len={})",
        hex::encode(&req.credential_id),
        req.credential_id.len()
    );
    let authenticator = db::get_authenticator_by_credential_id(&state.db, &req.credential_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| {
            log_failure(&user_id.to_string(), None, "credential_not_found");
            json_error(
                StatusCode::NOT_FOUND,
                "credential_not_found",
                "Credential not registered with this server",
            )
        })?;

    // Log the authenticator details for debugging
    tracing::info!(
        "login_complete: found authenticator id={}, stored_cred_id_hex={} (len={})",
        authenticator.id,
        hex::encode(&authenticator.credential_id),
        authenticator.credential_id.len()
    );
    // Sanity check: credential_id should match (lookup was by credential_id)
    if authenticator.credential_id.as_slice() != req.credential_id.as_bytes() {
        tracing::error!(
            "CRITICAL: credential_id mismatch after lookup! req={} vs stored={}",
            hex::encode(req.credential_id.as_bytes()),
            hex::encode(&authenticator.credential_id)
        );
    }

    // Verify authenticator belongs to this user (from user_handle)
    if authenticator.user_id != user_id.to_string() {
        log_failure(
            &user_id.to_string(),
            Some(&authenticator.id),
            "user_mismatch",
        );
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "user_mismatch",
            "Credential does not belong to this user",
        ));
    }

    // Get user for email
    let user = db::get_user_by_id(&state.db, &user_id.to_string())
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| {
            log_failure(
                &user_id.to_string(),
                Some(&authenticator.id),
                "user_not_found",
            );
            json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    // Server-side WebAuthn signature verification
    // Build expected origin from RP ID
    let expected_origin = format!("https://{}", auth_state.rp_id);
    let expected_challenge = URL_SAFE_NO_PAD.encode(&auth_state.challenge);

    // Get stored counter from authenticator
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);

    // Debug logging for signature verification
    tracing::info!(
        "login_complete: stored_public_key_hex={}, sig_len={}, auth_data_len={}",
        hex::encode(&authenticator.public_key),
        req.signature.len(),
        req.authenticator_data.len()
    );
    tracing::info!(
        "login_complete: authenticator_data_hex={}",
        hex::encode(&req.authenticator_data)
    );
    tracing::info!(
        "login_complete: signature_hex={}",
        hex::encode(&req.signature)
    );
    tracing::info!(
        "login_complete: client_data_json={}",
        String::from_utf8_lossy(&req.client_data_json)
    );
    // Compute and log the client_data_hash for comparison
    let debug_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &req.client_data_json);
    tracing::info!(
        "login_complete: client_data_hash={}",
        hex::encode(debug_hash.as_ref())
    );

    // Verify the WebAuthn assertion server-side
    let verification_result = webauthn_verify::verify_assertion(
        &req.authenticator_data,
        &req.client_data_json,
        &req.signature,
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
            StatusCode::BAD_REQUEST,
            "signature_verification_failed",
            &e.to_string(),
        )
    })?;

    tracing::info!(
        "WebAuthn assertion verified for user {}: counter={}, uv={}",
        user.email,
        verification_result.counter,
        verification_result.user_verified
    );

    // Update counter in database (WebAuthn counter is u32, stored as i32)
    let new_counter = verification_result.counter as i32;
    db::update_authenticator_counter(&state.db, &authenticator.id, new_counter)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Generate session token
    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config.session_hours).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid session hours",
        )
    })?;
    let duration = Span::new().hours(session_hours);
    let expires = now.checked_add(duration).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Time overflow",
        )
    })?;

    let claims = SessionClaims {
        sub: user.id.clone(),
        email: user.email.clone(),
        authenticator_id: Some(authenticator.id.clone()),
        iat: now.as_second(),
        exp: expires.as_second(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_error",
            &e.to_string(),
        )
    })?;

    // Store session
    let token_hash = hash_token(&token);
    db::create_session(
        &state.db,
        &user.id,
        &token_hash,
        Some(&authenticator.id),
        &expires.to_string(),
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Log successful login event
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        client_ip: client_info.client_ip,
        user_agent: client_info.user_agent,
        client_hostname: client_ctx.and_then(|c| c.hostname.clone()),
        client_os: client_ctx.and_then(|c| c.os.clone()),
        client_arch: client_ctx.and_then(|c| c.arch.clone()),
        client_version: client_ctx.and_then(|c| c.cli_version.clone()),
        success: true,
        failure_reason: None,
    };
    if let Err(e) = db::insert_auth_event(&state.db, &auth_event_params).await {
        tracing::warn!("Failed to log auth event: {}", e);
    }

    tracing::info!("Login successful for user: {}", user.email);

    Ok(Json(LoginCompleteResponse {
        token,
        expires_at: expires.to_string(),
        email: user.email,
    }))
}

/// Get current session status.
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SessionStatus>, (StatusCode, Json<ApiError>)> {
    // Get Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let Some(token) = auth_header else {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    };

    // Validate token
    let claims = match decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return Ok(Json(SessionStatus {
                authenticated: false,
                email: None,
                expires_in_seconds: None,
                device_name: None,
            }));
        }
    };

    // Check session exists in database
    let token_hash = hash_token(token);
    let session = db::get_session_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if session.is_none() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    }

    // Get authenticator name (if session has an authenticator)
    let device_name = match &claims.authenticator_id {
        Some(auth_id) => db::get_authenticator_by_id(&state.db, auth_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.name),
        None => None,
    };

    // Calculate time remaining
    let now = Timestamp::now().as_second();
    let expires_in = if claims.exp > now {
        u64::try_from(claims.exp - now).ok()
    } else {
        None
    };

    Ok(Json(SessionStatus {
        authenticated: expires_in.is_some(),
        email: Some(claims.email),
        expires_in_seconds: expires_in,
        device_name,
    }))
}

/// Handle sign-out (clears session cookie).
/// POST /logout
pub async fn logout(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // Get session from vouch_session cookie and delete it from database
    if let Some(token) = jar.get("vouch_session").map(|c| c.value()) {
        let token_hash = hash_token(token);
        match db::delete_session_by_token_hash(&state.db, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    tracing::info!("Session deleted during logout");
                }
            }
            Err(e) => {
                tracing::warn!("Failed to delete session during logout: {}", e);
            }
        }
    }

    // Clear session cookie and redirect to landing page
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, clear_session_cookie().to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
