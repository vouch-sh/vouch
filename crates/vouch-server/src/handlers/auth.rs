// SPDX-License-Identifier: BUSL-1.1
//! Authentication handlers for registration and login.
//!
//! Implements:
//! - WebAuthn Level 2 Section 7.1 — Registering a New Credential
//! - WebAuthn Level 2 Section 7.2 — Verifying an Authentication Assertion

use super::extractors::ClientInfo;
use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::services::auth::{
    AuthenticatorLookupParams, CreateSessionParams, LoginAssertionParams, create_login_session,
    lookup_and_verify_authenticator, verify_login_assertion,
};
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use jiff::Timestamp;
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
use crate::crypto::webauthn_verify;
use crate::redact_email;
use base64::Engine;

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
    /// RFC 8725 §3.11: Issued at time for expiration enforcement.
    iat: i64,
    /// RFC 8725 §3.11: Expiration time (5 minutes).
    exp: i64,
}

impl RegistrationState {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::encode_state_token(
            self,
            crate::crypto::jwt::JwtType::RegistrationState,
            secret.as_bytes(),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::decode_state_token(
            token,
            crate::crypto::jwt::JwtType::RegistrationState,
            secret.as_bytes(),
        )
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
    /// RFC 8725 §3.11: Issued at time for expiration enforcement.
    iat: i64,
    /// RFC 8725 §3.11: Expiration time (5 minutes).
    exp: i64,
}

impl AuthenticationState {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::encode_state_token(
            self,
            crate::crypto::jwt::JwtType::AuthenticationState,
            secret.as_bytes(),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        crate::crypto::jwt::decode_state_token(
            token,
            crate::crypto::jwt::JwtType::AuthenticationState,
            secret.as_bytes(),
        )
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Start registration - generate challenge and return to client
/// (WebAuthn Level 2 Section 7.1, Step 1-3).
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
        redact_email(user_email),
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
    let challenge = generate_challenge().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate challenge",
        )
    })?;

    // Create state token
    let challenge: Challenge<Raw> = challenge.into();
    let now = Timestamp::now();
    let exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 300);
    let reg_state = RegistrationState {
        user_id,
        user_name: user.email.clone(),
        device_name: req.name,
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        iat: now.as_second(),
        exp,
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

    Ok(Json(RegisterStartResponse {
        challenge,
        rp_id: state.config().rp_id.clone(),
        rp_name: state.config().rp_name.clone(),
        user_id,
        user_name: user.email,
        algorithms: vec![-7], // ES256
        state: state_token,
        exclude_credential_ids,
    }))
}

/// Complete registration - verify attestation and store credential
/// (WebAuthn Level 2 Section 7.1, Step 4-22).
pub async fn register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterCompleteRequest>,
) -> Result<Json<RegisterCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Registration complete");

    // Decode state
    let reg_state =
        RegistrationState::decode(&req.state, state.config().jwt_secret.expose_secret())
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Server-side WebAuthn attestation verification
    // Verify the attestation object, client data, RP ID, challenge, and origin
    let config = state.config();
    let challenge_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reg_state.challenge.as_bytes());
    let verified = webauthn_verify::verify_registration(
        req.attestation_object.as_bytes(),
        req.client_data_json.as_bytes(),
        &reg_state.rp_id,
        &challenge_b64,
        &config.base_url,
        true, // require user verification
    )
    .map_err(|e| {
        tracing::warn!("Registration attestation verification failed: {e}");
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_attestation",
            &e.to_string(),
        )
    })?;

    // Use server-verified credential_id from authData (not from request body)
    let verified_cred_id: vouch_common::fido2_types::CredentialId<Raw> =
        verified.credential_id.into();

    // Check for duplicate credential registration
    if let Some(_existing) = db::get_authenticator_by_credential_id(&state.db, &verified_cred_id)
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

    // Use server-verified AAGUID if available, fall back to client-provided
    let aaguid = verified.aaguid.or(validated.aaguid);

    // Use server-verified public key from authData
    let verified_public_key: vouch_common::fido2_types::CoseKey<Raw> =
        verified.public_key_cose.into();

    // Store the authenticator
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let device_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        &reg_state.device_name,
        &verified_cred_id,
        &verified_public_key,
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

/// Start login - generate challenge for discoverable credential authentication
/// (WebAuthn Level 2 Section 7.2, Step 1-3).
///
/// No email lookup needed — the YubiKey identifies the user via user_handle
/// (discoverable credential / resident key flow).
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login start (discoverable credential flow)");

    // Generate challenge
    let challenge = generate_challenge().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate challenge",
        )
    })?;

    // Create state token (simplified - no user info needed upfront)
    let challenge: Challenge<Raw> = challenge.into();
    let now = Timestamp::now();
    let exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 300);
    let auth_state = AuthenticationState {
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        iat: now.as_second(),
        exp,
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

    Ok(Json(LoginStartResponse {
        challenge,
        rp_id: state.config().rp_id.clone(),
        state: state_token,
    }))
}

/// Complete login - verify assertion and issue session token
/// (WebAuthn Level 2 Section 7.2, Step 4-21).
///
/// Uses discoverable credential flow: `credential_id` and `user_handle`
/// identify the user without a prior email lookup.
pub async fn login_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<Json<LoginCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login complete (discoverable credential flow)");

    // Extract client info from headers
    let client_info = ClientInfo::from_headers(&headers);
    let client_ctx = req.client_context.as_ref();

    // Decode state (only contains challenge and rp_id)
    let auth_state =
        AuthenticationState::decode(&req.state, state.config().jwt_secret.expose_secret())
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Parse user_handle as UUID to identify the user
    let user_id = Uuid::from_slice(&req.user_handle).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_user_handle",
            "Invalid user handle format",
        )
    })?;

    // Helper to log failed login attempts (captures client context)
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
        let db = state.db.clone();
        tokio::spawn(async move {
            if let Err(e) = db::insert_auth_event(&db, &params).await {
                tracing::warn!("Failed to log auth event: {}", e);
            }
        });
    };

    // Look up authenticator and verify ownership
    let lookup_result = lookup_and_verify_authenticator(
        &state,
        AuthenticatorLookupParams {
            credential_id: &req.credential_id,
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
        service_error_to_handler_error(e)
    })?;

    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // Verify WebAuthn assertion
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);
    let assertion_result = verify_login_assertion(LoginAssertionParams {
        authenticator_data: &req.authenticator_data,
        client_data_json: &req.client_data_json,
        signature: &req.signature,
        public_key: &authenticator.public_key,
        rp_id: &auth_state.rp_id,
        challenge: &auth_state.challenge,
        stored_counter,
    })
    .map_err(|e| {
        log_failure(
            &user.id,
            Some(&authenticator.id),
            "signature_verification_failed",
        );
        service_error_to_handler_error(e)
    })?;

    tracing::info!(
        "WebAuthn assertion verified for user {}: counter={}, uv={}",
        redact_email(&user.email),
        assertion_result.new_counter,
        assertion_result.user_verified
    );

    // Update counter in database
    db::update_authenticator_counter(
        &state.db,
        &authenticator.id,
        assertion_result.new_counter as i32,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Create session
    let session_result = create_login_session(
        &state,
        CreateSessionParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            purpose: crate::db::SessionPurpose::Fido2Session,
            scope: None,
        },
    )
    .await
    .map_err(service_error_to_handler_error)?;

    // Log successful login event (fire-and-forget, consistent with failure path)
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
    let db = state.db.clone();
    tokio::spawn(async move {
        if let Err(e) = db::insert_auth_event(&db, &auth_event_params).await {
            tracing::warn!("Failed to log auth event: {}", e);
        }
    });

    tracing::info!("Login successful for user: {}", redact_email(&user.email));

    Ok(Json(LoginCompleteResponse {
        token: session_result.token,
        expires_at: session_result.expires_at,
        email: user.email,
    }))
}

/// Convert a ServiceError to a handler error response.
fn service_error_to_handler_error(
    e: crate::services::ServiceError,
) -> (StatusCode, Json<ApiError>) {
    use crate::services::ServiceError;

    match e {
        ServiceError::NotFound(entity) => json_error(
            StatusCode::NOT_FOUND,
            &format!("{entity}_not_found"),
            &format!("{entity} not found"),
        ),
        ServiceError::Forbidden(msg) => json_error(StatusCode::FORBIDDEN, "forbidden", msg),
        ServiceError::Validation(msg) => {
            json_error(StatusCode::BAD_REQUEST, "invalid_request", &msg)
        }
        ServiceError::OAuth { code, description } => {
            json_error(code.status_code(), code.as_str(), &description)
        }
        ServiceError::Internal(msg) => {
            tracing::error!("Internal error: {}", msg);
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal server error",
            )
        }
        _ => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Internal server error",
        ),
    }
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

    // Validate token with iss/aud/typ checks (RFC 8725)
    let config = state.config();
    let claims = match super::decode_session_jwt(token, config.jwt_secret_bytes(), &config.base_url)
    {
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
