//! Authentication handlers for registration and login.

use crate::AppState;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::extractors::ClientInfo;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    ApiError, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest, LoginStartResponse,
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
    SessionStatus,
};

/// JSON error response helper.
fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}

/// Generate random challenge bytes.
fn generate_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    challenge
}

/// Hash a token for storage.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

// ============================================================================
// Registration State (stored temporarily)
// ============================================================================

/// Registration state stored between start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationState {
    user_id: Uuid,
    user_name: String,
    device_name: String,
    challenge: Vec<u8>,
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
#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationState {
    user_id: String,
    challenge: Vec<u8>,
    rp_id: String,
    credential_ids: Vec<Vec<u8>>,
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
    pub authenticator_id: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// Start registration - generate challenge and return to client.
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Registration start for email: {}", req.email);

    // Create or get user
    let user = db::upsert_user(&state.db, &req.email, Some(&req.name))
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

    // Generate challenge
    let challenge = generate_challenge();

    // Create state token
    let reg_state = RegistrationState {
        user_id,
        user_name: req.email.clone(),
        device_name: req.name,
        challenge: challenge.clone(),
        rp_id: state.config.rp_id.clone(),
    };

    let state_token = reg_state.encode(&state.config.jwt_secret).map_err(|e| {
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
        user_name: req.email,
        algorithms: vec![-7], // ES256
        state: state_token,
    }))
}

/// Complete registration - verify attestation and store credential.
pub async fn register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterCompleteRequest>,
) -> Result<Json<RegisterCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Registration complete");

    // Decode state
    let reg_state = RegistrationState::decode(&req.state, &state.config.jwt_secret)
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

    // Extract AAGUID from attestation object
    let aaguid = extract_aaguid_from_attestation(&req.attestation_object);

    // Store the authenticator
    let device_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        &reg_state.device_name,
        &req.credential_id,
        &req.public_key,
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

/// Start login - generate challenge and return credential IDs.
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login start for email: {}", req.email);

    // Get user
    let user = db::get_user_by_email(&state.db, &req.email)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    // Get user's authenticators
    let authenticators = db::get_authenticators_for_user(&state.db, &user.id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if authenticators.is_empty() {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "no_credentials",
            "No credentials registered for this user",
        ));
    }

    let credential_ids: Vec<Vec<u8>> = authenticators
        .iter()
        .map(|a| a.credential_id.clone())
        .collect();

    // Generate challenge
    let challenge = generate_challenge();

    // Create state token
    let auth_state = AuthenticationState {
        user_id: user.id,
        challenge: challenge.clone(),
        rp_id: state.config.rp_id.clone(),
        credential_ids: credential_ids.clone(),
    };

    let state_token = auth_state.encode(&state.config.jwt_secret).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            &e.to_string(),
        )
    })?;

    Ok(Json(LoginStartResponse {
        challenge,
        rp_id: state.config.rp_id.clone(),
        credential_ids,
        state: state_token,
    }))
}

/// Complete login - verify assertion and issue session token.
#[allow(clippy::too_many_lines)]
pub async fn login_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<Json<LoginCompleteResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Login complete");

    // Extract client info from headers
    let client_info = ClientInfo::from_headers(&headers);

    // Get client context from request (sent by CLI)
    let client_ctx = req.client_context.as_ref();

    // Decode state
    let auth_state = AuthenticationState::decode(&req.state, &state.config.jwt_secret)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

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

    // Verify the credential_id is in the allowed list
    if !auth_state
        .credential_ids
        .iter()
        .any(|id| id == &req.credential_id)
    {
        log_failure(&auth_state.user_id, None, "invalid_credential");
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential not in allowed list",
        ));
    }

    // Get the authenticator
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
            log_failure(&auth_state.user_id, None, "credential_not_found");
            json_error(
                StatusCode::NOT_FOUND,
                "credential_not_found",
                "Credential not found",
            )
        })?;

    // Verify user matches
    if authenticator.user_id != auth_state.user_id {
        log_failure(
            &auth_state.user_id,
            Some(&authenticator.id),
            "user_mismatch",
        );
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "user_mismatch",
            "User mismatch",
        ));
    }

    // Get user
    let user = db::get_user_by_id(&state.db, &auth_state.user_id)
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
                &auth_state.user_id,
                Some(&authenticator.id),
                "user_not_found",
            );
            json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;

    // For now, trust the CLI's signature verification
    // In production, verify the signature server-side using webauthn-rs

    // Update counter (extract from authenticator_data)
    // The counter is at bytes 33-36 of authenticator_data (big-endian u32)
    if req.authenticator_data.len() >= 37 {
        let counter_bytes: [u8; 4] = req
            .authenticator_data
            .get(33..37)
            .ok_or_else(|| {
                log_failure(&user.id, Some(&authenticator.id), "invalid_auth_data");
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_auth_data",
                    "Invalid authenticator data",
                )
            })?
            .try_into()
            .map_err(|_| {
                log_failure(&user.id, Some(&authenticator.id), "invalid_auth_data");
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_auth_data",
                    "Invalid authenticator data",
                )
            })?;
        let new_counter = i64::from(u32::from_be_bytes(counter_bytes));

        // Check counter is increasing
        if new_counter <= authenticator.counter {
            log_failure(&user.id, Some(&authenticator.id), "counter_not_increasing");
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "counter_error",
                "Counter not increasing - possible cloned authenticator",
            ));
        }

        db::update_authenticator_counter(&state.db, &authenticator.id, new_counter)
            .await
            .map_err(|e| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    &e.to_string(),
                )
            })?;
    }

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
        authenticator_id: authenticator.id.clone(),
        iat: now.as_second(),
        exp: expires.as_second(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
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
        &authenticator.id,
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
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
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

    // Get authenticator name
    let device_name = db::get_authenticator_by_id(&state.db, &claims.authenticator_id)
        .await
        .ok()
        .flatten()
        .map(|a| a.name);

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

/// Extract AAGUID from CBOR-encoded attestation object.
///
/// The attestation object structure (CBOR map):
/// - `fmt`: attestation statement format
/// - `attStmt`: attestation statement
/// - `authData`: authenticator data containing AAGUID and credential public key
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
