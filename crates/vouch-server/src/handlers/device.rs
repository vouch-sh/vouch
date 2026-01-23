//! Device Authorization Grant handlers (RFC 8628).

use crate::AppState;
use crate::db;
use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vouch_common::{
    ApiError, DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, DeviceTokenResponse,
    OAuthError,
};

/// Characters used for user code generation (no ambiguous characters).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// JSON error response helper.
fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}

/// OAuth error response helper.
fn oauth_error(status: StatusCode, error: OAuthError) -> (StatusCode, Json<OAuthError>) {
    (status, Json(error))
}

/// Generate a random device code (32 bytes, base64url encoded).
fn generate_device_code() -> String {
    let mut bytes = vec![0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate a user-friendly code in XXXX-XXXX format.
fn generate_user_code() -> String {
    let mut bytes = vec![0u8; 8];
    rand::rng().fill_bytes(&mut bytes);

    let chars: Vec<char> = bytes
        .iter()
        .map(|b| {
            let idx = (*b as usize) % USER_CODE_ALPHABET.len();
            USER_CODE_ALPHABET.get(idx).copied().unwrap_or(b'X') as char
        })
        .collect();

    format!(
        "{}-{}",
        chars.iter().take(4).collect::<String>(),
        chars.iter().skip(4).collect::<String>()
    )
}

/// Hash a device code for storage.
fn hash_device_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Start device authorization flow.
/// POST /oauth/device/code
#[allow(clippy::unused_async)]
pub async fn device_code(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Device authorization request");

    // Generate codes
    let device_code = generate_device_code();
    let user_code = generate_user_code();
    let device_code_hash = hash_device_code(&device_code);

    // Calculate expiration
    let now = Timestamp::now();
    let expires_seconds = i64::try_from(state.config.device_code_expires_seconds).unwrap_or(600);
    let duration = Span::new().seconds(expires_seconds);
    let expires_at = now.checked_add(duration).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Time overflow",
        )
    })?;

    let interval_seconds = i64::try_from(state.config.device_poll_interval_seconds).unwrap_or(5);

    // Store in database
    db::create_device_auth_request(
        &state.db,
        &device_code_hash,
        &user_code,
        &expires_at.to_string(),
        interval_seconds,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Build verification URL
    let verification_uri = format!("{}/device", state.config.verification_base_url);

    tracing::info!("Created device auth request, user_code: {}", user_code);

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        expires_in: state.config.device_code_expires_seconds,
        interval: state.config.device_poll_interval_seconds,
    }))
}

/// Poll for device token.
/// POST /oauth/token
#[allow(clippy::unused_async)]
pub async fn device_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeviceTokenRequest>,
) -> Result<Json<DeviceTokenResponse>, (StatusCode, Json<OAuthError>)> {
    // Validate grant type
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError {
                error: "unsupported_grant_type".to_string(),
                error_description: Some("Expected device_code grant type".to_string()),
            },
        ));
    }

    // Hash the device code and look it up
    let device_code_hash = hash_device_code(&req.device_code);
    let request = db::get_device_auth_by_code_hash(&state.db, &device_code_hash)
        .await
        .map_err(|_| {
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::invalid_grant(),
            )
        })?
        .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, OAuthError::invalid_grant()))?;

    // Check if expired
    let now = Timestamp::now();
    let expires_at: Timestamp = request.expires_at.parse().map_err(|_| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthError::invalid_grant(),
        )
    })?;

    if now > expires_at {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::expired_token(),
        ));
    }

    // Check polling rate
    let allowed =
        db::update_device_auth_poll_time(&state.db, &request.id, request.interval_seconds)
            .await
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

    if !allowed {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::slow_down(),
        ));
    }

    // Check status
    match request.status.as_str() {
        "pending" => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::authorization_pending(),
        )),
        "denied" => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::access_denied(),
        )),
        "authorized" => {
            // Get user info and create session token
            let user_id = request.user_id.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;
            let user_email = request.user_email.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;
            let authenticator_id = request.authenticator_id.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Generate session token (reuse the auth module's session creation logic)
            let session_hours = i64::try_from(state.config.session_hours).unwrap_or(8);
            let duration = Span::new().hours(session_hours);
            let session_expires = now.checked_add(duration).map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Create JWT claims
            let claims = crate::handlers::auth::SessionClaims {
                sub: user_id.clone(),
                email: user_email.clone(),
                authenticator_id: authenticator_id.clone(),
                iat: now.as_second(),
                exp: session_expires.as_second(),
            };

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            )
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Store session in database
            let token_hash = {
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                URL_SAFE_NO_PAD.encode(hasher.finalize())
            };

            db::create_session(
                &state.db,
                &user_id,
                &token_hash,
                &authenticator_id,
                &session_expires.to_string(),
            )
            .await
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            let expires_in = u64::try_from(session_expires.as_second() - now.as_second())
                .unwrap_or(state.config.session_hours * 3600);

            tracing::info!("Device authorization complete for: {}", user_email);

            Ok(Json(DeviceTokenResponse {
                access_token: token,
                token_type: "Bearer".to_string(),
                expires_in,
                email: user_email,
            }))
        }
        _ => Err(oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthError::invalid_grant(),
        )),
    }
}
