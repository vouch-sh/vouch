// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers for listing, renaming, removing, and registering security keys.

use crate::AppState;
use crate::db::{self};
use crate::redact_email;
use crate::services::error::ServiceError;
use crate::services::keys as key_svc;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    DeleteKeyResponse, ListKeysResponse, Raw, RegisterCompleteRequest, RegisterCompleteResponse,
    RegisterStartRequest, RegisterStartResponse, RenameKeyRequest, RenameKeyResponse,
    fido2_types::Challenge,
};

use super::errors::json_error;
use super::session::extract_resource_token;
use super::{generate_challenge, validate_registration_attestation};
use crate::crypto::webauthn_verify;

// ============================================================================
// Registration State (stored temporarily between start and complete)
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
// Registration Handlers
// ============================================================================

/// Start registration - generate challenge and return to client
/// (WebAuthn Level 2 Section 7.1, Step 1-3).
///
/// Requires an OAuth access token (FAPI 2.0). Users must first enroll via OIDC
/// (`vouch enroll`) to register their first key. After that, they can add
/// additional keys via this endpoint after logging in with an existing key.
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, Json<vouch_common::ApiError>)> {
    let token = extract_resource_token(&state, &headers, &jar).await?;
    let user_id = Uuid::parse_str(&token.sub).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            &e.to_string(),
        )
    })?;

    // Verify user exists (should always exist if they have a valid session)
    let user = db::get_user_by_id(&state.db, &token.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "user_not_found", "User not found"))?;

    tracing::info!(
        "Registration start for authenticated user: {} (adding key: {})",
        redact_email(&user.email),
        req.name
    );

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
) -> Result<Json<RegisterCompleteResponse>, (StatusCode, Json<vouch_common::ApiError>)> {
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

// ============================================================================
// Key Management Handlers
// ============================================================================

/// List all registered keys for the authenticated user.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, ServiceError> {
    let token = extract_resource_token(&state, &headers, &jar).await?;

    let keys =
        key_svc::list_keys_for_user(&state.db, &token.sub, token.authenticator_id.as_deref())
            .await?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a registered key.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, ServiceError> {
    let token = extract_resource_token(&state, &headers, &jar).await?;

    let message = key_svc::rename_key(&state.db, &token.sub, &key_id, &req.name).await?;

    Ok(Json(RenameKeyResponse { message }))
}

/// Delete a registered key.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, ServiceError> {
    let token = extract_resource_token(&state, &headers, &jar).await?;
    // Use auth_time as the freshness anchor; default to epoch (always stale) if absent
    key_svc::require_fresh_timestamp(
        token.auth_time.unwrap_or(0),
        key_svc::KEY_DELETE_MAX_AGE_SECS,
    )?;

    let (key_name, sessions_revoked) = key_svc::delete_key(&state.db, &token.sub, &key_id).await?;

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", key_name),
        sessions_revoked,
    }))
}
