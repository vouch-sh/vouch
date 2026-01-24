//! Key management handlers for listing and removing registered security keys.

use crate::AppState;
use crate::db;
use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, Validation, decode};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use vouch_common::{ApiError, DeleteKeyResponse, KeyInfo, ListKeysResponse, lookup_device_model};

use super::auth::SessionClaims;

/// JSON error response helper.
fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}

/// Hash a token for storage/lookup.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Extract and validate session from Authorization header.
/// Returns the session claims and the token hash.
async fn extract_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(SessionClaims, String), (StatusCode, Json<ApiError>)> {
    // Get Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = auth_header.ok_or_else(|| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing or invalid Authorization header",
        )
    })?;

    // Validate JWT
    let claims = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Invalid or expired token",
        )
    })?
    .claims;

    // Verify session exists in database
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
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Session not found",
        ));
    }

    Ok((claims, token_hash))
}

/// List all registered keys for the authenticated user.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ListKeysResponse>, (StatusCode, Json<ApiError>)> {
    let (claims, _token_hash) = extract_session(&state, &headers).await?;

    // Get all authenticators for this user
    let authenticators = db::get_authenticators_for_user(&state.db, &claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Convert to KeyInfo
    let keys: Vec<KeyInfo> = authenticators
        .into_iter()
        .map(|a| {
            let device_model = a
                .aaguid
                .as_deref()
                .and_then(lookup_device_model)
                .map(String::from);
            KeyInfo {
                id: a.id.clone(),
                name: a.name,
                created_at: a.created_at,
                is_current_session: a.id == claims.authenticator_id,
                device_model,
                aaguid: a.aaguid,
            }
        })
        .collect();

    Ok(Json(ListKeysResponse { keys }))
}

/// Delete a registered key.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<ApiError>)> {
    let (claims, _token_hash) = extract_session(&state, &headers).await?;

    // Get the authenticator to verify ownership
    let authenticator = db::get_authenticator_by_id(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "not_found", "Key not found"))?;

    // Verify the key belongs to the authenticated user
    if authenticator.user_id != claims.sub {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Key does not belong to this user",
        ));
    }

    // Check that this isn't the user's last key
    let key_count = db::count_authenticators_for_user(&state.db, &claims.sub)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    if key_count <= 1 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "last_key",
            "Cannot delete your last key. Register another key first.",
        ));
    }

    // Count sessions that will be revoked
    let sessions_revoked = db::count_sessions_for_authenticator(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    // Delete the authenticator (CASCADE will delete sessions)
    db::delete_authenticator(&state.db, &key_id)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                &e.to_string(),
            )
        })?;

    tracing::info!(
        "Deleted key {} for user {}, revoked {} sessions",
        key_id,
        claims.sub,
        sessions_revoked
    );

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", authenticator.name),
        sessions_revoked: u64::try_from(sessions_revoked).unwrap_or(0),
    }))
}
