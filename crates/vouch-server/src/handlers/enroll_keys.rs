// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management handlers during enrollment (using cookie-based authentication).
//!
//! These endpoints allow users to manage their security keys via browser UI.
//! Authentication is via the session cookie containing an OAuth access token.

use crate::AppState;
use crate::services::error::ServiceError;
use crate::services::keys as key_svc;
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;
use vouch_common::{DeleteKeyResponse, ListKeysResponse, RenameKeyRequest, RenameKeyResponse};

use super::session::extract_session_from_cookie;

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys/api
/// Authentication is via session cookie.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, ServiceError> {
    let token = extract_session_from_cookie(&state, &jar).await?;

    let keys =
        key_svc::list_keys_for_user(&state.store, &token.sub, token.authenticator_id.as_deref())
            .await?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a security key (during enrollment).
/// PATCH /enroll/keys/{id}
/// Authentication is via session cookie.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, ServiceError> {
    let token = extract_session_from_cookie(&state, &jar).await?;

    let message = key_svc::rename_key(&state.store, &token.sub, &key_id, &req.name).await?;

    Ok(Json(RenameKeyResponse { message }))
}

/// Delete a security key (during enrollment).
/// DELETE /enroll/keys/{id}
/// Authentication is via session cookie.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, ServiceError> {
    let token = extract_session_from_cookie(&state, &jar).await?;

    // Require a recent authentication for destructive key operations.
    // Use auth_time (when FIDO2 occurred) if available, otherwise fall back to iat.
    let auth_timestamp = token.auth_time.unwrap_or(0);
    key_svc::require_fresh_timestamp(auth_timestamp, key_svc::KEY_DELETE_MAX_AGE_SECS)?;

    let (key_name, sessions_revoked) =
        key_svc::delete_key(&state.store, &token.sub, &key_id).await?;

    // Invalidate session cache — authenticator deletion cascades to sessions
    state.session_cache.invalidate_for_user(&token.sub);

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", key_name),
        sessions_revoked,
    }))
}
