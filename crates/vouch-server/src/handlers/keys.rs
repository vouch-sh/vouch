// SPDX-License-Identifier: BUSL-1.1
//! Key management handlers for listing, renaming, and removing registered security keys.

use crate::AppState;
use crate::services::error::ServiceError;
use crate::services::keys as key_svc;
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::TypedHeader;
use axum_extra::extract::cookie::CookieJar;
use headers::authorization::{Authorization, Bearer};
use std::sync::Arc;
use vouch_common::{DeleteKeyResponse, ListKeysResponse, RenameKeyRequest, RenameKeyResponse};

use super::extract_session;

/// List all registered keys for the authenticated user.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, ServiceError> {
    let session = extract_session(&state, auth_header, &jar).await?;

    let keys = key_svc::list_keys_for_user(
        &state.db,
        &session.claims.sub,
        session.claims.authenticator_id.as_deref(),
    )
    .await?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a registered key.
pub async fn rename_key(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, ServiceError> {
    let session = extract_session(&state, auth_header, &jar).await?;

    let message = key_svc::rename_key(&state.db, &session.claims.sub, &key_id, &req.name).await?;

    Ok(Json(RenameKeyResponse { message }))
}

/// Delete a registered key.
pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, ServiceError> {
    let session = extract_session(&state, auth_header, &jar).await?;

    let (key_name, sessions_revoked) =
        key_svc::delete_key(&state.db, &session.claims.sub, &key_id).await?;

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", key_name),
        sessions_revoked,
    }))
}
