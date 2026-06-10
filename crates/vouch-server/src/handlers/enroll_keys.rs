// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management handlers during enrollment (using cookie-based authentication).
//!
//! These endpoints allow users to manage their security keys via browser UI.
//! Authentication is via the session cookie containing an OAuth access token.

use crate::AppState;
use crate::services::error::ServiceError;
use crate::services::keys as key_svc;
use axum::{
    Form, Json,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;
use vouch_common::{DeleteKeyResponse, ListKeysResponse};

use super::session::extract_session_from_cookie;

/// List all registered keys for the user (during enrollment).
/// GET /enroll/keys/api
/// Authentication is via session cookie.
pub(crate) async fn list_keys(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ListKeysResponse>, ServiceError> {
    let token = extract_session_from_cookie(&state, &jar).await?;

    let keys =
        key_svc::list_keys_for_user(&state.store, &token.sub, token.authenticator_id.as_deref())
            .await?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Form body for renaming a key from the browser UI.
#[derive(Debug, Deserialize)]
pub(crate) struct RenameKeyForm {
    /// New display name for the key.
    pub name: String,
}

/// Rename a security key (during enrollment) via a browser form POST.
/// POST /enroll/keys/{id}/rename
///
/// Server-rendered, redirect-back CRUD (matches the admin pages): on success
/// or failure the browser is redirected to `/enroll/keys`, which re-renders
/// the list — surfacing any error via a flash message rather than returning a
/// raw JSON error body. Authentication is via session cookie.
pub(crate) async fn rename_key_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(key_id): Path<String>,
    Form(form): Form<RenameKeyForm>,
) -> Response {
    let token = match extract_session_from_cookie(&state, &jar).await {
        Ok(token) => token,
        Err(_) => return Redirect::to("/enroll/start").into_response(),
    };

    match key_svc::rename_key(&state.store, &token.sub, &key_id, &form.name).await {
        Ok(_) => Redirect::to("/enroll/keys").into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "rename_key_form: rename failed");
            // A generic, user-safe message: the common failures (empty / too
            // long) are also constrained by the form, and we must not surface
            // internal error detail.
            let jar = crate::handlers::admin::flash::set_err(
                jar,
                "Could not rename key. Please choose a name between 1 and 100 characters.",
            );
            (jar, Redirect::to("/enroll/keys")).into_response()
        }
    }
}

/// Delete a security key (during enrollment).
/// DELETE /enroll/keys/{id}
/// Authentication is via session cookie.
pub(crate) async fn delete_key(
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
