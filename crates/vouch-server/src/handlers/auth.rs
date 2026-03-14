// SPDX-License-Identifier: BUSL-1.1
//! Authentication handlers for session management.

use crate::AppState;
use crate::db;
use crate::services::error::ServiceError;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use std::sync::Arc;
use vouch_common::SessionStatus;

use super::extractors::ClientInfo;
use super::{clear_session_cookie, hash_token};

/// Get current session status.
///
/// Accepts an OAuth access token (Bearer or DPoP scheme) and returns
/// authenticated status, email, expiration, and device name.
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SessionStatus>, ServiceError> {
    // Get Authorization header (Bearer or DPoP)
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h.strip_prefix("Bearer ").unwrap_or(""),
        Some(h) if h.starts_with("DPoP ") => h.strip_prefix("DPoP ").unwrap_or(""),
        _ => {
            return Ok(Json(SessionStatus {
                authenticated: false,
                email: None,
                expires_in_seconds: None,
                device_name: None,
            }));
        }
    };

    if token.is_empty() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    }

    // Validate as OAuth access token (ES256, at+jwt)
    let config = state.config();
    let decoded =
        match crate::services::auth::decode_token(token, &state.oidc_key, &config.base_url) {
            Some(d) => d,
            None => {
                return Ok(Json(SessionStatus {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    device_name: None,
                }));
            }
        };

    let crate::services::auth::DecodedToken::AccessToken(access_claims) = decoded;

    // Check session exists in database
    let token_hash = hash_token(token);
    let session = db::get_session_by_token_hash(&state.store, &token_hash)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;

    if session.is_none() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    }

    // Get authenticator name from server-side session record
    let device_name = match session.and_then(|s| s.authenticator_id) {
        Some(auth_id) => db::get_authenticator_by_id(&state.store, &auth_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.name),
        None => None,
    };

    // Calculate time remaining
    let now = Timestamp::now().as_second();
    let expires_in = if access_claims.exp > now {
        u64::try_from(access_claims.exp - now).ok()
    } else {
        None
    };

    Ok(Json(SessionStatus {
        authenticated: expires_in.is_some(),
        email: access_claims.email,
        expires_in_seconds: expires_in,
        device_name,
    }))
}

/// Handle sign-out (clears session cookie).
/// POST /logout
pub async fn logout(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    jar: CookieJar,
) -> Response {
    // Get session from cookie and delete it from database
    if let Some(token) = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value())
    {
        let token_hash = hash_token(token);

        // Look up session before deletion to capture user info for audit
        let session_info = db::get_session_by_token_hash(&state.store, &token_hash)
            .await
            .ok()
            .flatten();

        match db::delete_session_by_token_hash(&state.store, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    tracing::info!("Session deleted during logout");

                    // Fire-and-forget logout audit event
                    if let Some(session) = session_info {
                        let audit = state.audit.clone();
                        let user_email = session.user_email.clone();
                        let params = db::AuthEventParams {
                            user_id: session.user_id.clone(),
                            event_type: db::AuthEventType::Logout,
                            success: true,
                            ..Default::default()
                        }
                        .with_client_info(client_info);
                        tokio::spawn(async move {
                            if let Err(e) =
                                db::insert_auth_event(&audit, &params, Some(&user_email)).await
                            {
                                tracing::warn!("Failed to log logout event: {}", e,);
                            }
                        });
                    }
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
