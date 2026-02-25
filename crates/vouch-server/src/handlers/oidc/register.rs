// SPDX-License-Identifier: BUSL-1.1
//! RFC 7591 — Dynamic Client Registration endpoint handler.
//!
//! `POST /oauth/register` — Creates a new OAuth client from metadata.
//!
//! Supports two modes:
//! - **Authenticated registration**: With a valid Bearer token, the client is
//!   associated with the authenticated user.
//! - **Open registration** (RFC 7591 "open registration"): Without a Bearer token,
//!   the client is created without a user association. This is safe because a
//!   `client_id` alone grants zero access — the client must still authenticate
//!   with a valid FIDO2 key (hardware-bound) to obtain any token.

use crate::AppState;
use crate::services::oidc::registration::{RegistrationRequest, register_client};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// POST /oauth/register — RFC 7591 Dynamic Client Registration.
///
/// Accepts an optional Bearer token. When present, the authenticated user
/// becomes the owner of the newly registered client. When absent (open
/// registration), the client is created without user association.
///
/// Returns 201 Created with the client information response.
pub async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    // Try to extract user from Bearer token (optional for open registration).
    // We detect whether a token was even provided by checking the Authorization header.
    let has_auth = headers.contains_key(axum::http::header::AUTHORIZATION);

    let user_id = if has_auth {
        let jar = CookieJar::default();
        match crate::handlers::session::extract_resource_token(&state, &headers, &jar).await {
            Ok(token) => Some(token.sub),
            Err(_) => {
                // If a Bearer token was provided but is invalid, reject it
                return crate::services::ServiceError::oauth(
                    crate::services::OAuthErrorCode::InvalidClient,
                    "Invalid Bearer token",
                )
                .into_oauth_response()
                .into_response();
            }
        }
    } else {
        None // Open registration — no user association
    };

    // Delegate to service layer
    let response = match register_client(&state, request, user_id.as_deref()).await {
        Ok(r) => r,
        Err(e) => return e.into_oauth_response().into_response(),
    };

    // RFC 7591 Section 3.2.1: Respond with 201 Created
    // Cache-Control: no-store, Pragma: no-cache (per RFC 7591 Section 3.2.1)
    (
        StatusCode::CREATED,
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(response),
    )
        .into_response()
}
