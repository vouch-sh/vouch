// SPDX-License-Identifier: BUSL-1.1
//! RFC 7591 — Dynamic Client Registration endpoint handler.
//!
//! `POST /oauth/register` — Creates a new OAuth client from metadata.

use crate::AppState;
use crate::services::oidc::registration::{RegistrationRequest, register_client};
use crate::services::{OAuthErrorCode, ServiceError};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use headers::authorization::{Authorization, Bearer};
use std::sync::Arc;

use crate::handlers::extract_session;

/// POST /oauth/register — RFC 7591 Dynamic Client Registration.
///
/// Requires a valid Bearer token (Vouch session JWT). The authenticated user
/// becomes the owner of the newly registered client.
///
/// Returns 201 Created with the client information response.
pub async fn register(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    // Validate Bearer token — extract user_id from session JWT
    let session = match extract_session(
        &state,
        auth_header,
        &axum_extra::extract::cookie::CookieJar::default(),
    )
    .await
    {
        Ok(s) => s,
        Err(_) => {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Valid Bearer token required for client registration",
            )
            .into_oauth_response()
            .into_response();
        }
    };

    let user_id = &session.claims.sub;

    // Delegate to service layer
    let response = match register_client(&state, request, user_id).await {
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
