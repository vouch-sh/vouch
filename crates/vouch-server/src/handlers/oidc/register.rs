// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7591/7592 — Dynamic Client Registration endpoint handlers.
//!
//! - `POST /oauth/register` — Creates a new OAuth client (RFC 7591).
//! - `GET /oauth/register/:client_id` — Reads client configuration (RFC 7592).
//!
//! POST supports two modes:
//! - **Authenticated registration**: With a valid Bearer token, the client is
//!   associated with the authenticated user.
//! - **Open registration** (RFC 7591 "open registration"): Without a Bearer token,
//!   the client is created without a user association. This is safe because a
//!   `client_id` alone grants zero access — the client must still authenticate
//!   with a valid FIDO2 key (hardware-bound) to obtain any token.

use crate::AppState;
use crate::services::oidc::registration::{
    RegistrationRequest, delete_client_configuration, read_client_configuration, register_client,
    update_client_configuration,
};
use axum::extract::OriginalUri;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
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
pub(crate) async fn register(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    // Try to extract user from Bearer token (optional for open registration).
    // We detect whether a token was even provided by checking the Authorization header.
    let has_auth = headers.contains_key(axum::http::header::AUTHORIZATION);

    let user_id = if has_auth {
        let jar = CookieJar::default();
        match crate::handlers::session::extract_resource_token(
            &state,
            &headers,
            &jar,
            method.as_str(),
            uri.path(),
            None,
        )
        .await
        {
            Ok(token) => Some(token.sub),
            Err(_) => {
                // If a Bearer token was provided but is invalid, reject it
                return crate::error::ServiceError::oauth(
                    crate::error::OAuthErrorCode::InvalidClient,
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
        [
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("pragma", "no-cache"),
            ("expires", "0"),
        ],
        Json(response),
    )
        .into_response()
}

/// GET /oauth/register/:client_id — RFC 7592 Client Configuration Endpoint.
///
/// Authenticates via Bearer token (the `registration_access_token` issued
/// during dynamic registration). Returns 200 with current client metadata
/// on success, 401 if the token is invalid, 404 if the client does not exist.
pub(crate) async fn read_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", "Bearer")],
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "Bearer token required"
                })),
            )
                .into_response();
        }
    };

    match read_client_configuration(&state, &client_id, token).await {
        Ok(response) => (
            StatusCode::OK,
            [
                ("cache-control", "no-cache, no-store, must-revalidate"),
                ("pragma", "no-cache"),
                ("expires", "0"),
            ],
            Json(response),
        )
            .into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// PUT /oauth/register/:client_id — RFC 7592 Client Configuration Update.
///
/// Authenticates via Bearer token (the `registration_access_token` issued
/// during dynamic registration or the previous PUT). Replaces the client's
/// mutable registration metadata.  Returns 200 with updated metadata
/// (including a new `registration_access_token`) on success.
pub(crate) async fn update_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", "Bearer")],
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "Bearer token required"
                })),
            )
                .into_response();
        }
    };

    match update_client_configuration(&state, &client_id, token, request).await {
        Ok(response) => (
            StatusCode::OK,
            [
                ("cache-control", "no-cache, no-store, must-revalidate"),
                ("pragma", "no-cache"),
                ("expires", "0"),
            ],
            Json(response),
        )
            .into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// DELETE /oauth/register/:client_id — RFC 7592 Client Configuration Delete.
///
/// Authenticates via Bearer token (the `registration_access_token` issued
/// during dynamic registration). Returns 204 No Content on success,
/// 401 if the token is invalid, 404 if the client does not exist.
pub(crate) async fn delete_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", "Bearer")],
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "Bearer token required"
                })),
            )
                .into_response();
        }
    };

    match delete_client_configuration(&state, &client_id, token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Extract a Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    // RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    // `BEARER`, `bearer`, and `BeArEr` must all match like `Bearer`.
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("valid header value"),
        );
        headers
    }

    /// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    /// `BEARER`, `bearer`, and `BeArEr` must all match like `Bearer` when
    /// extracting the RFC 7592 registration access token.
    #[test]
    fn extract_bearer_token_accepts_scheme_case_variants() {
        for scheme in ["Bearer", "BEARER", "bearer", "BeArEr"] {
            let headers = headers_with_auth(&format!("{scheme} reg-token"));
            assert_eq!(
                extract_bearer_token(&headers),
                Some("reg-token"),
                "{scheme} scheme must be accepted (RFC 9110 case-insensitivity)"
            );
        }
    }

    #[test]
    fn extract_bearer_token_rejects_unrecognized_scheme_or_missing_header() {
        assert_eq!(
            extract_bearer_token(&headers_with_auth("Basic dXNlcjpwYXNz")),
            None
        );
        assert_eq!(extract_bearer_token(&headers_with_auth("Bearer")), None);
        assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
    }
}
