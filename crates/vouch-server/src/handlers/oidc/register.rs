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
use crate::error::OAuthErrorCode;
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
            // RFC 7592 §2 / RFC 6750 §3.1: `extract_resource_token` returns
            // `ServiceError::Api` with code `invalid_token` for any bearer-token
            // validation failure. Propagate that error so the response carries
            // `invalid_token` (not `invalid_client`), the correct 401 status,
            // and a `WWW-Authenticate` challenge.
            Err(e) => return into_registration_response(e),
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
        None => return missing_token_response(),
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
        Err(e) => into_registration_response(e),
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
        None => return missing_token_response(),
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
        Err(e) => into_registration_response(e),
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
        None => return missing_token_response(),
    };

    match delete_client_configuration(&state, &client_id, token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => into_registration_response(e),
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

/// Build the RFC 6750 Section 3.1 `WWW-Authenticate` challenge returned when a
/// bearer token is missing from (or invalid for) an RFC 7592 registration
/// endpoint. The `error` and `error_description` parameters mirror the JSON
/// body so OAuth client libraries can rely on either source.
fn bearer_challenge(error: &str, description: &str) -> String {
    format!("Bearer error=\"{error}\", error_description=\"{description}\"")
}

/// Build a 401 response for a missing bearer token on an RFC 7592 endpoint.
///
/// Per RFC 7592 Sections 2.1–2.3 (cross-referencing RFC 6750), a missing
/// access token on a protected registration endpoint MUST be reported with
/// `error="invalid_token"` and a `WWW-Authenticate` header carrying the
/// `error` / `error_description` parameters.
fn missing_token_response() -> Response {
    let description = "Bearer token required";
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            bearer_challenge(OAuthErrorCode::InvalidToken.as_str(), description),
        )],
        Json(serde_json::json!({
            "error": OAuthErrorCode::InvalidToken.as_str(),
            "error_description": description
        })),
    )
        .into_response()
}

/// Convert a `ServiceError` into an RFC 6750-compliant response for an RFC 7592
/// registration endpoint.
///
/// This wraps [`ServiceError::into_oauth_response`] and, for 401 responses,
/// appends a `WWW-Authenticate: Bearer error="invalid_token", ...` header as
/// required by RFC 6750 Section 3.1 for protected resources.
fn into_registration_response(err: crate::error::ServiceError) -> Response {
    let (status, json) = err.into_oauth_response();
    if status == StatusCode::UNAUTHORIZED {
        let description = json
            .error_description
            .clone()
            .unwrap_or_else(|| "Invalid or expired token".to_string());
        let www_auth = bearer_challenge(json.error.as_str(), description.as_str());
        (
            status,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_str(&www_auth)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer")),
            )],
            json,
        )
            .into_response()
    } else {
        (status, json).into_response()
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
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

    /// RFC 7592 §2.1–2.3 / RFC 6750 §3.1: a missing bearer token on a
    /// registration endpoint MUST produce a 401 with `error="invalid_token"`
    /// and a `WWW-Authenticate` header carrying the same error.
    #[tokio::test]
    async fn missing_token_response_is_rfc6750_compliant() {
        use axum::body::to_bytes;

        let response = missing_token_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            www_auth.contains("error=\"invalid_token\""),
            "WWW-Authenticate must contain error=\"invalid_token\": {www_auth}"
        );

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_token");
        assert_eq!(json["error_description"], "Bearer token required");
    }

    /// RFC 6750 §3.1: `into_registration_response` must add a
    /// `WWW-Authenticate` header (with `error="invalid_token"`) to any 401
    /// `ServiceError`, while preserving non-401 errors unchanged.
    #[tokio::test]
    async fn into_registration_response_adds_www_authenticate_on_401() {
        use axum::body::to_bytes;

        // 401 path: ServiceError::Unauthorized now renders as invalid_token.
        let err = crate::error::ServiceError::Unauthorized("Invalid registration access token");
        let response = into_registration_response(err);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            www_auth.contains("error=\"invalid_token\""),
            "401 must carry WWW-Authenticate with error=\"invalid_token\": {www_auth}"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_token");
    }

    /// Non-401 errors (e.g. RFC 7591 metadata validation → 400) must pass
    /// through `into_registration_response` without a `WWW-Authenticate` header.
    #[tokio::test]
    async fn into_registration_response_passes_through_non_401() {
        use axum::body::to_bytes;

        let err = crate::error::ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "jwks and jwks_uri are mutually exclusive",
        );
        let response = into_registration_response(err);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response.headers().get("www-authenticate").is_none(),
            "Non-401 errors must not carry a WWW-Authenticate header"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client_metadata");
    }
}
