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

use crate::db::ClientInfo;
use crate::error::ServiceError;
use crate::handlers::session::{AuthenticatedToken, OptionalAuthenticatedToken};
use crate::services::oidc::registration::{
    RegistrationRequest, delete_client_configuration, read_client_configuration, register_client,
    update_client_configuration,
};
use crate::{AppState, http};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use vouch_common::protocol;

/// POST /oauth/register — RFC 7591 Dynamic Client Registration.
///
/// Accepts an optional Bearer token. When present, the authenticated user
/// becomes the owner of the newly registered client, and must be active. When
/// absent (open registration), the client is created without user association.
///
/// Returns 201 Created with the client information response.
pub(crate) async fn register(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    token: Result<OptionalAuthenticatedToken, ServiceError>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    // Authentication is optional here, but a token that fails validation is an
    // error rather than an anonymous request. RFC 7592 §2 / RFC 6750 §3.1: the
    // rejection carries code `invalid_token` (not `invalid_client`), a 401, and
    // a `WWW-Authenticate` challenge — propagate it rather than falling back to
    // open registration.
    let user_id = match token {
        // A deactivated account's still-live token is refused by the extractor
        // as `invalid_token` (RFC 6750 §3.1), so it cannot own a client.
        Ok(OptionalAuthenticatedToken(Some(AuthenticatedToken { user, .. }))) => Some(user.id),
        Ok(OptionalAuthenticatedToken(None)) => None,
        Err(e) => return into_registration_response(e),
    };

    // Delegate to service layer
    let response = match register_client(&state, request, user_id.as_deref(), &client_info).await {
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
/// on success, 401 if the token is invalid or the client does not exist
/// (RFC 7592 §2.1/§5 keep these cases indistinguishable).
pub(crate) async fn read_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match http::bearer_token(&headers) {
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
    client_info: ClientInfo,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    let token = match http::bearer_token(&headers) {
        Some(t) => t,
        None => return missing_token_response(),
    };

    match update_client_configuration(&state, &client_id, token, request, &client_info).await {
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
/// 401 if the token is invalid or the client does not exist (RFC 7592
/// §2.3/§5 keep these cases indistinguishable).
pub(crate) async fn delete_client(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match http::bearer_token(&headers) {
        Some(t) => t,
        None => return missing_token_response(),
    };

    match delete_client_configuration(&state, &client_id, token, &client_info).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => into_registration_response(e),
    }
}

/// Build a 401 response for a missing bearer token on an RFC 7592 endpoint.
///
/// Per RFC 6750 Section 3.1: when the request lacks any authentication
/// information, the `WWW-Authenticate` challenge SHOULD NOT include an
/// error code or other error information. The `invalid_token` error is
/// reserved for requests that *do* carry a token that is expired,
/// revoked, or malformed; that path is handled by
/// [`into_registration_response`], which still emits
/// `error="invalid_token"`.
fn missing_token_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            http::bearer_challenge(&[]),
        )],
    )
        .into_response()
}

/// Convert a `ServiceError` into an RFC 6750-compliant response for an RFC 7592
/// registration endpoint.
///
/// This wraps [`ServiceError::into_oauth_response`] and, for 401 responses,
/// appends a `WWW-Authenticate: Bearer error="invalid_token", ...` header as
/// required by RFC 6750 Section 3.1 for protected resources.
///
/// `ServiceError::ApiWithHeaders` (emitted by `extract_resource_token` for
/// DPoP nonce refresh — RFC 9449 §7.2) carries additional response headers like
/// `DPoP-Nonce` that `into_oauth_response`'s tuple return type cannot convey.
/// Those headers are extracted before the error is consumed and reattached to
/// the built response so the client can retry with a fresh nonce.
///
/// Post-`f6485dd0`, every DPoP refusal at a resource routes through
/// `DpopChallenge` whose `headers()` already emits the RFC 9449 §7.1
/// `WWW-Authenticate: DPoP …` value into `ApiWithHeaders.headers`. Synthesizing
/// the RFC 6750 `Bearer` challenge on top of it and then `HeaderMap::append`-ing
/// the carried headers would yield **two** `WWW-Authenticate` field values (a
/// wrong-scheme `Bearer` value carrying a DPoP-extension error code, plus the
/// correct `DPoP` challenge). To keep `/oauth/register` consistent with
/// `/v1/*` and `/oauth/userinfo` — which append the carried headers without
/// synthesizing a competing `Bearer` challenge — the `Bearer` challenge is
/// only synthesized when the carried headers do not already include a
/// `WWW-Authenticate` value. This is observably a no-op for conformant callers
/// (RFC 9110 §11.6.1): a client facing the single `DPoP` challenge selects it
/// and retries exactly as it would have selected it from a two-value response.
fn into_registration_response(err: ServiceError) -> Response {
    let extra_headers = match &err {
        ServiceError::ApiWithHeaders { headers, .. } => Some(headers.clone()),
        _ => None,
    };

    // A DPoP refusal routed through `DpopChallenge` already carries the
    // RFC 9449 §7.1 `WWW-Authenticate: DPoP …` value. Synthesizing a `Bearer`
    // challenge on top of it (and then appending the carried headers) would
    // produce a second `WWW-Authenticate` field value — a wrong-scheme `Bearer`
    // challenge carrying a DPoP-extension error code — which `/v1/*` and
    // `/oauth/userinfo` do not emit. Skip the synthesis whenever the carried
    // headers already answer the 401, so the register endpoint renders one
    // challenge for a DPoP refusal like the other two surfaces.
    let has_www_auth = extra_headers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|(name, _)| *name == axum::http::header::WWW_AUTHENTICATE);

    let (status, json) = err.into_oauth_response();
    let mut response = if status == StatusCode::UNAUTHORIZED && !has_www_auth {
        let description = json
            .error_description
            .clone()
            .unwrap_or_else(|| "Invalid or expired token".to_string());
        // The `error` and `error_description` parameters mirror the JSON body
        // so OAuth client libraries can rely on either source (RFC 6750 §3.1).
        let www_auth = http::bearer_challenge(&[
            ("error", json.error.as_str()),
            ("error_description", description.as_str()),
        ]);
        (
            status,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_str(&www_auth).unwrap_or_else(|_| {
                    axum::http::HeaderValue::from_static(protocol::AUTH_SCHEME_BEARER)
                }),
            )],
            json,
        )
            .into_response()
    } else {
        (status, json).into_response()
    };

    if let Some(headers) = extra_headers {
        for (name, value) in headers {
            response.headers_mut().append(name, value);
        }
    }
    response
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::error::{OAuthErrorCode, ServiceError};

    /// RFC 6750 §3.1: when the request lacks any authentication
    /// information, the `WWW-Authenticate` challenge SHOULD NOT include
    /// an error code or other error information. A missing bearer token
    /// on a registration endpoint therefore produces a bare `Bearer`
    /// challenge with no `error` / `error_description` parameters and no
    /// JSON error body.
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
            www_auth == "Bearer",
            "WWW-Authenticate must be a bare 'Bearer' (no error parameters): {www_auth}"
        );
        assert!(
            !www_auth.contains("error="),
            "Missing-auth challenge must not include an error parameter: {www_auth}"
        );

        // RFC 6750 §3.1: no error information, so no JSON error body.
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(
            body.is_empty(),
            "Missing-auth response must not carry a JSON error body: {body:?}"
        );
    }

    /// RFC 6750 §3.1: `into_registration_response` must add a
    /// `WWW-Authenticate` header (with `error="invalid_token"`) to any 401
    /// `ServiceError`, while preserving non-401 errors unchanged.
    #[tokio::test]
    async fn into_registration_response_adds_www_authenticate_on_401() {
        use axum::body::to_bytes;

        // 401 path: registration-token validation emits a 401 invalid_token
        // API error, which the Api arm of into_oauth_response preserves.
        let err = ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid registration access token",
        );
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

        let err = ServiceError::oauth(
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

    /// RFC 9449 §7.2: `ServiceError::ApiWithHeaders` carrying a 401
    /// `use_dpop_nonce` (emitted by `extract_resource_token` when a DPoP-bound
    /// token replays a consumed nonce) MUST be preserved by
    /// `into_registration_response` — the response must carry the original 401
    /// status, the `use_dpop_nonce` error code in the body, a `WWW-Authenticate`
    /// header (RFC 6750 §3.1), AND the `DPoP-Nonce` header so the client can
    /// retry with a fresh nonce. Before the fix, `ApiWithHeaders` fell through
    /// `into_oauth_response`'s catch-all and became a 500 `server_error`.
    ///
    /// This variant carries only `DPoP-Nonce` (the pre-`f6485dd0` `UseNonce`
    /// shape, where no `WWW-Authenticate` value is carried), so the helper still
    /// synthesizes the RFC 6750 `Bearer` challenge — exactly one
    /// `WWW-Authenticate` value. The post-`f6485dd0` `DpopChallenge` shape (which
    /// carries `WWW-Authenticate: DPoP …`) is covered by
    /// [`into_registration_response_emits_single_dpop_challenge_for_dpop_refusal`].
    #[tokio::test]
    async fn into_registration_response_preserves_api_with_headers_on_401() {
        use axum::body::to_bytes;
        use axum::http::header;

        let err = ServiceError::api_with_header(
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "Authorization server requires nonce in DPoP proof",
            ("DPoP-Nonce", "fresh-nonce-value"),
        );
        let response = into_registration_response(err);

        // Status preserved — not collapsed to 500.
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce must remain 401, not 500"
        );

        // DPoP-Nonce header preserved for client retry (RFC 9449 §7.2).
        let nonce = response
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!(nonce, "fresh-nonce-value");

        // Exactly ONE `WWW-Authenticate` value — read via `get_all` so a
        // second, appended value cannot hide behind `HeaderMap::get`'s
        // first-value-only semantics.
        let challenges: Vec<&str> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            challenges.len(),
            1,
            "DPoP-Nonce-only shape must render a single WWW-Authenticate value: {challenges:?}"
        );
        assert!(
            challenges[0].starts_with("Bearer "),
            "DPoP-Nonce-only shape synthesizes the Bearer challenge: {challenges:?}"
        );
        assert!(
            challenges[0].contains(r#"error="use_dpop_nonce""#),
            "WWW-Authenticate must carry error=\"use_dpop_nonce\": {challenges:?}"
        );

        // Body carries the OAuth error code, not server_error.
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"], "use_dpop_nonce",
            "error code must be use_dpop_nonce, not server_error"
        );
    }

    /// RFC 9449 §7.1: post-`f6485dd0`, a DPoP refusal at a resource routes
    /// through `DpopChallenge`, whose `headers()` emits a
    /// `WWW-Authenticate: DPoP …` value (plus `DPoP-Nonce` for `use_dpop_nonce`)
    /// into `ServiceError::ApiWithHeaders`. `into_registration_response` MUST
    /// NOT synthesize a competing `Bearer` challenge on top of it — the
    /// response must carry exactly one `WWW-Authenticate` value, and its scheme
    /// must be `DPoP` (not `Bearer`), to match `/v1/*` and `/oauth/userinfo`.
    /// Before the fix the helper synthesized `Bearer error="use_dpop_nonce"`
    /// and then `HeaderMap::append`-ed the carried `DPoP` value, yielding two
    /// `WWW-Authenticate` field values.
    #[tokio::test]
    async fn into_registration_response_emits_single_dpop_challenge_for_dpop_refusal() {
        use axum::body::to_bytes;
        use axum::http::header;

        // Mirror `DpopChallenge::headers()` for the `use_dpop_nonce` arm: a
        // `WWW-Authenticate: DPoP …` value plus a `DPoP-Nonce` header.
        let challenge = http::dpop_challenge(&[
            ("error", "use_dpop_nonce"),
            (
                "error_description",
                "Resource server requires nonce in DPoP proof",
            ),
            ("algs", "ES256 PS256 EdDSA"),
        ]);
        let err = ServiceError::ApiWithHeaders {
            status: StatusCode::UNAUTHORIZED,
            code: "use_dpop_nonce".to_string(),
            message: "Resource server requires nonce in DPoP proof".to_string(),
            headers: vec![
                (
                    header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_str(&challenge).unwrap(),
                ),
                (
                    axum::http::HeaderName::from_static(protocol::HEADER_DPOP_NONCE),
                    axum::http::HeaderValue::from_str("fresh-nonce-value").unwrap(),
                ),
            ],
        };
        let response = into_registration_response(err);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Exactly ONE `WWW-Authenticate` field value — not two.
        let challenges: Vec<&str> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            challenges.len(),
            1,
            "DPoP refusal must render a single WWW-Authenticate value, got {challenges:?}"
        );
        // ...and it is the DPoP challenge (not a synthesized Bearer one).
        assert!(
            challenges[0].starts_with("DPoP "),
            "challenge scheme must be DPoP, got {challenges:?}"
        );
        assert!(
            challenges[0].contains(r#"error="use_dpop_nonce""#),
            "challenge must carry the use_dpop_nonce error: {challenges:?}"
        );
        assert!(
            challenges[0].contains(r#"algs="ES256 PS256 EdDSA""#),
            "challenge must carry the algs parameter: {challenges:?}"
        );
        assert!(
            !challenges[0].starts_with("Bearer"),
            "no wrong-scheme Bearer challenge must be synthesized: {challenges:?}"
        );

        // The `DPoP-Nonce` header the client needs for retry is preserved.
        let nonce = response
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .expect("DPoP-Nonce header must be preserved");
        assert_eq!(nonce, "fresh-nonce-value");

        // Body carries the OAuth error code.
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    /// RFC 9449 §7.1: a non-`UseNonce` DPoP refusal (here `invalid_dpop_proof`
    /// for an `htu` mismatch) routed through `DpopChallenge` carries a
    /// `WWW-Authenticate: DPoP error="invalid_dpop_proof" …` value and NO
    /// `DPoP-Nonce`. `into_registration_response` must render exactly that one
    /// challenge, with no synthesized `Bearer error="invalid_dpop_proof"` value
    /// — matching `/v1/*` and `/oauth/userinfo`.
    #[tokio::test]
    async fn into_registration_response_emits_single_dpop_challenge_for_invalid_dpop_proof() {
        use axum::http::header;

        let challenge = http::dpop_challenge(&[
            ("error", "invalid_dpop_proof"),
            ("error_description", "DPoP htu claim mismatch"),
            ("algs", "ES256 PS256 EdDSA"),
        ]);
        let err = ServiceError::ApiWithHeaders {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_dpop_proof".to_string(),
            message: "DPoP htu claim mismatch".to_string(),
            headers: vec![(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_str(&challenge).unwrap(),
            )],
        };
        let response = into_registration_response(err);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let challenges: Vec<&str> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            challenges.len(),
            1,
            "invalid_dpop_proof must render a single WWW-Authenticate value, got {challenges:?}"
        );
        assert!(
            challenges[0].starts_with(r#"DPoP error="invalid_dpop_proof""#),
            "challenge must be the DPoP invalid_dpop_proof value: {challenges:?}"
        );
        assert!(
            challenges[0].contains(r#"algs="ES256 PS256 EdDSA""#),
            "challenge must carry the algs parameter: {challenges:?}"
        );
        assert!(
            !challenges[0].starts_with("Bearer"),
            "no wrong-scheme Bearer challenge must be synthesized: {challenges:?}"
        );
        // A non-`UseNonce` arm must not carry a `DPoP-Nonce` header.
        assert!(
            response.headers().get("dpop-nonce").is_none(),
            "invalid_dpop_proof must not carry a DPoP-Nonce header"
        );
    }
}
