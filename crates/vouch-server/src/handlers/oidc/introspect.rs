// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token introspection and revocation endpoint handlers.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::db::ClientInfo;
use crate::error::ServiceError;
use crate::services::oidc::introspection::{
    introspect_token as svc_introspect, revoke_token as svc_revoke, sign_introspection_jwt,
};
use crate::services::oidc::token::ClientAuthError;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Deserialize;
use std::sync::Arc;

use super::client_auth::{ClientAuthFields, complete_client_auth, extract_client_auth};

/// Token revocation request (RFC 7009 Section 2.1).
///
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt`
/// (RFC 7523) client authentication methods.
#[derive(Deserialize)]
pub(crate) struct RevokeRequest {
    /// RFC 7009 Section 2.1: The token that the client wants to get revoked.
    token: String,
    /// RFC 7009 Section 2.1: A hint about the type of the token.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// RFC 6749 Section 2.3.1: Client ID for `client_secret_post` authentication.
    #[serde(default)]
    client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret for `client_secret_post` authentication.
    /// Wrapped in `SecretString` to prevent accidental logging and ensure zeroization on drop.
    #[serde(default)]
    client_secret: Option<SecretString>,
    /// RFC 7521 Section 4.2: JWT assertion for `private_key_jwt` authentication.
    #[serde(default)]
    client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Assertion type (must be
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
    #[serde(default)]
    client_assertion_type: Option<String>,
}

// Custom Debug that redacts the subject token to prevent accidental log
// exposure of a live credential the client is asking us to revoke.
impl std::fmt::Debug for RevokeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokeRequest")
            .field("token", &"[REDACTED]")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("client_assertion", &"[REDACTED]")
            .field("client_assertion_type", &self.client_assertion_type)
            .finish()
    }
}

impl ClientAuthFields for RevokeRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
}

/// Token introspection request (RFC 7662 Section 2.1).
///
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt`
/// (RFC 7523) client authentication methods.
#[derive(Deserialize)]
pub(crate) struct IntrospectRequest {
    /// RFC 7662 Section 2.1: The string value of the token.
    token: String,
    /// RFC 7662 Section 2.1: A hint about the type of the token.
    #[serde(default)]
    token_type_hint: Option<String>,
    /// RFC 6749 Section 2.3.1: Client ID for `client_secret_post` authentication.
    #[serde(default)]
    client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret for `client_secret_post` authentication.
    /// Wrapped in `SecretString` to prevent accidental logging and ensure zeroization on drop.
    #[serde(default)]
    client_secret: Option<SecretString>,
    /// RFC 7521 Section 4.2: JWT assertion for `private_key_jwt` authentication.
    #[serde(default)]
    client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Assertion type (must be
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
    #[serde(default)]
    client_assertion_type: Option<String>,
}

// Custom Debug that redacts the subject token to prevent accidental log
// exposure of the live credential being introspected.
impl std::fmt::Debug for IntrospectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectRequest")
            .field("token", &"[REDACTED]")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("client_assertion", &"[REDACTED]")
            .field("client_assertion_type", &self.client_assertion_type)
            .finish()
    }
}

impl ClientAuthFields for IntrospectRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
}

/// POST /oauth/revoke
///
/// Revoke an access token (RFC 7009 Section 2.1).
/// Returns 200 OK regardless of whether the token was valid (security best practice).
/// Supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt` auth.
pub(crate) async fn revoke(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    headers: HeaderMap,
    axum::Form(params): axum::Form<RevokeRequest>,
) -> Response {
    // RFC 7009 Section 2.1: Authenticate the calling client.
    // Supports client_secret_basic, client_secret_post, and private_key_jwt.
    let auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    let (caller_client_id, pending_jti) = match complete_client_auth(&state, auth).await {
        Ok(Some(a)) => (a.client_id, a.pending_jti),
        Ok(None) => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
        Err(response) => return response,
    };

    let _result = svc_revoke(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        client_info,
        &caller_client_id,
    )
    .await;

    // Commit JTI after revocation so clients can retry on failure.
    if let Some(p) = pending_jti {
        match p.commit(&state).await {
            Ok(_claim) => {}
            Err(ClientAuthError::InvalidCredentials) => {
                // JTI was already used — reject so the client generates a new assertion.
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(e) => {
                // Transient DB error. Revocation already succeeded — return 200
                // per RFC 7009 §2 and log for ops visibility.
                tracing::warn!("JTI commit failed for revoke (revocation succeeded): {e:?}");
            }
        }
    }

    // Always return 200 per RFC 7009 Section 2 (for valid clients)
    StatusCode::OK.into_response()
}

/// POST /oauth/introspect
///
/// Introspect a token (RFC 7662).
/// Requires client authentication via `Authorization: Basic` header, body
/// credentials, or `private_key_jwt` (RFC 7523).
/// Returns token metadata if valid, or `{"active": false}` if invalid or auth fails.
pub(crate) async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(params): axum::Form<IntrospectRequest>,
) -> Response {
    // RFC 7662 Section 2.1: The introspection endpoint MUST authenticate the caller.
    // Supports client_secret_basic, client_secret_post, and private_key_jwt.
    let auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    let (authenticated_client, pending_jti) = match complete_client_auth(&state, auth).await {
        Ok(Some(a)) => (a.client.client, a.pending_jti),
        Ok(None) => {
            // No credentials provided → 401
            return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic")]).into_response();
        }
        Err(response) => return response,
    };

    let wants_jwt = authenticated_client
        .introspection_signed_response_alg
        .is_some();
    let client_id = authenticated_client.client_id.clone();
    let config = state.config();
    let issuer = config.base_url.clone();

    let result = match svc_introspect(
        &state,
        &params.token,
        params.token_type_hint.as_deref(),
        Some(client_id.as_str()),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Introspection failed: {e}");
            return introspect_error_response(e);
        }
    };

    // Commit JTI after introspection so clients can retry on failure.
    if let Some(p) = pending_jti {
        match p.commit(&state).await {
            Ok(_claim) => {}
            Err(ClientAuthError::InvalidCredentials) => {
                // JTI was already used — reject so the client generates a new assertion.
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(e) => {
                // Transient DB error. Introspection already succeeded — return the
                // result per defense-in-depth: prefer denying replay over dropping
                // a valid response. Log for ops visibility.
                tracing::warn!("JTI commit failed for introspect (returning result anyway): {e:?}");
            }
        }
    }

    if wants_jwt {
        let jwt_result =
            sign_introspection_jwt(&result, &issuer, &client_id, &state.oidc_key).await;
        jwt_introspect_response(jwt_result)
    } else {
        Json(result).into_response()
    }
}

/// Render any introspection-endpoint `ServiceError` as an RFC 6749 §5.2 OAuth
/// error response (e.g. `{"error": "server_error", ...}`).
///
/// Both error-producing paths in this endpoint — the introspection-service
/// failure (store/DB errors) and the JWT-signing failure — funnel through this
/// helper so the endpoint can never emit two different error shapes for the same
/// `ServiceError` (issue #572). Do not hand-roll an error response here; route it
/// through `ServiceError::into_oauth_response`.
fn introspect_error_response(e: ServiceError) -> Response {
    e.into_oauth_response().into_response()
}

/// Map a signed-introspection-JWT result to an HTTP response.
///
/// Returns 200 with Content-Type `application/token-introspection+jwt` on success
/// (RFC 9701 §5). On signing failure, returns the OAuth `server_error` response
/// (via [`introspect_error_response`]) and logs the underlying error — never
/// `{"active": false}`, which would misrepresent a validated active token as
/// inactive (issue #396).
fn jwt_introspect_response(jwt_result: Result<String, ServiceError>) -> Response {
    match jwt_result {
        Ok(jwt) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/token-introspection+jwt",
            )],
            jwt,
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to sign introspection JWT: {e}");
            introspect_error_response(e)
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    async fn read_body(response: Response) -> (StatusCode, Option<String>, String) {
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");
        let body = String::from_utf8_lossy(&bytes).to_string();
        (status, content_type, body)
    }

    /// Regression guard for issue #396: when JWT signing fails, the handler
    /// must NOT return `{"active": false}` — that misrepresents a token whose
    /// introspection already succeeded as inactive. Instead it must return
    /// 500 server_error so operators can detect and clients see a real error.
    #[tokio::test]
    async fn test_jwt_introspect_response_err_returns_500_server_error() {
        let response = jwt_introspect_response(Err(ServiceError::Internal(
            "simulated signing failure".to_string(),
        )));

        let (status, _content_type, body) = read_body(response).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let json: serde_json::Value =
            serde_json::from_str(&body).expect("Body must be JSON OAuth error");
        assert_eq!(
            json["error"], "server_error",
            "Error code must be 'server_error' per RFC 6749 §5.2: {body}"
        );
        assert!(
            json.get("error_description").is_some(),
            "Error response must include a description: {body}"
        );
        assert!(
            json.get("active").is_none(),
            "Response must NOT contain 'active' field — that would leak \
             the buggy inactive payload (issue #396): {body}"
        );
    }

    /// Regression guard for issue #572: every `ServiceError` from this endpoint
    /// — whether from the introspection service (store/DB) or JWT signing — must
    /// render as an RFC 6749 §5.2 OAuth error (`{"error": "server_error"}`),
    /// never the API error envelope (`{"code": ..., "message": ...}`). Both arms
    /// funnel through `introspect_error_response`, so testing it pins the single
    /// rendering contract the two paths share.
    #[tokio::test]
    async fn test_introspect_error_response_uses_oauth_error_shape() {
        for err in [
            ServiceError::Internal("simulated store failure".to_string()),
            ServiceError::OccConflict,
        ] {
            let response = introspect_error_response(err);
            let (status, _content_type, body) = read_body(response).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");

            let json: serde_json::Value =
                serde_json::from_str(&body).expect("Body must be JSON OAuth error");
            assert_eq!(
                json["error"], "server_error",
                "Must use OAuth 'error' field per RFC 6749 §5.2, not API 'code': {body}"
            );
            assert!(
                json.get("code").is_none() && json.get("message").is_none(),
                "Must NOT use the API error envelope ({{code, message}}): {body}"
            );
        }
    }

    /// Happy path: signed JWT is returned verbatim with the RFC 9701
    /// content-type and 200 status.
    #[tokio::test]
    async fn test_jwt_introspect_response_ok_returns_200_with_jwt_content_type() {
        let jwt_payload = "eyJ.aGVsbG8.signed".to_string();
        let response = jwt_introspect_response(Ok(jwt_payload.clone()));

        let (status, content_type, body) = read_body(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type.as_deref(),
            Some("application/token-introspection+jwt"),
            "RFC 9701 §5 requires this exact content type"
        );
        assert_eq!(body, jwt_payload, "Body must be the JWT verbatim");
    }
}
