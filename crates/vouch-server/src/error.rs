// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Service layer error types with RFC-compliant conversions.
//!
//! This module provides error types for the service layer that can be
//! converted into appropriate HTTP responses for different protocols:
//! - Standard HTTP error responses
//! - OAuth 2.0 error responses (RFC 6749 Section 5.2)

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use vouch_common::ApiError;

/// Service layer errors with protocol-aware conversions.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Entity not found.
    #[error("not found: {0}")]
    NotFound(&'static str),

    /// Validation error.
    #[error("validation: {0}")]
    Validation(String),

    /// Permission denied.
    #[error("forbidden: {0}")]
    Forbidden(&'static str),

    /// Conflict (e.g., duplicate resource).
    #[error("conflict: {0}")]
    Conflict(String),

    /// OAuth protocol error (RFC 6749 Section 5.2).
    #[error("oauth error: {code}")]
    OAuth {
        /// OAuth error code.
        code: OAuthErrorCode,
        /// Human-readable description.
        description: String,
    },

    /// Structured API error with explicit status code, error code, and message.
    ///
    /// Use this when you need a specific error code in the response body (e.g.,
    /// `"ssh_ca_not_configured"`) that doesn't map cleanly to one of the typed
    /// `ServiceError` variants. Produces `{"code": "...", "message": "..."}`.
    #[error("{message}")]
    Api {
        /// HTTP status code.
        status: StatusCode,
        /// Machine-readable error code (e.g., "ssh_ca_not_configured").
        code: String,
        /// Human-readable error message.
        message: String,
    },

    /// Structured API error that carries additional response headers.
    ///
    /// Like [`Self::Api`], but attaches headers the response must include —
    /// e.g. the RFC 9449 `DPoP-Nonce` header that accompanies a
    /// `use_dpop_nonce` error at a protected resource endpoint, so the client
    /// can retry with a fresh nonce. The body is still
    /// `{"code": "...", "message": "..."}`.
    #[error("{message}")]
    ApiWithHeaders {
        /// HTTP status code.
        status: StatusCode,
        /// Machine-readable error code (e.g., "use_dpop_nonce").
        code: String,
        /// Human-readable error message.
        message: String,
        /// Additional response headers (e.g., `DPoP-Nonce`).
        headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
    },

    /// RFC 9470: Step-up authentication required.
    ///
    /// A resource server determines the current token's authentication is
    /// insufficient (e.g., `auth_time` too old). The response includes a
    /// `WWW-Authenticate` header with `error="insufficient_user_authentication"`.
    #[error("step-up authentication required")]
    StepUpRequired {
        /// Requested authentication context class references.
        acr_values: Option<String>,
        /// Maximum authentication age in seconds.
        max_age: Option<u64>,
    },

    /// OCC version-conflict signal.
    ///
    /// Returned by transactional operations when `compare_and_update` returns
    /// `Ok(false)` — meaning another writer already bumped the owning document's
    /// version between our read and our commit.  This is the **only** `ServiceError`
    /// variant that `with_dsql_retry!` will re-run the enclosing async block for;
    /// business-logic 409s (e.g. `max_secrets_reached`, `last_secret`) are
    /// distinct variants and are **not** retried.
    #[error("OCC version conflict; retry the transaction")]
    OccConflict,

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for ServiceError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl crate::db::pool::RetryableError for ServiceError {
    /// Only `OccConflict` triggers a retry.
    ///
    /// Business-logic errors (max_secrets_reached, last_secret, last_key, …)
    /// use dedicated `ServiceError::Api` or `ServiceError::NotFound` variants and
    /// must propagate immediately — retrying them would loop forever.
    fn is_retryable(&self) -> bool {
        matches!(self, Self::OccConflict)
    }
}

/// OAuth 2.0 error codes (RFC 6749 Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    /// RFC 6749 Section 5.2: The request is missing a required parameter.
    InvalidRequest,
    /// RFC 6749 Section 5.2: Client authentication failed.
    InvalidClient,
    /// RFC 6749 Section 5.2: The provided authorization grant is invalid.
    InvalidGrant,
    /// RFC 6749 Section 5.2: The client is not authorized to use this grant type.
    UnauthorizedClient,
    /// RFC 6749 Section 5.2: The authorization grant type is not supported.
    UnsupportedGrantType,
    /// RFC 6749 Section 5.2: The requested scope is invalid or unknown.
    InvalidScope,
    /// RFC 6749 Section 4.1.2.1: The authorization server encountered an unexpected condition.
    ServerError,
    /// RFC 6749 Section 4.1.2.1: The authorization server is temporarily unavailable.
    TemporarilyUnavailable,
    /// RFC 8628 Section 3.5: The authorization request is still pending.
    AuthorizationPending,
    /// RFC 8628 Section 3.5: Polling too frequently.
    SlowDown,
    /// RFC 8628 Section 3.5: The device code has expired.
    ExpiredToken,
    /// RFC 6749 Section 4.1.2.1: Access denied by the resource owner or authorization server.
    AccessDenied,
    /// RFC 6749 Section 4.1.2.1: The response type is not supported.
    UnsupportedResponseType,
    /// RFC 6750 Section 3.1: The access token provided is expired, revoked,
    /// malformed, or invalid for other reasons. Used by OAuth 2.0 protected
    /// resources (e.g., RFC 7592 registration endpoints) when bearer-token
    /// validation fails.
    InvalidToken,
    /// RFC 9449 Section 5.1: Invalid DPoP proof.
    InvalidDpopProof,
    /// RFC 9449 Section 5.1: DPoP nonce required.
    UseDpopNonce,
    /// RFC 8707 Section 2: The target resource is invalid, unknown, or malformed.
    InvalidTarget,
    /// RFC 9470 Section 3: Token authentication is insufficient (step-up required).
    InsufficientUserAuthentication,
    /// RFC 9470 Section 4: Authorization server cannot meet requested authentication requirements.
    UnmetAuthenticationRequirements,
    /// RFC 9101 Section 6.2: The Request Object is invalid.
    InvalidRequestObject,
    /// RFC 7591 Section 3.2.2: A redirect URI is invalid.
    InvalidRedirectUri,
    /// RFC 7591 Section 3.2.2: Client metadata is invalid.
    InvalidClientMetadata,
    /// RFC 9396 Section 7: The authorization_details parameter is invalid.
    InvalidAuthorizationDetails,
    /// OIDC Core Section 6.2: The request_uri parameter value is invalid.
    InvalidRequestUri,
    /// OIDC Core Section 3.1.2.6: "The Authorization Server requires
    /// End-User authentication. This error MAY be returned when the prompt
    /// parameter value in the Authentication Request is none, but the
    /// Authentication Request cannot be completed without displaying a user
    /// interface for End-User authentication."
    /// <https://openid.net/specs/openid-connect-core-1_0.html#AuthError>
    LoginRequired,
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl OAuthErrorCode {
    /// Get the appropriate HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest
            | Self::InvalidScope
            | Self::InvalidDpopProof
            | Self::InvalidTarget
            | Self::UnmetAuthenticationRequirements
            | Self::InvalidRequestObject
            | Self::InvalidRedirectUri
            | Self::InvalidClientMetadata
            | Self::InvalidAuthorizationDetails
            | Self::InvalidRequestUri
            // `login_required` only ever travels as a redirect query
            // parameter (OIDC Core 3.1.2.6), never as an HTTP status on a
            // direct response, so this arm is currently unreachable.
            | Self::LoginRequired => StatusCode::BAD_REQUEST,
            Self::InvalidClient | Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::InsufficientUserAuthentication => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::AuthorizationPending
            | Self::SlowDown
            | Self::ExpiredToken
            | Self::AccessDenied => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ServerError | Self::TemporarilyUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UseDpopNonce => StatusCode::BAD_REQUEST,
        }
    }

    /// Convert to the string representation used in OAuth responses.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::InvalidToken => "invalid_token",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
            Self::InvalidTarget => "invalid_target",
            Self::InsufficientUserAuthentication => "insufficient_user_authentication",
            Self::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::InvalidAuthorizationDetails => "invalid_authorization_details",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::LoginRequired => "login_required",
        }
    }
}

/// OAuth 2.0 error response (RFC 6749 Section 5.2).
#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    /// RFC 6749 Section 5.2: A single ASCII error code.
    pub error: String,
    /// RFC 6749 Section 5.2: Human-readable ASCII text providing additional information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// RFC 6749 Section 5.2: A URI identifying a human-readable web page with error information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl ServiceError {
    /// Create an OAuth error.
    #[must_use]
    pub fn oauth(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self::OAuth {
            code,
            description: description.into(),
        }
    }

    /// Returns the OAuth-facing description if this is an `OAuth` variant,
    /// otherwise falls back to the error's `Display` output.
    #[must_use]
    pub(crate) fn oauth_description(&self) -> String {
        match self {
            Self::OAuth { description, .. } => description.clone(),
            other => other.to_string(),
        }
    }

    /// Create a structured API error with a specific status code, error code,
    /// and message.
    ///
    /// Use this when you need a specific error code in the response body (e.g.,
    /// `"ssh_ca_not_configured"`) that doesn't map cleanly to one of the typed
    /// `ServiceError` variants.
    #[must_use]
    pub fn api(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Api {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Create a structured API error that carries an additional response header.
    ///
    /// Produces the same `{"code": "...", "message": "..."}` body as
    /// [`Self::api`] but attaches a header such as `DPoP-Nonce` (RFC 9449) to
    /// the response so the client can retry. The header name is parsed with
    /// case-insensitive matching (`"DPoP-Nonce"` → `dpop-nonce`); the value is
    /// stored verbatim and must be a valid HTTP header value.
    #[must_use]
    pub fn api_with_header(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
        header: (&'static str, &str),
    ) -> Self {
        let (name, value) = header;
        Self::ApiWithHeaders {
            status,
            code: code.into(),
            message: message.into(),
            headers: vec![(
                axum::http::HeaderName::try_from(name)
                    .unwrap_or_else(|_| axum::http::HeaderName::from_static("x-vouch-header")),
                axum::http::HeaderValue::from_str(value)
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            )],
        }
    }

    /// Classify a database error from a transactional operation.
    ///
    /// Writer contention (Postgres serialization failure, Aurora DSQL
    /// OC000/OC001, SQLite BUSY/LOCKED) becomes [`Self::OccConflict`] so the
    /// enclosing `with_dsql_retry!` re-runs the transaction; anything else
    /// becomes [`Self::Internal`] and propagates as a 500.
    pub(crate) fn from_db_contention(err: anyhow::Error, msg: &'static str) -> Self {
        tracing::error!("{msg}: {err}");
        if crate::db::pool::is_retryable_db_error(&err) {
            Self::OccConflict
        } else {
            Self::Internal(msg.to_string())
        }
    }

    /// Convert to an OAuth error response.
    pub fn into_oauth_response(self) -> (StatusCode, Json<OAuthErrorResponse>) {
        match self {
            Self::OAuth { code, description } => (
                code.status_code(),
                Json(OAuthErrorResponse {
                    error: code.as_str().to_string(),
                    error_description: Some(description),
                    error_uri: None,
                }),
            ),
            Self::NotFound(entity) => (
                StatusCode::NOT_FOUND,
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidRequest.as_str().to_string(),
                    error_description: Some(format!("{entity} not found")),
                    error_uri: None,
                }),
            ),
            Self::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidRequest.as_str().to_string(),
                    error_description: Some(msg),
                    error_uri: None,
                }),
            ),
            // RFC 6750 Section 3.1: preserve bearer-token errors (`invalid_token`
            // from `extract_resource_token` or RFC 7592 registration-token
            // validation) instead of collapsing them to a 500 `server_error`.
            // Only 401s are preserved: other `Api` errors carry internal codes
            // (e.g. `issuer_error`) that are not registered OAuth error codes
            // and must keep falling through to the generic `server_error`.
            Self::Api {
                status,
                code,
                message,
            } if status == StatusCode::UNAUTHORIZED => (
                status,
                Json(OAuthErrorResponse {
                    error: code,
                    error_description: Some(message),
                    error_uri: None,
                }),
            ),
            // RFC 9449 §7.2: `ApiWithHeaders` carries the same 401 bearer-token
            // errors as `Api` (emitted by `extract_resource_token` for DPoP
            // nonce refresh) plus response headers like `DPoP-Nonce`. The tuple
            // return type cannot convey headers; preserve the error code and
            // status here so callers that do not need headers (e.g., token/PAR
            // endpoints with their own nonce handling) still get the right
            // error instead of a 500 `server_error`. Callers that need the
            // headers (e.g., `/oauth/register` via `into_registration_response`)
            // extract them before calling this method.
            Self::ApiWithHeaders {
                status,
                code,
                message,
                ..
            } if status == StatusCode::UNAUTHORIZED => (
                status,
                Json(OAuthErrorResponse {
                    error: code,
                    error_description: Some(message),
                    error_uri: None,
                }),
            ),
            Self::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::AccessDenied.as_str().to_string(),
                    error_description: Some("Access denied".to_string()),
                    error_uri: None,
                }),
            ),
            Self::StepUpRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InsufficientUserAuthentication
                        .as_str()
                        .to_string(),
                    error_description: Some("A recent authentication is required".to_string()),
                    error_uri: None,
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::ServerError.as_str().to_string(),
                    error_description: Some("Internal server error".to_string()),
                    error_uri: None,
                }),
            ),
        }
    }

    /// Build a `WWW-Authenticate` header value for RFC 9470 step-up challenges.
    fn build_www_authenticate(acr_values: &Option<String>, max_age: &Option<u64>) -> String {
        let mut params = vec![
            (
                "error",
                OAuthErrorCode::InsufficientUserAuthentication
                    .as_str()
                    .to_string(),
            ),
            (
                "error_description",
                "A recent authentication is required".to_string(),
            ),
        ];
        if let Some(acr) = acr_values {
            params.push(("acr_values", acr.clone()));
        }
        if let Some(age) = max_age {
            params.push(("max_age", age.to_string()));
        }
        let params: Vec<(&str, &str)> = params.iter().map(|(n, v)| (*n, v.as_str())).collect();
        crate::http::bearer_challenge(&params)
    }

    /// Convert to a standard API error response.
    ///
    /// All non-protocol variants produce `{"code": "...", "message": "..."}`.
    pub fn into_api_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::NotFound(entity) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("{entity} not found"),
            ),
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, "invalid_request", msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", (*msg).to_string()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            Self::Api {
                status,
                code,
                message,
            } => {
                return (*status, Json(ApiError::new(code.clone(), message.clone())))
                    .into_response();
            }
            Self::ApiWithHeaders {
                status,
                code,
                message,
                headers,
            } => {
                let mut response =
                    (*status, Json(ApiError::new(code.clone(), message.clone()))).into_response();
                for (name, value) in headers {
                    response.headers_mut().append(name.clone(), value.clone());
                }
                return response;
            }
            Self::StepUpRequired {
                acr_values,
                max_age,
            } => {
                let www_auth = Self::build_www_authenticate(acr_values, max_age);
                return (
                    StatusCode::UNAUTHORIZED,
                    [(
                        axum::http::header::WWW_AUTHENTICATE,
                        axum::http::HeaderValue::from_str(&www_auth).unwrap_or_else(|_| {
                            axum::http::HeaderValue::from_static(
                                "Bearer error=\"insufficient_user_authentication\"",
                            )
                        }),
                    )],
                    Json(serde_json::json!({
                        "error": "insufficient_user_authentication",
                        "error_description": "A recent authentication is required",
                    })),
                )
                    .into_response();
            }
            Self::Database(_) | Self::Internal(_) | Self::OccConflict => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal error".to_string(),
            ),
            Self::OAuth { .. } => return self.into_oauth_response().into_response(),
        };

        (status, Json(ApiError::new(code, &message))).into_response()
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        self.into_api_response()
    }
}

/// Result type for service operations.
pub(crate) type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_error_codes() {
        assert_eq!(OAuthErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(OAuthErrorCode::InvalidClient.as_str(), "invalid_client");
        assert_eq!(
            OAuthErrorCode::AuthorizationPending.as_str(),
            "authorization_pending"
        );
    }

    #[test]
    fn test_oauth_error_status_codes() {
        assert_eq!(
            OAuthErrorCode::InvalidRequest.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            OAuthErrorCode::InvalidClient.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            OAuthErrorCode::ServerError.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_service_error_oauth_conversion() {
        let err = ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Token expired");
        let (status, json) = err.into_oauth_response();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json.error, "invalid_grant");
        assert_eq!(json.error_description, Some("Token expired".to_string()));
    }

    #[test]
    fn test_oauth_description_returns_description_for_oauth_variant() {
        let err = ServiceError::oauth(OAuthErrorCode::InvalidRequest, "boom");
        assert_eq!(err.oauth_description(), "boom");
    }

    #[test]
    fn test_oauth_description_falls_back_to_display_for_other_variant() {
        let err = ServiceError::Internal("x".to_string());
        assert_eq!(err.oauth_description(), "internal error: x");
        assert_eq!(err.oauth_description(), err.to_string());
    }

    /// `OccConflict` is the only retryable `ServiceError`. Every
    /// `with_dsql_retry!` loop over `ServiceError` depends on this
    /// contract — if it regresses, transactional writes silently stop
    /// retrying transient OCC conflicts.
    #[test]
    fn occ_conflict_is_the_only_retryable_service_error() {
        use crate::db::pool::RetryableError;

        assert!(ServiceError::OccConflict.is_retryable());
        assert!(!ServiceError::Internal("boom".to_string()).is_retryable());
        assert!(!ServiceError::Conflict("duplicate".to_string()).is_retryable());
        // Business-logic 409s must propagate immediately, never retry.
        assert!(
            !ServiceError::api(StatusCode::CONFLICT, "max_secrets_reached", "cap hit")
                .is_retryable()
        );
    }

    #[test]
    fn test_service_error_api_factory() {
        let err = ServiceError::api(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH CA is not configured",
        );
        assert!(
            matches!(err, ServiceError::Api { .. }),
            "Expected ServiceError::Api"
        );
        let ServiceError::Api {
            status,
            code,
            message,
        } = err
        else {
            return;
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "ssh_ca_not_configured");
        assert_eq!(message, "SSH CA is not configured");
    }

    /// Verify that `ServiceError::Api` produces `{"code": "...", "message": "..."}`.
    #[tokio::test]
    async fn test_api_error_response_format() {
        use axum::body::to_bytes;

        let err = ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Must have exactly "code" and "message" fields
        assert_eq!(json["code"], "user_not_found");
        assert_eq!(json["message"], "User not found");
    }

    /// Verify that all standard ServiceError variants produce `{"code":..., "message":...}`.
    #[tokio::test]
    async fn test_standard_variants_produce_code_message_format() {
        use axum::body::to_bytes;

        let cases: Vec<(ServiceError, StatusCode, &str, &str)> = vec![
            (
                ServiceError::NotFound("Session"),
                StatusCode::NOT_FOUND,
                "not_found",
                "Session not found",
            ),
            (
                ServiceError::Validation("bad input".to_string()),
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "bad input",
            ),
            (
                ServiceError::api(StatusCode::UNAUTHORIZED, "invalid_token", "no token"),
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "no token",
            ),
            (
                ServiceError::Forbidden("not allowed"),
                StatusCode::FORBIDDEN,
                "forbidden",
                "not allowed",
            ),
            (
                ServiceError::Conflict("duplicate".to_string()),
                StatusCode::CONFLICT,
                "conflict",
                "duplicate",
            ),
            (
                ServiceError::Internal("boom".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal error",
            ),
        ];

        for (err, expected_status, expected_code, expected_msg) in cases {
            let response = err.into_response();
            assert_eq!(response.status(), expected_status);

            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["code"], expected_code);
            assert_eq!(json["message"], expected_msg);
        }
    }

    /// Verify OAuth error response format matches RFC 6749 Section 5.2.
    #[tokio::test]
    async fn test_oauth_error_response_format() {
        use axum::body::to_bytes;

        let err = ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Token expired");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], "invalid_grant");
        assert_eq!(json["error_description"], "Token expired");
    }

    // =========================================================================
    // RFC 9470 Step-Up Authentication Tests
    // =========================================================================

    #[test]
    fn test_rfc9470_error_codes() {
        assert_eq!(
            OAuthErrorCode::InsufficientUserAuthentication.as_str(),
            "insufficient_user_authentication"
        );
        assert_eq!(
            OAuthErrorCode::UnmetAuthenticationRequirements.as_str(),
            "unmet_authentication_requirements"
        );
    }

    #[test]
    fn test_rfc9470_error_status_codes() {
        assert_eq!(
            OAuthErrorCode::InsufficientUserAuthentication.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            OAuthErrorCode::UnmetAuthenticationRequirements.status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    /// Verify StepUpRequired produces a 401 with WWW-Authenticate header (RFC 9470 Section 3).
    #[tokio::test]
    async fn test_step_up_required_response_with_all_params() {
        use axum::body::to_bytes;

        let err = ServiceError::StepUpRequired {
            acr_values: Some("urn:nist:authentication:assurance-level:aal3".to_string()),
            max_age: Some(300),
        };
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Check WWW-Authenticate header
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("insufficient_user_authentication"));
        assert!(www_auth.contains("acr_values=\"urn:nist:authentication:assurance-level:aal3\""));
        assert!(www_auth.contains("max_age=\"300\""));

        // Check body
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "insufficient_user_authentication");
    }

    /// Verify StepUpRequired with only max_age omits acr_values from header.
    #[tokio::test]
    async fn test_step_up_required_response_max_age_only() {
        let err = ServiceError::StepUpRequired {
            acr_values: None,
            max_age: Some(60),
        };
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("max_age=\"60\""));
        assert!(!www_auth.contains("acr_values"));
    }

    /// Verify StepUpRequired with no params still produces correct header.
    #[tokio::test]
    async fn test_step_up_required_response_no_params() {
        let err = ServiceError::StepUpRequired {
            acr_values: None,
            max_age: None,
        };
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.starts_with("Bearer error=\"insufficient_user_authentication\""));
        assert!(!www_auth.contains("acr_values"));
        assert!(!www_auth.contains("max_age"));
    }

    // =========================================================================
    // RFC 7591 Dynamic Client Registration Error Code Tests
    // =========================================================================

    #[test]
    fn test_rfc7591_error_code_as_str() {
        assert_eq!(
            OAuthErrorCode::InvalidRedirectUri.as_str(),
            "invalid_redirect_uri"
        );
        assert_eq!(
            OAuthErrorCode::InvalidClientMetadata.as_str(),
            "invalid_client_metadata"
        );
    }

    #[test]
    fn test_rfc7591_error_codes_all_400() {
        assert_eq!(
            OAuthErrorCode::InvalidRedirectUri.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            OAuthErrorCode::InvalidClientMetadata.status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_rfc7591_oauth_error_response_format() {
        use axum::body::to_bytes;

        let err = ServiceError::oauth(
            OAuthErrorCode::InvalidClientMetadata,
            "jwks and jwks_uri are mutually exclusive",
        );
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], "invalid_client_metadata");
        assert_eq!(
            json["error_description"],
            "jwks and jwks_uri are mutually exclusive"
        );
    }

    // =========================================================================
    // RFC 6750 Bearer Token Error Code Tests
    // =========================================================================

    #[test]
    fn test_rfc6750_invalid_token_error_code() {
        assert_eq!(OAuthErrorCode::InvalidToken.as_str(), "invalid_token");
        assert_eq!(
            OAuthErrorCode::InvalidToken.status_code(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// RFC 6750 §3.1: `ServiceError::Api` carrying `invalid_token` (emitted by
    /// `extract_resource_token` for session JWT failures) MUST be preserved by
    /// `into_oauth_response()` instead of falling through to a 500
    /// `server_error`.
    #[test]
    fn test_api_invalid_token_preserved_in_oauth_response() {
        let err = ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid or expired access token",
        );
        let (status, json) = err.into_oauth_response();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json.error, "invalid_token");
        assert_eq!(
            json.error_description,
            Some("Invalid or expired access token".to_string())
        );
    }

    /// Non-401 `ServiceError::Api` errors carry internal codes (e.g.
    /// `issuer_error` from org-issuer construction) that are not registered
    /// OAuth error codes. `into_oauth_response()` must keep collapsing them to
    /// the generic 500 `server_error` rather than leaking them from the token
    /// endpoint.
    #[test]
    fn test_api_non_401_still_collapses_to_server_error() {
        let err = ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "issuer_error",
            "Failed to construct the organization issuer",
        );
        let (status, json) = err.into_oauth_response();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.error, "server_error");
        assert!(
            json.error_description
                .as_deref()
                .is_none_or(|d| !d.contains("issuer")),
            "internal error detail must not leak: {json:?}"
        );
    }

    /// RFC 9449 §7.2: `ServiceError::ApiWithHeaders` carrying a 401
    /// `use_dpop_nonce` (emitted by `extract_resource_token` when a DPoP-bound
    /// token replays a consumed nonce) MUST be preserved by
    /// `into_oauth_response()` instead of falling through to a 500
    /// `server_error`. The headers themselves cannot be conveyed through the
    /// tuple return type — callers that need them extract them separately —
    /// but the error code and status must survive.
    #[test]
    fn test_api_with_headers_401_preserved_in_oauth_response() {
        let err = ServiceError::api_with_header(
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "Authorization server requires nonce in DPoP proof",
            ("DPoP-Nonce", "fresh-nonce-value"),
        );
        let (status, json) = err.into_oauth_response();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json.error, "use_dpop_nonce");
        assert_eq!(
            json.error_description,
            Some("Authorization server requires nonce in DPoP proof".to_string())
        );
    }

    /// Non-401 `ServiceError::ApiWithHeaders` errors, like non-401
    /// `ServiceError::Api`, carry internal codes that are not registered OAuth
    /// error codes and must collapse to the generic 500 `server_error`.
    #[test]
    fn test_api_with_headers_non_401_still_collapses_to_server_error() {
        let err = ServiceError::api_with_header(
            StatusCode::INTERNAL_SERVER_ERROR,
            "issuer_error",
            "Failed to construct the organization issuer",
            ("DPoP-Nonce", "should-not-leak"),
        );
        let (status, json) = err.into_oauth_response();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.error, "server_error");
        assert!(
            json.error_description
                .as_deref()
                .is_none_or(|d| !d.contains("issuer")),
            "internal error detail must not leak: {json:?}"
        );
    }

    // =========================================================================
    // ServiceError::api_with_header — RFC 9449 DPoP-Nonce on resource 401s
    // =========================================================================

    /// `api_with_header` produces the same `{"code", "message"}` body as `api`,
    /// plus the named response header. This is the shape `extract_resource_token`
    /// relies on to return a `use_dpop_nonce` error with a fresh `DPoP-Nonce`
    /// header (RFC 9449) at a protected resource endpoint.
    #[tokio::test]
    async fn test_api_with_header_emits_header_and_body() {
        use axum::body::to_bytes;

        let err = ServiceError::api_with_header(
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "Authorization server requires nonce in DPoP proof",
            ("DPoP-Nonce", "fresh-nonce-value"),
        );
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Header name lookup is case-insensitive; "DPoP-Nonce" is stored as
        // "dpop-nonce" and must be retrievable either way.
        let nonce = response
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!(nonce, "fresh-nonce-value");

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "use_dpop_nonce");
        assert_eq!(
            json["message"],
            "Authorization server requires nonce in DPoP proof"
        );
    }

    /// `api_with_header` with an uppercase header name still produces a header
    /// that clients reading the canonical lowercase form can find (HTTP headers
    /// are case-insensitive per RFC 9230 §4.4.1).
    #[test]
    fn test_api_with_header_name_case_insensitive() {
        let err = ServiceError::api_with_header(
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "nonce required",
            ("DPoP-Nonce", "abc"),
        );
        let response = err.into_response();
        let headers = response.headers();
        assert!(headers.get("dpop-nonce").is_some());
        assert!(headers.get("DPoP-Nonce").is_some());
        assert!(headers.get("DPOP-NONCE").is_some());
    }

    /// `ApiWithHeaders` is not retryable — only `OccConflict` is. Guards the
    /// retry contract used by `with_dsql_retry!`.
    #[test]
    fn test_api_with_headers_is_not_retryable() {
        use crate::db::pool::RetryableError;

        let err = ServiceError::api_with_header(
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "nonce required",
            ("DPoP-Nonce", "abc"),
        );
        assert!(!err.is_retryable());
    }
}
