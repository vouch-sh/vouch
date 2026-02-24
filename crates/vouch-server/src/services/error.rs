// SPDX-License-Identifier: BUSL-1.1
//! Service layer error types with RFC-compliant conversions.
//!
//! This module provides error types for the service layer that can be
//! converted into appropriate HTTP responses for different protocols:
//! - Standard HTTP error responses
//! - OAuth 2.0 error responses (RFC 6749 Section 5.2)
//! - SCIM error responses (RFC 7644 Section 3.12)

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

    /// Authentication required.
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),

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

    /// SCIM protocol error (RFC 7644 Section 3.12).
    #[error("scim error: {status} {detail}")]
    Scim {
        /// HTTP status code.
        status: u16,
        /// Error detail message.
        detail: String,
        /// SCIM error type (e.g., "invalidValue", "uniqueness").
        scim_type: Option<String>,
    },

    /// Pre-formatted HTTP error from legacy handler code.
    ///
    /// This variant bridges the old `(StatusCode, Json<ApiError>)` handler pattern
    /// with the `ServiceError` type, preserving the original status code, error code,
    /// and message. It enables incremental migration of handlers from the tuple
    /// pattern to `Result<T, ServiceError>` without losing error information.
    #[error("{message}")]
    HttpError {
        /// HTTP status code.
        status: StatusCode,
        /// Machine-readable error code (e.g., "ssh_ca_not_configured").
        code: String,
        /// Human-readable error message.
        message: String,
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

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
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
    /// RFC 6749 Section 5.2: The authorization server encountered an unexpected condition.
    ServerError,
    /// RFC 6749 Section 5.2: The authorization server is temporarily unavailable.
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
            | Self::InvalidRequestObject => StatusCode::BAD_REQUEST,
            Self::InvalidClient | Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::InsufficientUserAuthentication => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::AuthorizationPending
            | Self::SlowDown
            | Self::ExpiredToken
            | Self::AccessDenied => StatusCode::BAD_REQUEST,
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
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
            Self::InvalidTarget => "invalid_target",
            Self::InsufficientUserAuthentication => "insufficient_user_authentication",
            Self::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            Self::InvalidRequestObject => "invalid_request_object",
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

/// SCIM error response (RFC 7644 Section 3.12).
#[derive(Debug, Serialize)]
pub struct ScimErrorResponse {
    /// SCIM schema URIs.
    pub schemas: Vec<String>,
    /// Error detail message.
    pub detail: String,
    /// HTTP status code.
    pub status: String,
    /// SCIM error type.
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
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

    /// Create an HTTP error with a specific status code, error code, and message.
    ///
    /// This is the `ServiceError` equivalent of the legacy `json_error()` helper.
    /// Use this when you need a specific error code in the response body (e.g.,
    /// `"ssh_ca_not_configured"`) that doesn't map cleanly to one of the typed
    /// `ServiceError` variants.
    #[must_use]
    pub fn http(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::HttpError {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Create a SCIM error.
    #[must_use]
    pub fn scim(status: u16, detail: impl Into<String>, scim_type: Option<&str>) -> Self {
        Self::Scim {
            status,
            detail: detail.into(),
            scim_type: scim_type.map(String::from),
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
                    error: "invalid_request".to_string(),
                    error_description: Some(format!("{entity} not found")),
                    error_uri: None,
                }),
            ),
            Self::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                Json(OAuthErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some(msg),
                    error_uri: None,
                }),
            ),
            Self::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                Json(OAuthErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client authentication failed".to_string()),
                    error_uri: None,
                }),
            ),
            Self::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                Json(OAuthErrorResponse {
                    error: "access_denied".to_string(),
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
                    error: "server_error".to_string(),
                    error_description: Some("Internal server error".to_string()),
                    error_uri: None,
                }),
            ),
        }
    }

    /// Convert to a SCIM error response.
    pub fn into_scim_response(self) -> Response {
        let (status, body) = match self {
            Self::Scim {
                status,
                detail,
                scim_type,
            } => (
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail,
                    status: status.to_string(),
                    scim_type,
                },
            ),
            Self::NotFound(entity) => (
                StatusCode::NOT_FOUND,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: format!("{entity} not found"),
                    status: "404".to_string(),
                    scim_type: None,
                },
            ),
            Self::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: msg,
                    status: "400".to_string(),
                    scim_type: Some("invalidValue".to_string()),
                },
            ),
            Self::Conflict(msg) => (
                StatusCode::CONFLICT,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: msg,
                    status: "409".to_string(),
                    scim_type: Some("uniqueness".to_string()),
                },
            ),
            Self::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: "Authentication required".to_string(),
                    status: "401".to_string(),
                    scim_type: None,
                },
            ),
            Self::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: "Permission denied".to_string(),
                    status: "403".to_string(),
                    scim_type: None,
                },
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ScimErrorResponse {
                    schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
                    detail: "Internal server error".to_string(),
                    status: "500".to_string(),
                    scim_type: None,
                },
            ),
        };

        (
            status,
            [("Content-Type", "application/scim+json")],
            Json(body),
        )
            .into_response()
    }

    /// Build a `WWW-Authenticate` header value for RFC 9470 step-up challenges.
    fn build_www_authenticate(acr_values: &Option<String>, max_age: &Option<u64>) -> String {
        let mut parts = vec![
            "Bearer error=\"insufficient_user_authentication\"".to_string(),
            "error_description=\"A recent authentication is required\"".to_string(),
        ];
        if let Some(acr) = acr_values {
            parts.push(format!("acr_values=\"{acr}\""));
        }
        if let Some(age) = max_age {
            parts.push(format!("max_age=\"{age}\""));
        }
        parts.join(", ")
    }

    /// Convert to a standard API error response.
    pub fn into_api_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(entity) => (StatusCode::NOT_FOUND, format!("{entity} not found")),
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, (*msg).to_string()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, (*msg).to_string()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::HttpError {
                status,
                code,
                message,
            } => {
                return (*status, Json(ApiError::new(code.clone(), message.clone())))
                    .into_response();
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
            Self::Database(_) | Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            ),
            Self::OAuth { .. } => return self.into_oauth_response().into_response(),
            Self::Scim { .. } => return self.into_scim_response(),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<(StatusCode, Json<ApiError>)> for ServiceError {
    fn from((status, Json(api_error)): (StatusCode, Json<ApiError>)) -> Self {
        Self::HttpError {
            status,
            code: api_error.code,
            message: api_error.message,
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        self.into_api_response()
    }
}

/// Result type for service operations.
pub type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
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
    fn test_service_error_http_factory() {
        let err = ServiceError::http(
            StatusCode::SERVICE_UNAVAILABLE,
            "ssh_ca_not_configured",
            "SSH CA is not configured",
        );
        match err {
            ServiceError::HttpError {
                status,
                code,
                message,
            } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(code, "ssh_ca_not_configured");
                assert_eq!(message, "SSH CA is not configured");
            }
            _ => panic!("Expected HttpError"),
        }
    }

    #[test]
    fn test_service_error_from_tuple() {
        let tuple = (
            StatusCode::NOT_FOUND,
            Json(ApiError::new("user_not_found", "User not found")),
        );
        let err = ServiceError::from(tuple);
        match err {
            ServiceError::HttpError {
                status,
                code,
                message,
            } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(code, "user_not_found");
                assert_eq!(message, "User not found");
            }
            _ => panic!("Expected HttpError"),
        }
    }

    /// Verify that `ServiceError::HttpError` produces the exact same JSON wire format
    /// as the legacy `json_error()` helper: `{"code": "...", "message": "..."}`.
    #[tokio::test]
    async fn test_http_error_response_format() {
        use axum::body::to_bytes;

        let err = ServiceError::http(StatusCode::NOT_FOUND, "user_not_found", "User not found");
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Must have exactly "code" and "message" fields
        assert_eq!(json["code"], "user_not_found");
        assert_eq!(json["message"], "User not found");
    }

    /// Verify that `From<(StatusCode, Json<ApiError>)>` round-trips correctly
    /// through `IntoResponse`, producing the same format.
    #[tokio::test]
    async fn test_from_tuple_response_format() {
        use axum::body::to_bytes;

        let tuple = (
            StatusCode::FORBIDDEN,
            Json(ApiError::new("insufficient_scope", "Requires admin")),
        );
        let err = ServiceError::from(tuple);
        let response = err.into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["code"], "insufficient_scope");
        assert_eq!(json["message"], "Requires admin");
    }

    /// Verify that standard ServiceError variants produce a JSON body with "error" field.
    #[tokio::test]
    async fn test_standard_error_response_format() {
        use axum::body::to_bytes;

        let err = ServiceError::NotFound("Session");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Session not found");
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

    #[test]
    fn test_service_error_scim_factory() {
        let err = ServiceError::scim(400, "Invalid attribute", Some("invalidValue"));
        match err {
            ServiceError::Scim {
                status,
                detail,
                scim_type,
            } => {
                assert_eq!(status, 400);
                assert_eq!(detail, "Invalid attribute");
                assert_eq!(scim_type, Some("invalidValue".to_string()));
            }
            _ => panic!("Expected Scim error"),
        }
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
}
