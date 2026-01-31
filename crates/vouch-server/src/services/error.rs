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
    /// The request is missing a required parameter.
    InvalidRequest,
    /// Client authentication failed.
    InvalidClient,
    /// The provided authorization grant is invalid.
    InvalidGrant,
    /// The client is not authorized to use this grant type.
    UnauthorizedClient,
    /// The authorization grant type is not supported.
    UnsupportedGrantType,
    /// The requested scope is invalid or unknown.
    InvalidScope,
    /// The authorization server encountered an unexpected condition.
    ServerError,
    /// The authorization server is temporarily unavailable.
    TemporarilyUnavailable,
    /// The authorization request is still pending (RFC 8628).
    AuthorizationPending,
    /// Polling too frequently (RFC 8628).
    SlowDown,
    /// The device code has expired (RFC 8628).
    ExpiredToken,
    /// Access denied by the user (RFC 8628).
    AccessDenied,
    /// Invalid DPoP proof (RFC 9449).
    InvalidDpopProof,
    /// DPoP nonce required (RFC 9449).
    UseDpopNonce,
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
        };
        write!(f, "{s}")
    }
}

impl OAuthErrorCode {
    /// Get the appropriate HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest | Self::InvalidScope | Self::InvalidDpopProof => {
                StatusCode::BAD_REQUEST
            }
            Self::InvalidClient | Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant
            | Self::UnsupportedGrantType
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
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
        }
    }
}

/// OAuth 2.0 error response (RFC 6749 Section 5.2).
#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    /// Error code.
    pub error: String,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// URI with more information.
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

    /// Convert to a standard API error response.
    pub fn into_api_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(entity) => (StatusCode::NOT_FOUND, format!("{entity} not found")),
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, (*msg).to_string()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, (*msg).to_string()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
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

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        self.into_api_response()
    }
}

/// Result type for service operations.
pub type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
#[allow(clippy::panic)]
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
}
