//! Error types for vouch

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VouchError {
    #[error("not authenticated - run 'vouch login' first")]
    NotAuthenticated,

    #[error("session expired - run 'vouch login' to refresh")]
    SessionExpired,

    #[error("no authenticator registered - run 'vouch register' first")]
    NoAuthenticator,

    #[error("authenticator error: {0}")]
    AuthenticatorError(String),

    #[error("delegation not found: {0}")]
    DelegationNotFound(String),

    #[error("delegation expired")]
    DelegationExpired,

    #[error("delegation revoked")]
    DelegationRevoked,

    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("credential issuance failed: {0}")]
    CredentialIssuanceFailed(String),

    #[error("server error: {0}")]
    ServerError(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("agent not running - start with 'vouch agent start'")]
    AgentNotRunning,
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            error: error.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}
