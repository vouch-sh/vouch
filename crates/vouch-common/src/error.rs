// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error types for vouch.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur in vouch operations.
#[derive(Debug, Error)]
pub enum VouchError {
    /// No valid session token found.
    #[error("not authenticated")]
    NotAuthenticated,

    /// Session token has expired.
    #[error("session expired")]
    SessionExpired,

    /// No `YubiKey` or FIDO2 device found.
    #[error("no YubiKey found - please insert your YubiKey")]
    NoDevice,

    /// Multiple devices found, need to select one.
    #[error("multiple devices found - please ensure only one YubiKey is connected")]
    MultipleDevices,

    /// FIDO2 protocol error.
    #[error("FIDO2 error: {0}")]
    Fido2(String),

    /// User verification failed (wrong PIN, cancelled, etc.).
    #[error("user verification failed: {0}")]
    UserVerification(String),

    /// Server returned an error.
    #[error("server error: {0}")]
    Server(String),

    /// Network error communicating with server.
    #[error("network error: {0}")]
    Network(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// User not found.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Credential not found.
    #[error("credential not found")]
    CredentialNotFound,
}

/// API error response from server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    /// Error code (e.g., `not_authenticated`, `invalid_credential`).
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

impl ApiError {
    /// Create a new API error.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
