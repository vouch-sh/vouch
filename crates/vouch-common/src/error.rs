// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error types for vouch.

use serde::{Deserialize, Serialize};

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
