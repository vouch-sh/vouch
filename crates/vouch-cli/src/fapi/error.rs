// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error types for FAPI 2.0 client operations.

use thiserror::Error;

/// Errors that can occur during FAPI 2.0 client operations.
#[derive(Debug, Error)]
pub enum FapiError {
    /// Failed to generate an ES256 keypair.
    #[error("failed to generate ES256 keypair: {0}")]
    KeyGeneration(String),

    /// Failed to load a key from disk.
    #[error("failed to load key from disk: {0}")]
    KeyLoad(String),

    /// Failed to save a key to disk.
    #[error("failed to save key to disk: {0}")]
    KeySave(String),

    /// Key file has an invalid format.
    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Failed to sign a JWT.
    #[error("failed to sign JWT: {0}")]
    JwtSigning(String),

    /// JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Failed to compute a JWK thumbprint per RFC 7638.
    #[error("failed to compute JWK thumbprint: {0}")]
    ThumbprintComputation(String),

    /// Failed to access the OS keychain.
    #[error("keychain access error: {0}")]
    KeychainAccess(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_fapi_error_display_key_generation() {
        let err = FapiError::KeyGeneration("rng failure".to_string());
        assert!(err.to_string().contains("generate ES256 keypair"));
        assert!(err.to_string().contains("rng failure"));
    }

    #[test]
    fn test_fapi_error_display_key_load() {
        let err = FapiError::KeyLoad("file not found".to_string());
        assert!(err.to_string().contains("load key from disk"));
    }

    #[test]
    fn test_fapi_error_display_key_save() {
        let err = FapiError::KeySave("permission denied".to_string());
        assert!(err.to_string().contains("save key to disk"));
    }

    #[test]
    fn test_fapi_error_display_invalid_key_format() {
        let err = FapiError::InvalidKeyFormat("bad base64".to_string());
        assert!(err.to_string().contains("invalid key format"));
    }

    #[test]
    fn test_fapi_error_display_jwt_signing() {
        let err = FapiError::JwtSigning("key error".to_string());
        assert!(err.to_string().contains("sign JWT"));
    }

    #[test]
    fn test_fapi_error_display_thumbprint() {
        let err = FapiError::ThumbprintComputation("hash failed".to_string());
        assert!(err.to_string().contains("JWK thumbprint"));
    }

    #[test]
    fn test_fapi_error_display_keychain_access() {
        let err = FapiError::KeychainAccess("no backend available".to_string());
        assert!(err.to_string().contains("keychain access error"));
        assert!(err.to_string().contains("no backend available"));
    }

    #[test]
    fn test_fapi_error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json {").unwrap_err();
        let err = FapiError::from(json_err);
        assert!(matches!(err, FapiError::Serialization(_)));
    }
}
