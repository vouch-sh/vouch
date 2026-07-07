// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error types for FAPI 2.0 client operations.

/// Errors that can occur during FAPI 2.0 client operations.
#[derive(Debug)]
pub enum FapiError {
    /// Failed to generate an ES256 keypair.
    KeyGeneration(String),

    /// Failed to load a key from disk.
    KeyLoad(String),

    /// Failed to save a key to disk.
    KeySave(String),

    /// Key file has an invalid format.
    InvalidKeyFormat(String),

    /// Failed to sign a JWT.
    JwtSigning(String),

    /// JSON serialization or deserialization failure.
    Serialization(serde_json::Error),

    /// Failed to compute a JWK thumbprint per RFC 7638.
    ThumbprintComputation(String),

    /// Failed to access the OS keychain.
    KeychainAccess(String),
}

impl std::fmt::Display for FapiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::KeyGeneration(e) => {
                crate::tr_args!("fapi-err-key-generation", error = e.as_str())
            }
            Self::KeyLoad(e) => crate::tr_args!("fapi-err-key-load", error = e.as_str()),
            Self::KeySave(e) => crate::tr_args!("fapi-err-key-save", error = e.as_str()),
            Self::InvalidKeyFormat(e) => {
                crate::tr_args!("fapi-err-invalid-key-format", error = e.as_str())
            }
            Self::JwtSigning(e) => crate::tr_args!("fapi-err-jwt-signing", error = e.as_str()),
            Self::Serialization(e) => {
                crate::tr_args!("fapi-err-serialization", error = e.to_string())
            }
            Self::ThumbprintComputation(e) => {
                crate::tr_args!("fapi-err-thumbprint", error = e.as_str())
            }
            Self::KeychainAccess(e) => crate::tr_args!("fapi-err-keychain", error = e.as_str()),
        };
        f.write_str(&msg)
    }
}

impl std::error::Error for FapiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(e) => Some(e),
            Self::KeyGeneration(_)
            | Self::KeyLoad(_)
            | Self::KeySave(_)
            | Self::InvalidKeyFormat(_)
            | Self::JwtSigning(_)
            | Self::ThumbprintComputation(_)
            | Self::KeychainAccess(_) => None,
        }
    }
}

impl From<serde_json::Error> for FapiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
