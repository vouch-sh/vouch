// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error types for HTTP message signatures.

/// Errors that can occur during HTTP message signature operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpSigError {
    /// A required component is missing from the message.
    #[error("missing component: {0}")]
    MissingComponent(String),

    /// A component value is invalid or cannot be resolved.
    #[error("invalid component: {0}")]
    InvalidComponent(String),

    /// Signature base construction failed.
    #[error("signature base construction failed: {0}")]
    BaseConstruction(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// The signature bytes are structurally invalid.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// A required HTTP header is missing.
    #[error("missing header: {0}")]
    MissingHeader(String),

    /// Structured field value parsing failed.
    #[error("SFV parse error: {0}")]
    SfvParse(String),

    /// The requested algorithm is not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The signature has expired or its timestamp is outside the allowed window.
    #[error("signature expired: {0}")]
    Expired(String),

    /// The Content-Digest header does not match the body.
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
}
