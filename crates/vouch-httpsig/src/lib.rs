// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 HTTP Message Signatures and RFC 9530 Digest Fields.
//!
//! This crate provides signing and verification of HTTP messages per
//! [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) with content integrity
//! via [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) Content-Digest.
//!
//! ## Supported algorithms
//!
//! - `ecdsa-p256-sha256` — ECDSA with P-256 and SHA-256 (DER-encoded signatures)
//! - `ed25519` — Ed25519 (raw 64-byte signatures)
//! - `hmac-sha256` — HMAC with SHA-256
//! - `rsa-pss-sha512` — RSASSA-PSS with SHA-512
//! - `rsa-v1_5-sha256` — RSASSA-PKCS1-v1.5 with SHA-256

pub mod algorithm;
pub mod component;
pub mod digest;
pub mod error;
#[cfg(feature = "axum")]
pub mod middleware;
pub mod sfv;
pub mod sig_policy;
pub mod sign;
pub mod signature_base;
pub mod signature_params;
pub mod verify;

pub use algorithm::{SigningAlgorithm, VerifyingAlgorithm};
pub use component::ComponentIdentifier;
pub use digest::DigestAlgorithm;
pub use error::HttpSigError;
pub use sig_policy::requires_signature;
pub use sign::SignatureBuilder;
pub use signature_params::SignatureParams;
pub use verify::verify_request_signature;
