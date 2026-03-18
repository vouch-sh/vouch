// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cryptographic primitives and signing services.
//!
//! This module groups all cryptographic operations into a single audit boundary:
//! JWT signing/verification, SSH certificate authority, WebAuthn COSE verification,
//! NitroTPM-attested KMS decryption, and encoding utilities.

#[cfg(any(test, feature = "test-utils"))]
pub mod attestation_chain;
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod attestation_chain;

#[cfg(any(test, feature = "test-utils"))]
pub mod ber;
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod ber;
pub mod cose;
pub(crate) mod document_crypto;
pub mod hash;
pub(crate) mod jwt;
pub(crate) mod kms_signer;
pub(crate) mod pem;
pub mod ssh_ca;
pub mod tpm_decrypt;
pub mod webauthn_verify;

pub use hash::{generate_challenge, generate_random_bytes, hash_token};
