// SPDX-License-Identifier: BUSL-1.1
//! Cryptographic primitives and signing services.
//!
//! This module groups all cryptographic operations into a single audit boundary:
//! JWT signing/verification, SSH certificate authority, WebAuthn COSE verification,
//! TPM/KMS envelope decryption, and encoding utilities.

pub(crate) mod ber;
pub(crate) mod jwt;
pub(crate) mod pem;
pub mod ssh_ca;
pub mod tpm_decrypt;
pub mod webauthn_verify;
