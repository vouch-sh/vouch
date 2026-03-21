// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FAPI 2.0 client crypto infrastructure for vouch-cli.
//!
//! This module provides the cryptographic primitives required for FAPI 2.0
//! (Financial-grade API Security Profile) compliance on the client side:
//!
//! - **ES256 key management** ([`key`]): Generate, persist, and load P-256 ECDSA
//!   keypairs used for DPoP and client assertions.
//! - **DPoP proofs** ([`dpop`]): RFC 9449 Demonstrating Proof of Possession JWTs
//!   that bind access tokens to a specific client key.
//! - **Client assertions** ([`client_assertion`]): RFC 7523 `private_key_jwt`
//!   assertions for client authentication at the token endpoint.
//! - **Interaction tracking** ([`interaction`]): FAPI `x-fapi-interaction-id`
//!   and `x-fapi-end-user-present` header generation.
//! - **Keychain storage** ([`key_store`]): OS keychain backend for encrypted-at-rest
//!   key storage (macOS Keychain, Linux Secret Service, Windows Credential Manager).
//! - **Error types** ([`error`]): Typed errors for all FAPI operations.

pub mod client_assertion;
pub mod dpop;
pub mod error;
pub mod httpsig;
pub mod interaction;
pub mod key;
pub mod key_store;
pub mod registration;

// Re-export the most commonly used types for convenience
pub use client_assertion::{ClientAssertion, ClientAssertionBuilder};
pub use dpop::DpopProofBuilder;
pub use error::FapiError;
pub use interaction::FapiInteraction;
pub use key::{ClientKey, PublicEcJwk};
pub use registration::RegistrationResult;
