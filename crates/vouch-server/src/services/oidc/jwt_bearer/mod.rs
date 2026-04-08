// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7523: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants.
//!
//! This module implements:
//! - **JWT Client Authentication (`private_key_jwt`)** — Clients authenticate at the token
//!   endpoint using a signed JWT assertion instead of a shared secret.
//! - **JWT Authorization Grant (`jwt-bearer`)** — A JWT from a trusted external issuer is
//!   exchanged directly for a Vouch access token.
//!
//! ## Standards
//!
//! - [RFC 7521 - Assertion Framework](https://www.rfc-editor.org/rfc/rfc7521)
//! - [RFC 7523 - JWT Profile](https://www.rfc-editor.org/rfc/rfc7523)

pub mod client_auth;
pub mod grant;
pub mod jwks;
pub mod validate;

pub use client_auth::commit_jti;
pub use jwks::{
    find_matching_key_with_refresh_client, find_matching_key_with_refresh_issuer,
    resolve_client_jwks,
};
pub use validate::SUPPORTED_ALGORITHMS;
