// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7523 §2.2: JWT Profile for OAuth 2.0 Client Authentication (`private_key_jwt`).
//!
//! Clients authenticate at the token endpoint using a signed JWT assertion
//! instead of a shared secret. Used at `/oauth/token`, `/oauth/par`,
//! `/oauth/introspect`, and `/oauth/revoke`.
//!
//! ## Standards
//!
//! - [RFC 7521 - Assertion Framework](https://www.rfc-editor.org/rfc/rfc7521)
//! - [RFC 7523 §2.2 - JWT Client Authentication](https://www.rfc-editor.org/rfc/rfc7523#section-2.2)

pub mod client_auth;
pub mod jwks;
pub mod validate;

pub use jwks::{find_matching_key_with_refresh_client, resolve_client_jwks};
