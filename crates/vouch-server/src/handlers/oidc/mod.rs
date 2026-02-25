// SPDX-License-Identifier: BUSL-1.1
//! OIDC Provider endpoints for application integration.
//!
//! This module implements a standard OpenID Connect 1.0 provider, allowing
//! applications to integrate with Vouch using off-the-shelf OIDC libraries.
//!
//! ## Endpoints
//!
//! - `GET /.well-known/openid-configuration` — OIDC Discovery 1.0 Section 4
//! - `GET /oauth/jwks` — RFC 7517 Section 5 (JWK Set)
//! - `GET /oauth/authorize` — RFC 6749 Section 3.1 (Authorization Endpoint)
//! - `POST /oauth/token` — RFC 6749 Section 3.2 (Token Endpoint)
//! - `GET /oauth/userinfo` — OIDC Core 1.0 Section 5.3 (UserInfo Endpoint)
//! - `POST /oauth/revoke` — RFC 7009 Section 2 (Token Revocation)
//! - `POST /oauth/introspect` — RFC 7662 Section 2 (Token Introspection)
//!
//! ## Token Claims
//!
//! ID tokens include standard OIDC claims (OIDC Core 1.0 Section 5.1) plus
//! Vouch-specific claims:
//! - `hardware_verified: true` — Indicates hardware authentication was used
//! - `hardware_aaguid` — The AAGUID of the authenticator used

mod authorize;
pub(crate) mod client_auth;
mod discovery;
mod fido2_challenge;
mod introspect;
mod par;
mod register;
mod token;
mod userinfo;

// Re-export handler functions
pub use authorize::authorize;
pub use discovery::{discovery, jwks};
pub use fido2_challenge::fido2_challenge;
pub use introspect::{introspect, revoke};
pub use par::par;
pub use register::register;
pub use token::token;
pub use userinfo::userinfo;

#[cfg(test)]
mod tests;
