// SPDX-License-Identifier: BUSL-1.1
//! OIDC Provider endpoints for application integration.
//!
//! This module implements a standard OpenID Connect 1.0 provider, allowing
//! applications to integrate with Vouch using off-the-shelf OIDC libraries.
//!
//! ## Endpoints
//!
//! - `GET /.well-known/openid-configuration` - Discovery document
//! - `GET /oauth/jwks` - Public keys for token verification
//! - `GET /oauth/authorize` - Authorization endpoint
//! - `POST /oauth/token` - Token endpoint
//! - `GET /oauth/userinfo` - User info endpoint
//! - `POST /oauth/revoke` - Token revocation (RFC 7009)
//! - `POST /oauth/introspect` - Token introspection (RFC 7662)
//!
//! ## Token Claims
//!
//! ID tokens include standard OIDC claims plus Vouch-specific claims:
//! - `hardware_verified: true` - Indicates hardware authentication was used
//! - `hardware_aaguid` - The AAGUID of the authenticator used

mod authorize;
mod discovery;
mod introspect;
mod token;
mod userinfo;

// Re-export handler functions
pub use authorize::authorize;
pub use discovery::{discovery, jwks};
pub use introspect::{introspect, revoke};
pub use token::token;
pub use userinfo::userinfo;

#[cfg(test)]
mod tests;
