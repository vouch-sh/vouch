// SPDX-License-Identifier: BUSL-1.1
//! OIDC Provider service layer.
//!
//! This module implements the business logic for the OpenID Connect 1.0 provider,
//! separating protocol concerns from HTTP handling.
//!
//! ## Standards Implemented
//!
//! - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
//! - [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
//! - [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
//! - [RFC 7009 - Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
//! - [RFC 7662 - Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
//! - [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
//! - [RFC 8693 - Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
//! - [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
//!
//! ## Module Organization
//!
//! - [`keys`] - ES256 signing key management and JWK export
//! - [`discovery`] - OIDC Discovery document and JWKS generation
//! - [`authorization`] - Authorization code issuance and validation
//! - [`token`] - Token endpoint logic (auth code, device code grants)
//! - [`exchange`] - Token exchange (RFC 8693)
//! - [`introspection`] - Token introspection and revocation

pub mod authorization;
pub mod discovery;
pub mod dpop;
pub mod exchange;
pub mod introspection;
pub mod keys;
pub mod scope;
pub mod token;

// Re-export commonly used types
pub use authorization::{AuthorizationCodeParams, ValidatedAuthRequest, check_client_access};
pub use discovery::{OidcDiscoveryDocument, build_discovery_document, build_jwks};
pub use exchange::{TokenExchangeParams, TokenExchangeResult};
pub use introspection::{IntrospectionResult, RevocationResult};
pub use keys::{EcJwk, OidcSigningKey};
pub use scope::{OAuthScope, ScopeSet};
pub use token::{
    AuthCodeExchangeParams, AuthCodeExchangeResult, AuthenticatedClient, ClientAuthError,
    ClientCredentials,
};
