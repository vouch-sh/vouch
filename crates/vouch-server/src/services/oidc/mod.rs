// SPDX-License-Identifier: Apache-2.0 OR MIT
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
//! - [RFC 7521 - Assertion Framework](https://www.rfc-editor.org/rfc/rfc7521)
//! - [RFC 7523 - JWT Profile for Client Auth and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523)
//! - [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
//! - [RFC 9101 - JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101)
//! - [RFC 9126 - Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
//! - [RFC 8176 - Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176)
//! - [RFC 8707 - Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707)
//! - [RFC 9396 - Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
//! - [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
//! - [RFC 9700 - Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
//! - [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
//! - [RFC 7591 - Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
//! - [RFC 7592 - Dynamic Client Registration Management](https://www.rfc-editor.org/rfc/rfc7592)
//! - [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
//!
//! ## Module Organization
//!
//! - [`fapi`] - FAPI 2.0 Security Profile validation
//! - [`keys`] - ES256 signing key management and JWK export
//! - [`discovery`] - OIDC Discovery document and JWKS generation
//! - [`protected_resource`] - Protected Resource Metadata (RFC 9728)
//! - [`authorization`] - Authorization code issuance and validation
//! - [`token`] - Token endpoint logic (auth code, device code grants)
//! - [`grant_type`] - OAuth `grant_type` wire values (single source of truth)
//! - [`client_credentials`] - Client credentials grant (RFC 6749 Section 4.4)
//! - [`exchange`] - Token exchange (RFC 8693)
//! - [`jwt_bearer`] - JWT client authentication and bearer grants (RFC 7523)
//! - [`jar`] - JWT-Secured Authorization Request validation (RFC 9101)
//! - [`amr`] - Authentication method references (RFC 8176)
//! - [`authorization_details`] - Rich authorization requests (RFC 9396)
//! - [`claims`] - OIDC token claims for cloud identity federation
//! - [`dpop`] - DPoP proof validation (RFC 9449)
//! - [`fido2_grant`] - FIDO2 assertion grant (RFC 6749 Section 4.5)
//! - [`introspection`] - Token introspection and revocation
//! - [`registration`] - Dynamic client registration (RFC 7591/7592)
//! - [`resource`] - Resource indicators (RFC 8707)
//! - [`scope`] - OAuth 2.0 scope types (RFC 6749 Section 3.3)

pub mod authorization;
pub mod authorization_details;
pub mod claims;
pub mod client_credentials;
pub mod discovery;
pub mod dpop;
pub mod exchange;
pub mod fapi;
pub mod fido2_grant;
pub(crate) mod grant_type;
pub mod introspection;
pub mod jar;
pub mod jarm;
pub mod jwt_bearer;
pub mod keys;
pub(crate) mod mtls;
pub mod org_keys;
pub mod protected_resource;
pub mod registration;
pub mod resource;
pub mod scope;
pub mod token;

// Re-export commonly used types
pub use authorization::{AuthorizationCodeParams, ValidatedAuthRequest, check_client_access};
pub use authorization_details::AuthorizationDetails;
pub use claims::{
    AwsSessionTags, ClaimsBuildError, CnfClaim, OidcIdTokenClaims, OidcIdTokenClaimsBuilder,
};
pub use discovery::{OidcDiscoveryDocument, build_discovery_document, build_jwks};
pub use dpop::{DpopError, ValidatedDpopProof};
pub use exchange::{TokenExchangeParams, TokenExchangeResult};
pub use introspection::{IntrospectionResult, RevocationResult};
pub use keys::{EcJwk, Jwk, OidcRsaSigningKey, OidcSigningKey, RsaJwk};
pub use org_keys::{
    Operator, OrgKeySetSnapshot, OrgKeys, OrgKeysCache, RevokeOutcome, RotateOutcome,
    emergency_rotate_org_keys, org_issuer_or_base, org_jwks, resolve_org_keys,
    revoke_org_previous_keys, rotate_org_keys,
};
pub(crate) use org_keys::{OrgKeyPanel, org_key_panel};
pub use protected_resource::{
    PROTECTED_RESOURCE_PREFIXES, ProtectedResourceMetadata, SIGNED_METADATA_TYP,
    SubPathClassification, WELL_KNOWN_SUFFIX, build_protected_resource_metadata, classify_sub_path,
};
pub use registration::{
    RegistrationRequest, RegistrationResponse, read_client_configuration, register_client,
};
pub use resource::ResourceUri;
pub use scope::{OAuthScope, ScopeSet};
pub use token::{
    AuthCodeExchangeParams, AuthCodeExchangeResult, AuthenticatedClient, ClientAuthError,
    ClientCredentials,
};
