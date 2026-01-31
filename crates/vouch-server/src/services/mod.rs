// SPDX-License-Identifier: BUSL-1.1
//! Service layer for business logic.
//!
//! This module contains business logic services that are called by HTTP handlers.
//! Services encapsulate domain logic and RFC-compliant protocol implementations,
//! while handlers focus on HTTP concerns (extraction, response formatting).
//!
//! # Architecture
//!
//! ```text
//! HTTP Request
//!     │
//!     ▼
//! ┌─────────────────┐
//! │    Handler      │  ← Extract HTTP-specific data (headers, cookies, form)
//! │  (thin layer)   │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Service      │  ← Business logic, RFC compliance, validation
//! │ (domain logic)  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   Database      │  ← Persistence operations
//! │   (db module)   │
//! └─────────────────┘
//! ```
//!
//! # Available Services
//!
//! - [`OidcService`] - OpenID Connect provider (RFC 6749, 7636, 8628, 8693, 9449)
//!
//! # Error Handling
//!
//! Services return [`ServiceError`] which can be converted to protocol-appropriate
//! responses (OAuth, SCIM, or standard HTTP errors).

pub mod error;
pub mod oidc;

// Service modules will be added here as they are implemented:
// pub mod scim;
// pub mod auth;
// pub mod credentials;
// pub mod applications;
// pub mod enrollment;
// pub mod github;

pub use error::{
    OAuthErrorCode, OAuthErrorResponse, ScimErrorResponse, ServiceError, ServiceResult,
};
pub use oidc::{
    AuthCodeExchangeParams, AuthCodeExchangeResult, AuthenticatedClient, AuthorizationCodeParams,
    ClientAuthError, ClientCredentials, IntrospectionResult, OidcDiscoveryDocument,
    RevocationResult, TokenExchangeParams, TokenExchangeResult, ValidatedAuthRequest,
    build_discovery_document, build_jwks, check_client_access,
};
