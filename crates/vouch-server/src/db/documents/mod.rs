// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Document type definitions for the encrypted document store.
//!
//! Each module defines serializable document types that implement
//! [`DocumentType`] for storage in the 3-table document store.

pub(crate) mod audit;
pub(crate) mod authenticator;
pub(crate) mod authorization_code;
pub(crate) mod challenge_state;
pub(crate) mod credential;
pub(crate) mod device_auth;
pub(crate) mod dpop;
pub(crate) mod github;
pub(crate) mod jwks_cache;
pub(crate) mod jwt_assertion_jti;
pub(crate) mod jwt_issuer;
pub(crate) mod oauth;
pub(crate) mod organization;
pub(crate) mod par;
pub(crate) mod pending_oauth;
pub(crate) mod posture_policy;
pub(crate) mod scim;
pub(crate) mod session;
pub(crate) mod user;
