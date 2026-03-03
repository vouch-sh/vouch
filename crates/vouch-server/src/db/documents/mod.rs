// SPDX-License-Identifier: BUSL-1.1
//! Document type definitions for the encrypted document store.
//!
//! Each module defines serializable document types that implement
//! [`DocumentType`] for storage in the 3-table document store.

pub mod audit;
pub mod authenticator;
pub mod authorization_code;
pub mod challenge_state;
pub mod credential;
pub mod device_auth;
pub mod dpop;
pub mod github;
pub mod jwt_assertion_jti;
pub mod jwt_issuer;
pub mod oauth;
pub mod organization;
pub mod par;
pub mod pending_oauth;
pub mod scim;
pub mod session;
pub mod user;
