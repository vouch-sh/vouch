// SPDX-License-Identifier: BUSL-1.1
//! HTTP request handlers.

pub mod about;
pub mod admin;
pub mod applications;
pub mod auth;
pub mod common;
pub mod credentials;
pub mod device;
pub mod docs;
pub mod enroll;
pub mod enroll_keys;
pub mod home;
pub mod install;
pub mod keys;
pub mod legal;
pub mod oidc;
pub mod scim;

// Re-export commonly used utilities
pub use common::{
    extract_session, extract_session_with_email, generate_challenge, generate_random_bytes,
    hash_token, json_error, validate_registration_attestation,
};
