// SPDX-License-Identifier: BUSL-1.1
//! HTTP request handlers.

pub mod admin;
pub mod applications;
pub mod auth;
pub mod browser_login;
pub(crate) mod common;
pub mod credentials;
pub mod device;
pub mod enroll;
pub mod enroll_keys;
pub mod github;
pub mod home;
pub mod install;
pub mod integrations;
pub mod keys;
pub mod legal;
pub mod oidc;
pub mod scim;

// Re-export commonly used utilities
pub(crate) use common::{
    clear_session_cookie, create_session_cookie, extract_session, extract_session_from_cookie,
    extract_session_with_email, generate_challenge, generate_random_bytes, hash_token, json_error,
    validate_registration_attestation,
};
