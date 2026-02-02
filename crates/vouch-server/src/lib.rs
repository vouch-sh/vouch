// SPDX-License-Identifier: BUSL-1.1
//! Vouch identity server library.
//!
//! This crate provides the Vouch identity server with OIDC provider,
//! WebAuthn authentication, and credential issuance.

pub mod cleanup;
pub mod config;
pub mod db;
pub mod dpop;
pub mod extractors;
pub mod handlers;
pub mod services;
pub mod ssh_ca;
pub mod webauthn_verify;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-export main types
pub use config::ServerConfig;
pub use db::User;
pub use webauthn_verify::{CoseVerifier, RealCoseVerifier, VerificationResult, VerifyError};

#[cfg(any(test, feature = "test-utils"))]
pub use webauthn_verify::TestCoseVerifier;

use db::Pool;

/// Shared application state.
pub struct AppState {
    /// Database connection pool.
    pub db: Pool,
    /// Server configuration.
    pub config: ServerConfig,
    /// WebAuthn instance.
    pub webauthn: webauthn_rs::Webauthn,
    /// SSH Certificate Authority (optional, None if disabled).
    pub ssh_ca: Option<ssh_ca::SshCa>,
    /// RFC 9449 DPoP state (nonce manager, JTI cache).
    pub dpop: dpop::DpopState,
    /// OIDC signing key for ES256 JWT signing.
    pub oidc_key: services::oidc::OidcSigningKey,
    /// GitHub App for credential issuance (optional, None if not configured).
    pub github_app: Option<std::sync::Arc<services::integrations::github::GitHubApp>>,
}
