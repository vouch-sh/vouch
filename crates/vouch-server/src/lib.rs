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

use sqlx::SqlitePool;

/// Shared application state.
pub struct AppState {
    /// Database connection pool.
    pub db: SqlitePool,
    /// Server configuration.
    pub config: ServerConfig,
    /// WebAuthn instance.
    pub webauthn: webauthn_rs::Webauthn,
    /// SSH Certificate Authority (optional, None if disabled).
    pub ssh_ca: Option<ssh_ca::SshCa>,
    /// RFC 9449 DPoP state (nonce manager, JTI cache).
    pub dpop: dpop::DpopState,
}
