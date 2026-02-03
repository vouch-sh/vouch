// SPDX-License-Identifier: BUSL-1.1
//! AWS integration service.
//!
//! This module provides OIDC token issuance for AWS STS `AssumeRoleWithWebIdentity`.
//!
//! # How it works
//!
//! 1. User authenticates with Vouch using FIDO2/WebAuthn
//! 2. User requests an AWS token via `/v1/credentials/aws/token`
//! 3. Vouch issues an OIDC ID token with the user's identity
//! 4. User exchanges the token with AWS STS for temporary credentials
//!
//! # AWS Configuration
//!
//! The AWS IAM role must be configured to trust the Vouch OIDC provider:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/vouch.example.com"},
//!     "Action": "sts:AssumeRoleWithWebIdentity",
//!     "Condition": {
//!       "StringEquals": {
//!         "vouch.example.com:aud": "https://vouch.example.com"
//!       }
//!     }
//!   }]
//! }
//! ```

use crate::config::ServerConfig;
use crate::db::{self, Authenticator, Pool};
use crate::services::oidc::OidcSigningKey;
use vouch_common::oidc::OidcIdTokenClaimsBuilder;

/// Error types for AWS integration operations.
#[derive(Debug, thiserror::Error)]
pub enum AwsError {
    /// User session does not have an associated authenticator.
    #[error("Session does not have a security key - please register one first")]
    NoAuthenticator,

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),

    /// Failed to build OIDC claims.
    #[error("Failed to build claims: {0}")]
    ClaimsBuild(String),

    /// Failed to sign the token.
    #[error("Failed to sign token: {0}")]
    TokenSign(String),
}

/// Result type for AWS integration operations.
pub type AwsResult<T> = Result<T, AwsError>;

/// Result of issuing an AWS OIDC token.
#[derive(Debug)]
pub struct AwsTokenResult {
    /// The signed OIDC ID token.
    pub id_token: String,
    /// Token validity in seconds.
    pub expires_in: u64,
}

/// AWS integration service.
///
/// Provides OIDC token issuance for AWS STS `AssumeRoleWithWebIdentity`.
pub struct AwsService<'a> {
    db: &'a Pool,
    config: &'a ServerConfig,
    oidc_key: &'a OidcSigningKey,
}

impl<'a> AwsService<'a> {
    /// Create a new AWS service instance.
    #[must_use]
    pub fn new(db: &'a Pool, config: &'a ServerConfig, oidc_key: &'a OidcSigningKey) -> Self {
        Self {
            db,
            config,
            oidc_key,
        }
    }

    /// Issue an OIDC ID token for AWS STS.
    ///
    /// The token can be used with `AssumeRoleWithWebIdentity` to get temporary
    /// AWS credentials. The token includes:
    /// - `sub`: User email
    /// - `aud`: Vouch issuer URL (AWS matches against the OIDC provider)
    /// - `iss`: Vouch issuer URL
    /// - `hardware_aaguid`: FIDO2 authenticator AAGUID (for hardware key verification)
    /// - `hd`: Google Workspace hosted domain (for domain-based access control)
    ///
    /// # Arguments
    /// * `user_email` - The authenticated user's email
    /// * `authenticator_id` - The authenticator ID from the session (for AAGUID lookup)
    /// * `hd` - The user's organization domain (Google Workspace hosted domain)
    pub async fn issue_token(
        &self,
        user_email: &str,
        authenticator_id: Option<&str>,
        hd: Option<String>,
    ) -> AwsResult<AwsTokenResult> {
        // Get authenticator info for AAGUID
        let authenticator = self.get_authenticator(authenticator_id).await?;

        // Token validity matches session duration
        let expires_in = self.config.session_hours * 3600;

        // Build OIDC claims
        // For AWS, the audience is the issuer URL (AWS matches against the OIDC provider)
        let id_claims = OidcIdTokenClaimsBuilder::for_aws(&self.config.base_url, user_email)
            .hardware_aaguid(authenticator.and_then(|a| a.aaguid))
            .hd(hd)
            .valid_for_seconds(expires_in)
            .build()
            .map_err(|e| AwsError::ClaimsBuild(e.to_string()))?;

        // Sign the token with ES256
        let id_token = self
            .oidc_key
            .sign_jwt(&id_claims)
            .map_err(|e| AwsError::TokenSign(e.to_string()))?;

        tracing::info!("Issued AWS OIDC token for {}", user_email);

        Ok(AwsTokenResult {
            id_token,
            expires_in,
        })
    }

    /// Get authenticator info for AAGUID lookup.
    async fn get_authenticator(
        &self,
        authenticator_id: Option<&str>,
    ) -> AwsResult<Option<Authenticator>> {
        let Some(id) = authenticator_id else {
            return Err(AwsError::NoAuthenticator);
        };

        db::get_authenticator_by_id(self.db, id)
            .await
            .map_err(AwsError::Database)
    }
}
