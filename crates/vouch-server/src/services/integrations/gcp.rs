// SPDX-License-Identifier: BUSL-1.1
//! GCP integration service.
//!
//! This module provides OIDC token issuance for GCP Workload Identity Federation.
//!
//! # How it works
//!
//! 1. User authenticates with Vouch using FIDO2/WebAuthn
//! 2. User requests a GCP token via `/v1/credentials/gcp/token?audience=...`
//! 3. Vouch issues an OIDC ID token with the user's identity
//! 4. User exchanges the token with GCP for temporary credentials
//!
//! # GCP Configuration
//!
//! 1. Create a Workload Identity Pool
//! 2. Add an OIDC provider pointing to your Vouch server
//! 3. Configure attribute mappings (e.g., `google.subject` = `assertion.sub`)
//! 4. Grant IAM roles to the pool's principal
//!
//! The audience must be the full Workload Identity Pool provider resource name:
//! `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID`

use crate::config::ServerConfig;
use crate::db::{self, Authenticator, Pool};
use crate::redact_email;
use crate::services::oidc::OidcSigningKey;
use vouch_common::oidc::OidcIdTokenClaimsBuilder;

/// Error types for GCP integration operations.
#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    /// Invalid audience format.
    #[error("{0}")]
    InvalidAudience(&'static str),

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

/// Result type for GCP integration operations.
pub type GcpResult<T> = Result<T, GcpError>;

/// Result of issuing a GCP OIDC token.
#[derive(Debug)]
pub struct GcpTokenResult {
    /// The signed OIDC ID token.
    pub id_token: String,
    /// Token validity in seconds.
    pub expires_in: u64,
}

/// GCP integration service.
///
/// Provides OIDC token issuance for GCP Workload Identity Federation.
pub struct GcpService<'a> {
    db: &'a Pool,
    config: &'a ServerConfig,
    oidc_key: &'a OidcSigningKey,
}

impl<'a> GcpService<'a> {
    /// Create a new GCP service instance.
    #[must_use]
    pub fn new(db: &'a Pool, config: &'a ServerConfig, oidc_key: &'a OidcSigningKey) -> Self {
        Self {
            db,
            config,
            oidc_key,
        }
    }

    /// Issue an OIDC ID token for GCP Workload Identity Federation.
    ///
    /// The token can be used with GCP's Security Token Service to get temporary
    /// credentials. The token includes:
    /// - `sub`: User email
    /// - `aud`: Workload Identity Pool provider resource name
    /// - `iss`: Vouch issuer URL
    /// - `hardware_aaguid`: FIDO2 authenticator AAGUID (for hardware key verification)
    /// - `hd`: Google Workspace hosted domain (for domain-based access control)
    ///
    /// # Arguments
    /// * `user_email` - The authenticated user's email
    /// * `audience` - The Workload Identity Pool provider resource name
    /// * `authenticator_id` - The authenticator ID from the session (for AAGUID lookup)
    /// * `hd` - The user's organization domain (Google Workspace hosted domain)
    pub async fn issue_token(
        &self,
        user_email: &str,
        audience: &str,
        authenticator_id: Option<&str>,
        hd: Option<String>,
    ) -> GcpResult<GcpTokenResult> {
        // Validate audience format
        validate_gcp_audience(audience)?;

        // Get authenticator info for AAGUID
        let authenticator = self.get_authenticator(authenticator_id).await?;

        // Token validity matches session duration
        let expires_in = self.config.session_hours * 3600;

        // Build OIDC claims
        // For GCP, the audience is the Workload Identity Pool provider resource name
        let id_claims =
            OidcIdTokenClaimsBuilder::for_gcp(&self.config.base_url, user_email, audience)
                .hardware_aaguid(authenticator.and_then(|a| a.aaguid))
                .hd(hd)
                .valid_for_seconds(expires_in)
                .build()
                .map_err(|e| GcpError::ClaimsBuild(e.to_string()))?;

        // Sign the token with ES256
        let id_token = self
            .oidc_key
            .sign_jwt(&id_claims)
            .map_err(|e| GcpError::TokenSign(e.to_string()))?;

        tracing::info!(
            "Issued GCP OIDC token: user={}, audience={}",
            redact_email(user_email),
            audience
        );

        Ok(GcpTokenResult {
            id_token,
            expires_in,
        })
    }

    /// Get authenticator info for AAGUID lookup.
    async fn get_authenticator(
        &self,
        authenticator_id: Option<&str>,
    ) -> GcpResult<Option<Authenticator>> {
        let Some(id) = authenticator_id else {
            return Err(GcpError::NoAuthenticator);
        };

        db::get_authenticator_by_id(self.db, id)
            .await
            .map_err(GcpError::Database)
    }
}

/// Validate GCP audience format.
///
/// GCP Workload Identity Federation requires audiences in a specific format:
/// `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID`
pub fn validate_gcp_audience(audience: &str) -> GcpResult<()> {
    if !audience.starts_with("//iam.googleapis.com/projects/") {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: must start with //iam.googleapis.com/projects/",
        ));
    }

    // Parse the audience to validate structure
    let parts: Vec<&str> = audience.split('/').collect();
    // Expected: ["", "", "iam.googleapis.com", "projects", PROJECT_NUMBER, "locations", "global", "workloadIdentityPools", POOL_ID, "providers", PROVIDER_ID]
    if parts.len() < 11 {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: incomplete path",
        ));
    }

    // Validate project number is numeric
    if let Some(project_num) = parts.get(4) {
        if !project_num.chars().all(|c| c.is_ascii_digit()) {
            return Err(GcpError::InvalidAudience(
                "Invalid GCP audience format: project number must be numeric",
            ));
        }
    } else {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: missing project number",
        ));
    }

    // Validate expected path components
    if parts.get(5) != Some(&"locations") || parts.get(6) != Some(&"global") {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: expected /locations/global/",
        ));
    }

    if parts.get(7) != Some(&"workloadIdentityPools") {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: expected /workloadIdentityPools/",
        ));
    }

    if parts.get(9) != Some(&"providers") {
        return Err(GcpError::InvalidAudience(
            "Invalid GCP audience format: expected /providers/",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_gcp_audience() {
        let audience = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider";
        assert!(validate_gcp_audience(audience).is_ok());
    }

    #[test]
    fn test_invalid_gcp_audience_wrong_prefix() {
        let audience = "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider";
        assert!(validate_gcp_audience(audience).is_err());
    }

    #[test]
    fn test_invalid_gcp_audience_non_numeric_project() {
        let audience = "//iam.googleapis.com/projects/my-project/locations/global/workloadIdentityPools/my-pool/providers/my-provider";
        assert!(validate_gcp_audience(audience).is_err());
    }

    #[test]
    fn test_invalid_gcp_audience_missing_components() {
        let audience = "//iam.googleapis.com/projects/123456789";
        assert!(validate_gcp_audience(audience).is_err());
    }

    #[test]
    fn test_invalid_gcp_audience_wrong_location() {
        let audience = "//iam.googleapis.com/projects/123456789/locations/us-west1/workloadIdentityPools/my-pool/providers/my-provider";
        assert!(validate_gcp_audience(audience).is_err());
    }
}
