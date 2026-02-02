// SPDX-License-Identifier: BUSL-1.1
//! Kubernetes integration service.
//!
//! This module provides OIDC token issuance for Kubernetes authentication.
//!
//! # How it works
//!
//! 1. User authenticates with Vouch using FIDO2/WebAuthn
//! 2. User requests a K8s token via `/v1/credentials/k8s/token?audience=...`
//! 3. Vouch issues an OIDC ID token with the user's identity
//! 4. User configures kubectl to use the token for authentication
//!
//! # Kubernetes Configuration
//!
//! The Kubernetes API server must be configured with OIDC authentication:
//!
//! ```yaml
//! apiServer:
//!   extraArgs:
//!     oidc-issuer-url: "https://vouch.example.com"
//!     oidc-client-id: "my-cluster"
//!     oidc-username-claim: "sub"
//!     oidc-groups-claim: "groups"
//! ```
//!
//! The `audience` parameter should match the `--oidc-client-id` flag.

use crate::config::ServerConfig;
use crate::db::{self, Authenticator, Pool};
use crate::services::oidc::OidcSigningKey;
use vouch_common::oidc::OidcIdTokenClaimsBuilder;

/// Error types for Kubernetes integration operations.
#[derive(Debug, thiserror::Error)]
pub enum K8sError {
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

/// Result type for Kubernetes integration operations.
pub type K8sResult<T> = Result<T, K8sError>;

/// Result of issuing a Kubernetes OIDC token.
#[derive(Debug)]
pub struct K8sTokenResult {
    /// The signed OIDC ID token.
    pub id_token: String,
    /// Token validity in seconds.
    pub expires_in: u64,
}

/// Kubernetes integration service.
///
/// Provides OIDC token issuance for Kubernetes authentication.
pub struct KubernetesService<'a> {
    db: &'a Pool,
    config: &'a ServerConfig,
    oidc_key: &'a OidcSigningKey,
}

impl<'a> KubernetesService<'a> {
    /// Create a new Kubernetes service instance.
    #[must_use]
    pub fn new(db: &'a Pool, config: &'a ServerConfig, oidc_key: &'a OidcSigningKey) -> Self {
        Self {
            db,
            config,
            oidc_key,
        }
    }

    /// Issue an OIDC ID token for Kubernetes authentication.
    ///
    /// The token can be used with kubectl or other Kubernetes clients for
    /// OIDC-based authentication. The token includes:
    /// - `sub`: User email
    /// - `aud`: Cluster audience (matches `--oidc-client-id`)
    /// - `iss`: Vouch issuer URL
    /// - `hardware_aaguid`: FIDO2 authenticator AAGUID (for hardware key verification)
    /// - `hd`: Google Workspace hosted domain (for domain-based access control)
    ///
    /// # Arguments
    /// * `user_email` - The authenticated user's email
    /// * `audience` - The Kubernetes cluster audience (matches `--oidc-client-id`)
    /// * `authenticator_id` - The authenticator ID from the session (for AAGUID lookup)
    /// * `hd` - The user's organization domain (Google Workspace hosted domain)
    pub async fn issue_token(
        &self,
        user_email: &str,
        audience: &str,
        authenticator_id: Option<&str>,
        hd: Option<String>,
    ) -> K8sResult<K8sTokenResult> {
        // Validate audience format
        validate_k8s_audience(audience)?;

        // Get authenticator info for AAGUID
        let authenticator = self.get_authenticator(authenticator_id).await?;

        // Token validity matches session duration
        let expires_in = self.config.session_hours * 3600;

        // Build OIDC claims
        // For Kubernetes, the audience is the cluster identifier (--oidc-client-id)
        let id_claims =
            OidcIdTokenClaimsBuilder::for_k8s(&self.config.base_url, user_email, audience)
                .hardware_aaguid(authenticator.and_then(|a| a.aaguid))
                .hd(hd)
                .valid_for_seconds(expires_in)
                .build()
                .map_err(|e| K8sError::ClaimsBuild(e.to_string()))?;

        // Sign the token with ES256
        let id_token = self
            .oidc_key
            .sign_jwt(&id_claims)
            .map_err(|e| K8sError::TokenSign(e.to_string()))?;

        tracing::info!(
            "Issued Kubernetes OIDC token: user={}, audience={}",
            user_email,
            audience
        );

        Ok(K8sTokenResult {
            id_token,
            expires_in,
        })
    }

    /// Get authenticator info for AAGUID lookup.
    async fn get_authenticator(
        &self,
        authenticator_id: Option<&str>,
    ) -> K8sResult<Option<Authenticator>> {
        let Some(id) = authenticator_id else {
            return Err(K8sError::NoAuthenticator);
        };

        db::get_authenticator_by_id(self.db, id)
            .await
            .map_err(K8sError::Database)
    }
}

/// Validate Kubernetes audience format.
///
/// Kubernetes audiences are typically cluster names or identifiers.
/// This validation ensures the audience is non-empty and contains valid characters.
///
/// Allowed characters: alphanumeric, hyphens, underscores, dots, colons, and forward slashes.
/// This covers cluster names, URLs, and URNs.
pub fn validate_k8s_audience(audience: &str) -> K8sResult<()> {
    if audience.is_empty() {
        return Err(K8sError::InvalidAudience(
            "Invalid Kubernetes audience: audience cannot be empty",
        ));
    }

    // Kubernetes audiences should be reasonable identifiers
    // Max length based on DNS subdomain name limit
    if audience.len() > 253 {
        return Err(K8sError::InvalidAudience(
            "Invalid Kubernetes audience: too long (max 253 characters)",
        ));
    }

    for c in audience.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' && c != ':' && c != '/' {
            return Err(K8sError::InvalidAudience(
                "Invalid Kubernetes audience: must contain only alphanumeric characters, hyphens, underscores, dots, colons, or slashes",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_simple_cluster_name() {
        assert!(validate_k8s_audience("my-cluster").is_ok());
        assert!(validate_k8s_audience("production").is_ok());
        assert!(validate_k8s_audience("dev-01").is_ok());
    }

    #[test]
    fn test_valid_cluster_name_with_underscores() {
        assert!(validate_k8s_audience("my_cluster").is_ok());
        assert!(validate_k8s_audience("prod_us_east_1").is_ok());
    }

    #[test]
    fn test_valid_cluster_name_with_dots() {
        assert!(validate_k8s_audience("cluster.example.com").is_ok());
        assert!(validate_k8s_audience("k8s.prod.internal").is_ok());
    }

    #[test]
    fn test_valid_url_like_audience() {
        assert!(validate_k8s_audience("https://k8s.example.com").is_ok());
        assert!(validate_k8s_audience("https://api.cluster.local:6443").is_ok());
    }

    #[test]
    fn test_valid_urn_audience() {
        assert!(validate_k8s_audience("urn:k8s:cluster:production").is_ok());
    }

    #[test]
    fn test_empty_audience_fails() {
        assert!(validate_k8s_audience("").is_err());
    }

    #[test]
    fn test_audience_with_spaces_fails() {
        assert!(validate_k8s_audience("my cluster").is_err());
        assert!(validate_k8s_audience(" production").is_err());
        assert!(validate_k8s_audience("production ").is_err());
    }

    #[test]
    fn test_audience_with_special_chars_fails() {
        assert!(validate_k8s_audience("cluster;drop").is_err());
        assert!(validate_k8s_audience("cluster&test").is_err());
        assert!(validate_k8s_audience("cluster|pipe").is_err());
        assert!(validate_k8s_audience("cluster$var").is_err());
        assert!(validate_k8s_audience("cluster`cmd`").is_err());
    }

    #[test]
    fn test_audience_too_long_fails() {
        let long_audience = "a".repeat(254);
        assert!(validate_k8s_audience(&long_audience).is_err());
    }

    #[test]
    fn test_audience_max_length_succeeds() {
        let max_audience = "a".repeat(253);
        assert!(validate_k8s_audience(&max_audience).is_ok());
    }

    #[test]
    fn test_numeric_audience() {
        assert!(validate_k8s_audience("123456").is_ok());
        assert!(validate_k8s_audience("cluster-123").is_ok());
    }
}
