// SPDX-License-Identifier: BUSL-1.1
//! Kubernetes OIDC integration service.
//!
//! This module provides OIDC token issuance for generic Kubernetes clusters
//! configured with an OIDC authenticator pointing at the Vouch server.
//!
//! # How it works
//!
//! 1. User authenticates with Vouch using FIDO2/WebAuthn
//! 2. User requests a Kubernetes token via `/v1/credentials/kubernetes/token`
//! 3. Vouch issues an OIDC ID token with the user's identity
//! 4. kubectl presents the token to the Kubernetes API server
//! 5. The API server validates the token against the Vouch JWKS endpoint
//!
//! # Kubernetes Configuration
//!
//! The Kubernetes API server must be configured with:
//!
//! ```text
//! --oidc-issuer-url=https://vouch.example.com
//! --oidc-client-id=kubernetes
//! --oidc-username-claim=email
//! ```

use crate::services::oidc::OidcIdTokenClaimsBuilder;
use crate::services::oidc::OidcSigningKey;

/// Default audience for Kubernetes tokens.
pub const DEFAULT_K8S_AUDIENCE: &str = "kubernetes";

/// Token validity for Kubernetes tokens (1 hour).
const K8S_TOKEN_EXPIRES_SECONDS: u64 = 3600;

/// Error types for Kubernetes integration operations.
#[derive(Debug, thiserror::Error)]
pub enum K8sError {
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

/// Issue an OIDC ID token for Kubernetes authentication.
///
/// The token can be used with a Kubernetes API server configured with OIDC
/// authentication pointing at the Vouch server. The token includes:
/// - `sub`: User email
/// - `aud`: Configured audience (default: "kubernetes")
/// - `iss`: Vouch issuer URL
/// - `email`: User email address
/// - `hardware_aaguid`: FIDO2 authenticator AAGUID (for hardware key verification)
/// - `hd`: Hosted domain (for organization-scoped access)
///
/// # Arguments
/// * `base_url` - Server base URL (issuer)
/// * `oidc_key` - OIDC signing key
/// * `user_email` - The authenticated user's email
/// * `audience` - Token audience (matches `--oidc-client-id` on the API server)
/// * `hardware_aaguid` - AAGUID of the authenticator used
/// * `hd` - User's organization domain
pub async fn issue_kubernetes_token(
    base_url: &str,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    audience: &str,
    hardware_aaguid: Option<String>,
    hd: Option<String>,
) -> K8sResult<K8sTokenResult> {
    // Build OIDC claims
    let id_claims = OidcIdTokenClaimsBuilder::for_k8s(base_url, user_email, audience)
        .hardware_aaguid(hardware_aaguid)
        .hd(hd)
        .valid_for_seconds(K8S_TOKEN_EXPIRES_SECONDS)
        .build()
        .map_err(|e| K8sError::ClaimsBuild(e.to_string()))?;

    // Sign the token with ES256
    let id_token = oidc_key
        .sign_jwt(&id_claims)
        .await
        .map_err(|e| K8sError::TokenSign(e.to_string()))?;

    Ok(K8sTokenResult {
        id_token,
        expires_in: K8S_TOKEN_EXPIRES_SECONDS,
    })
}
