// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generic OIDC ID token issuance for external relying parties.
//!
//! Vouch acts as the OIDC issuer; the relying party (a Kubernetes API
//! server, the Claude API, the OpenAI API, ...) validates the token's
//! signature against the JWKS endpoint and checks `iss`/`aud`/`exp`
//! against its trust configuration.
//!
//! Unlike the AWS path ([`crate::services::integrations::aws`]), the
//! issued token carries only the standard OIDC claim set — no
//! provider-specific tags. The caller chooses the audience.
//!
//! Used by the `/v1/credentials/oidc/token` handler.

use thiserror::Error;

use super::claims::{ClaimsBuildError, OidcIdTokenClaimsBuilder};
use super::keys::OidcSigningKey;

/// Errors from federation token issuance.
#[derive(Debug, Error)]
pub(crate) enum FederationError {
    /// Failed to build the OIDC claim set (e.g. a required field was missing).
    #[error("failed to build claims")]
    ClaimsBuild(#[from] ClaimsBuildError),
    /// Failed to sign the token (key access, KMS error, ...).
    #[error("failed to sign token")]
    TokenSign(#[source] anyhow::Error),
}

/// Result alias for federation token operations.
pub(crate) type FederationResult<T> = Result<T, FederationError>;

/// A successfully issued federation token.
#[derive(Debug)]
pub(crate) struct FederationTokenResult {
    /// Signed OIDC ID token (ES256).
    pub id_token: String,
    /// Lifetime in seconds the token is valid.
    pub expires_in_secs: u64,
}

/// Inputs to [`issue_federation_token`].
///
/// `audience` is required — the caller decides what `aud` to bind the
/// token to. A self-issued token (`audience == base_url`) is a valid
/// choice, but must be made explicitly at the call site so the intent
/// is visible.
pub(crate) struct FederationTokenParams<'a> {
    /// Issuer URL (`iss` claim) — typically the Vouch base URL.
    pub base_url: &'a str,
    /// OIDC signing key (ES256).
    pub oidc_key: &'a OidcSigningKey,
    /// Authenticated user's email (`sub` and `email` claims).
    pub user_email: &'a str,
    /// Audience the relying party expects (`aud` claim).
    pub audience: &'a str,
    /// AAGUID of the authenticator used (`hardware_aaguid` claim).
    pub hardware_aaguid: Option<String>,
    /// Hosted domain (`hd` claim) for organization-scoped policies.
    pub hd: Option<String>,
    /// Token validity in seconds.
    pub expires_in_secs: u64,
}

/// Mint a clean OIDC ID token for federation with an external relying party.
pub(crate) async fn issue_federation_token(
    params: FederationTokenParams<'_>,
) -> FederationResult<FederationTokenResult> {
    let claims =
        OidcIdTokenClaimsBuilder::for_audience(params.base_url, params.user_email, params.audience)
            .hardware_aaguid(params.hardware_aaguid)
            .hd(params.hd)
            .valid_for_seconds(params.expires_in_secs)
            .build()?;

    let id_token = params
        .oidc_key
        .sign_jwt(&claims)
        .await
        .map_err(FederationError::TokenSign)?;

    Ok(FederationTokenResult {
        id_token,
        expires_in_secs: params.expires_in_secs,
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const BASE_URL: &str = "https://vouch.example.com";
    const USER_EMAIL: &str = "user@example.com";

    fn decode_payload(token: &str) -> serde_json::Value {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        let bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The issued token carries only standard OIDC claims — no AWS-namespaced
    /// tags. This is the invariant that distinguishes federation tokens from
    /// AWS tokens.
    #[tokio::test]
    async fn test_federation_token_has_no_aws_claims() {
        let key = OidcSigningKey::generate().unwrap();
        let result = issue_federation_token(FederationTokenParams {
            base_url: BASE_URL,
            oidc_key: &key,
            user_email: USER_EMAIL,
            audience: "https://api.anthropic.com",
            hardware_aaguid: None,
            hd: None,
            expires_in_secs: 3600,
        })
        .await
        .unwrap();

        let claims = decode_payload(&result.id_token);
        assert_eq!(claims["iss"], BASE_URL);
        assert_eq!(claims["sub"], USER_EMAIL);
        assert_eq!(claims["aud"], "https://api.anthropic.com");
        assert_eq!(claims["email"], USER_EMAIL);
        assert!(claims.get("https://aws.amazon.com/tags").is_none());
        assert!(
            claims
                .get("https://aws.amazon.com/source_identity")
                .is_none()
        );
    }

    /// The caller-supplied audience must round-trip into `aud` verbatim
    /// (no defaulting, no normalisation).
    #[tokio::test]
    async fn test_audience_round_trips_verbatim() {
        let key = OidcSigningKey::generate().unwrap();
        let result = issue_federation_token(FederationTokenParams {
            base_url: BASE_URL,
            oidc_key: &key,
            user_email: USER_EMAIL,
            audience: "kubernetes",
            hardware_aaguid: None,
            hd: None,
            expires_in_secs: 3600,
        })
        .await
        .unwrap();

        let claims = decode_payload(&result.id_token);
        assert_eq!(claims["aud"], "kubernetes");
    }

    #[tokio::test]
    async fn test_expires_in_round_trips() {
        let key = OidcSigningKey::generate().unwrap();
        let result = issue_federation_token(FederationTokenParams {
            base_url: BASE_URL,
            oidc_key: &key,
            user_email: USER_EMAIL,
            audience: "kubernetes",
            hardware_aaguid: None,
            hd: None,
            expires_in_secs: 1800,
        })
        .await
        .unwrap();
        assert_eq!(result.expires_in_secs, 1800);
    }
}
