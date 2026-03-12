// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS SSO-OIDC client for IAM Identity Center token exchange.
//!
//! Implements the `CreateTokenWithIAM` API using the JWT Bearer grant
//! to exchange a Vouch OIDC ID token for an IAM Identity Center access
//! token.
//!
//! # Reference
//!
//! <https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html>

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::Deserialize;

use super::sigv4;
use super::sts::StsCredentials;

/// Response from `CreateTokenWithIAM`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

impl std::fmt::Debug for CreateTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Result of a successful `CreateTokenWithIAM` call.
pub struct IdcToken {
    /// SSO access token (bearer token for SSO portal APIs).
    pub access_token: SecretString,
    /// Token validity in seconds.
    pub expires_in: u64,
}

impl std::fmt::Debug for IdcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdcToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Exchange a Vouch OIDC token for an IAM Identity Center access token.
///
/// Calls `POST /token?aws_iam=t` on the SSO-OIDC endpoint with the
/// JWT Bearer grant type. The request is SigV4-signed with the provided
/// bootstrap credentials.
///
/// # Arguments
/// * `http_client` - HTTP client
/// * `application_arn` - IAM Identity Center application ARN (`clientId`)
/// * `assertion` - Vouch OIDC ID token (the JWT)
/// * `region` - AWS region where Identity Center is deployed
/// * `domain_suffix` - DNS suffix for the partition (e.g., `amazonaws.com`)
/// * `creds` - Bootstrap IAM credentials (from `AssumeRoleWithWebIdentity`)
pub async fn create_token_with_iam(
    http_client: &reqwest::Client,
    application_arn: &str,
    assertion: &str,
    region: &str,
    domain_suffix: &str,
    creds: &StsCredentials,
) -> Result<IdcToken> {
    let endpoint = format!("https://oidc.{region}.{domain_suffix}/token?aws_iam=t");

    let body = serde_json::json!({
        "clientId": application_arn,
        "grantType": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
    });

    let response_text = sigv4::sign_and_send_json(
        http_client,
        &endpoint,
        "sso-oauth",
        region,
        creds,
        &body,
    )
    .await
    .context("CreateTokenWithIAM failed")?;

    let response: CreateTokenResponse = serde_json::from_str(&response_text)
        .context("failed to parse CreateTokenWithIAM response")?;

    Ok(IdcToken {
        access_token: SecretString::from(response.access_token),
        expires_in: response.expires_in,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create_token_response() {
        let json = r#"{
            "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example",
            "expiresIn": 3600,
            "tokenType": "Bearer"
        }"#;
        let response: CreateTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.expires_in, 3600);
        assert_eq!(response.token_type, "Bearer");
        assert!(!response.access_token.is_empty());
    }
}
