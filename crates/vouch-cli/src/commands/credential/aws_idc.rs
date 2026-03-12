// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center credential command.
//!
//! Obtains temporary AWS credentials via the Trusted Token Issuer flow:
//!
//! 1. `GET /v1/credentials/aws-idc/token` → SSO access token (server handles
//!    OIDC issuance, STS bootstrap, and `CreateTokenWithIAM`)
//! 2. `GetRoleCredentials` → final AWS temporary credentials

use anyhow::{Context, Result};
use secrecy::SecretString;

use super::aws::CredentialProcessOutput;
use crate::client::VouchClient;

/// Fetch an SSO access token from the Vouch server.
///
/// The server performs the full Trusted Token Issuer exchange
/// (OIDC token → STS bootstrap → `CreateTokenWithIAM`) and returns
/// the SSO access token along with the IdC region and domain suffix.
async fn fetch_idc_token(server: &str) -> Result<vouch_common::IdcTokenResponse> {
    let client = VouchClient::new(server).await?;
    client
        .get_authenticated("/v1/credentials/aws-idc/token")
        .await
        .context(
            "failed to get IdC token from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )
}

/// Run the AWS Identity Center credential command.
///
/// Uses a cache-first strategy via [`super::cache::get_or_fetch`]:
/// 1. Check agent cache — return immediately if valid cached credentials exist
/// 2. Execute the 2-call flow, cache the result
/// 3. On network error, fall back to cached credentials (if any)
pub async fn run(server: &str, account_id: &str, role_name: &str) -> Result<()> {
    let cache_key = format!("aws-idc:{account_id}:{role_name}");

    let data = super::cache::get_or_fetch(&cache_key, "AWS IdC credentials", || async {
        let output = fetch_idc_credentials(server, account_id, role_name).await?;
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await?;

    let json = serde_json::to_string(&data).context("failed to serialize credentials")?;
    println!("{json}");
    Ok(())
}

/// Execute the 2-call credential flow.
async fn fetch_idc_credentials(
    server: &str,
    account_id: &str,
    role_name: &str,
) -> Result<CredentialProcessOutput> {
    // 1. Get SSO access token from server (server handles bootstrap + exchange)
    let idc_token = fetch_idc_token(server).await?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // 2. Get role credentials using the SSO access token
    let role_creds = crate::integrations::aws::sso::get_role_credentials(
        &http_client,
        &SecretString::from(idc_token.access_token),
        account_id,
        role_name,
        &idc_token.region,
        &idc_token.domain_suffix,
    )
    .await
    .context("failed to get role credentials from Identity Center")?;

    // 3. Convert expiration from millis to ISO 8601
    let expiration = jiff::Timestamp::from_millisecond(role_creds.expiration)
        .map(|ts| ts.to_string())
        .context("invalid expiration timestamp from SSO")?;

    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id: role_creds.access_key_id,
        secret_access_key: role_creds.secret_access_key,
        session_token: role_creds.session_token,
        expiration,
    })
}
