// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center credential command.
//!
//! Obtains temporary AWS credentials via the server-side IdC flow:
//!
//! `GET /v1/credentials/aws-idc/{account_id}/roles/{role_name}`
//!
//! The server handles the full chain: OIDC issuance → STS bootstrap →
//! `CreateTokenWithIAM` → `GetRoleCredentials` → (optional)
//! identity-enhanced `AssumeRole` with `ProvidedContexts`.

use anyhow::{Context, Result};
use secrecy::SecretString;

use super::aws::CredentialProcessOutput;
use crate::client::VouchClient;

/// Run the AWS Identity Center credential command.
///
/// Uses a cache-first strategy via [`super::cache::get_or_fetch`]:
/// 1. Check agent cache — return immediately if valid cached credentials exist
/// 2. Execute the server-side flow, cache the result
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

/// Fetch AWS credentials from the server in a single call.
async fn fetch_idc_credentials(
    server: &str,
    account_id: &str,
    role_name: &str,
) -> Result<CredentialProcessOutput> {
    let client = VouchClient::new(server).await?;
    let url = format!(
        "/v1/credentials/aws-idc/{}/roles/{}",
        urlencoding::encode(account_id),
        urlencoding::encode(role_name),
    );
    let response: vouch_common::IdcCredentialsResponse =
        client.get_authenticated(&url).await.context(
            "failed to get IdC credentials from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )?;

    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id: response.access_key_id,
        secret_access_key: SecretString::from(response.secret_access_key),
        session_token: SecretString::from(response.session_token),
        expiration: response.expiration.to_string(),
    })
}
