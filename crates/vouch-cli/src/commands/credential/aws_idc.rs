// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center credential command.
//!
//! Obtains temporary AWS credentials via the Trusted Token Issuer flow:
//!
//! 1. Fetch Vouch OIDC token from server
//! 2. Bootstrap IAM credentials via `AssumeRoleWithWebIdentity`
//! 3. Exchange Vouch token for IdC SSO token via `CreateTokenWithIAM`
//! 4. Get AWS credentials via `GetRoleCredentials`

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use super::aws::{CredentialProcessOutput, OidcTokenResponse, decode_jwt_payload};
use crate::client::VouchClient;
use crate::session::get_user_email;

/// Fetch the IdC config from the Vouch server.
///
/// Returns `(bootstrap_role_arn, application_arn, idc_region)`.
async fn fetch_idc_config(server: &str) -> Result<(String, String, String)> {
    let client = VouchClient::new(server).await?;
    let resp: vouch_common::IntegrationConfigResponse<vouch_common::AwsIntegrationConfig> = client
        .get_authenticated("/v1/integrations/aws")
        .await
        .context("failed to fetch AWS integration config from server")?;

    let config = resp
        .config
        .filter(|c| c.idc_configured())
        .context(
            "AWS Identity Center is not configured on the Vouch server.\n\
             Ask your org admin to configure it at the Vouch admin portal.",
        )?;

    Ok((
        config
            .idc_bootstrap_role_arn
            .context("missing idc_bootstrap_role_arn")?,
        config
            .idc_application_arn
            .context("missing idc_application_arn")?,
        config.idc_region.context("missing idc_region")?,
    ))
}

/// Run the AWS Identity Center credential command.
///
/// Uses a cache-first strategy via [`super::cache::get_or_fetch`]:
/// 1. Check agent cache — return immediately if valid cached credentials exist
/// 2. Execute the full TTI exchange flow, cache the result
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

/// Execute the full Trusted Token Issuer exchange flow.
async fn fetch_idc_credentials(
    server: &str,
    account_id: &str,
    role_name: &str,
) -> Result<CredentialProcessOutput> {
    use crate::integrations::aws::sts::{Arn, assume_role_with_web_identity};

    // 1. Fetch IdC configuration from server
    let (bootstrap_role_arn, application_arn, idc_region) = fetch_idc_config(server).await?;

    let bootstrap_arn = Arn::parse_role_arn(&bootstrap_role_arn)?;
    let domain_suffix = bootstrap_arn.partition.dns_suffix();

    // 2. Get Vouch OIDC token
    let client = VouchClient::new(server).await?;
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;
    let id_token = token_response.id_token.expose_secret();

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // 3. Bootstrap: AssumeRoleWithWebIdentity → temp IAM creds
    let email = get_user_email(server).await;
    let session_name = email.as_deref().unwrap_or("vouch-idc-session");
    let bootstrap_region = bootstrap_arn.partition.default_sts_region();

    let bootstrap_creds = assume_role_with_web_identity(
        &http_client,
        &bootstrap_role_arn,
        session_name,
        id_token,
        bootstrap_region,
        domain_suffix,
        &[], // No session tags needed for bootstrap
    )
    .await
    .context("failed to assume bootstrap role for Identity Center")?;

    // 4. Token exchange: CreateTokenWithIAM → SSO access token
    let idc_token = crate::integrations::aws::sso_oidc::create_token_with_iam(
        &http_client,
        &application_arn,
        id_token,
        &idc_region,
        domain_suffix,
        &bootstrap_creds,
    )
    .await
    .context("failed to exchange token with Identity Center")?;

    // 5. Get credentials: GetRoleCredentials → AWS temp creds
    let role_creds = crate::integrations::aws::sso::get_role_credentials(
        &http_client,
        &idc_token.access_token,
        account_id,
        role_name,
        &idc_region,
        domain_suffix,
    )
    .await
    .context("failed to get role credentials from Identity Center")?;

    // 6. Convert expiration from millis to ISO 8601
    let expiration = jiff::Timestamp::from_millisecond(role_creds.expiration)
        .map(|ts| ts.to_string())
        .unwrap_or_default();

    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id: role_creds.access_key_id,
        secret_access_key: role_creds.secret_access_key,
        session_token: role_creds.session_token,
        expiration,
    })
}

/// Decode JWT payload to extract claims for display purposes.
///
/// Reused from the base aws credential module.
pub(crate) fn _extract_email_from_token(token: &str) -> Option<String> {
    decode_jwt_payload(token)
        .ok()
        .and_then(|c| c.get("email").and_then(serde_json::Value::as_str).map(String::from))
}
