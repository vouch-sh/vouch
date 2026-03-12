// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center SSO token refresh command.
//!
//! Obtains an SSO access token from the Vouch server and writes it to
//! `~/.aws/sso/cache/` so native AWS tools (CLI, SDKs, terraform, CDK)
//! can use cached SSO credentials directly.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::client::VouchClient;
use crate::integrations::aws::sso_session_name;
use crate::sso_cache;

/// Run the AWS Identity Center SSO token refresh command.
///
/// Calls `POST /v1/credentials/aws-idc/sso-token` and writes the
/// result to `~/.aws/sso/cache/`.
pub async fn run(server: &str) -> Result<()> {
    let session_name = sso_session_name(server)?;
    let response = fetch_sso_token(server).await?;

    sso_cache::write_sso_token(
        &session_name,
        server,
        &response.region,
        response.access_token.expose_secret(),
        response.expires_in,
    )?;

    // Saturate to i64::MAX if expires_in exceeds i64 range (practically impossible
    // since SSO tokens last hours, but avoids a panic path)
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            i64::try_from(response.expires_in).unwrap_or(i64::MAX),
        ))
        .context("overflow computing expiration")?;

    println!(
        "AWS SSO token refreshed (expires: {})",
        expires_at.strftime("%Y-%m-%d %H:%M %Z"),
    );

    Ok(())
}

/// Auto-refresh SSO token after login (best-effort, silent on failure).
///
/// Checks if `~/.aws/config` has a matching `[sso-session]` section.
/// If found, refreshes the SSO token. If not configured, does nothing.
pub async fn auto_refresh_sso_token(server: &str) {
    let session_name = match sso_session_name(server) {
        Ok(name) => name,
        Err(_) => return,
    };

    // Check if SSO session is configured
    let config = match crate::integrations::aws::AwsConfig::load() {
        Ok(c) => c,
        Err(_) => return,
    };

    if !config.sso_session_exists(&session_name) {
        return;
    }

    match fetch_sso_token(server).await {
        Ok(response) => {
            if let Err(e) = sso_cache::write_sso_token(
                &session_name,
                server,
                &response.region,
                response.access_token.expose_secret(),
                response.expires_in,
            ) {
                tracing::debug!("Failed to write SSO cache: {e}");
            } else {
                tracing::debug!("Auto-refreshed AWS SSO token");
            }
        }
        Err(e) => {
            tracing::debug!("Failed to refresh SSO token: {e}");
        }
    }
}

/// Fetch SSO token from the Vouch server.
async fn fetch_sso_token(server: &str) -> Result<vouch_common::IdcSsoTokenResponse> {
    let client = VouchClient::new(server).await?;
    client
        .post_authenticated("/v1/credentials/aws-idc/sso-token", &())
        .await
        .context(
            "failed to get SSO token from Vouch server.\n\
             Ensure AWS Identity Center is configured by your org admin.",
        )
}
