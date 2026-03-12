// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center SSO token refresh command.
//!
//! Obtains an SSO access token from the Vouch server and writes it to
//! `~/.aws/sso/cache/` so native AWS tools (CLI, SDKs, terraform, CDK)
//! can use cached SSO credentials directly.

use anyhow::{Context, Result};

use crate::client::VouchClient;
use crate::config::hostname_from_url;
use crate::sso_cache;

/// Derive the SSO session name from a server URL.
///
/// Uses the hostname (with port if non-standard), sanitized to
/// `[a-z0-9-]`. This becomes both the `[sso-session X]` name in
/// `~/.aws/config` and the SHA-1 cache key in `~/.aws/sso/cache/`.
///
/// Examples:
/// - `https://us.vouch.sh`    → `us-vouch-sh`
/// - `http://localhost:3000`   → `localhost-3000`
/// - `https://dev.vouch.sh`   → `dev-vouch-sh`
pub fn sso_session_name(server: &str) -> Result<String> {
    let host = hostname_from_url(server)?;
    let sanitized: String = host
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Collapse consecutive dashes and trim
    let mut result = String::with_capacity(sanitized.len());
    let mut prev_dash = false;
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_dash {
                result.push(c);
            }
            prev_dash = true;
        } else {
            result.push(c);
            prev_dash = false;
        }
    }

    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        anyhow::bail!("could not derive SSO session name from server URL: {server}");
    }
    Ok(trimmed.to_string())
}

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
        &response.access_token,
        response.expires_in,
    )?;

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
                &response.access_token,
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
