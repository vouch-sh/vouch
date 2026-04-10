// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws login` — authenticate to AWS IAM Identity Center.

use anyhow::{Context, Result};

use crate::integrations::aws::config::AwsConfig;
use crate::integrations::aws::sso::{
    SsoConfig, load_cached_token, poll_for_token, register_client, save_access_token,
    start_device_authorization,
};

/// Arguments for `vouch aws login`.
#[derive(clap::Args)]
pub(crate) struct LoginArgs {
    /// SSO session name from ~/.aws/config (default: first found).
    #[arg(long)]
    pub sso_session: Option<String>,
}

/// Run `vouch aws login`.
pub(crate) async fn run(args: LoginArgs) -> Result<()> {
    let aws_config = AwsConfig::load()?;
    let session = super::resolve_sso_session(&aws_config, args.sso_session.as_deref())?;
    let sso_config = SsoConfig::from_session(&session);

    // Check if already authenticated
    if let Some(token) = load_cached_token(&sso_config) {
        let expires_at = token.expires_at.clone();
        println!("Already authenticated (expires {expires_at})");
        return Ok(());
    }

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    // Register or reuse cached client
    let registration = register_client(&http_client, &sso_config)
        .await
        .context("failed to register SSO OIDC client")?;

    // Start device authorization
    let device_auth = start_device_authorization(&http_client, &sso_config, &registration)
        .await
        .context("failed to start device authorization")?;

    println!("Open the following URL in your browser:");
    println!();
    println!("  {}", device_auth.verification_uri_complete);
    println!();
    println!("Enter code: {}", device_auth.user_code);
    println!();

    // Best-effort browser open
    if let Err(e) = open::that(&device_auth.verification_uri_complete) {
        tracing::debug!("failed to open browser: {e}");
    }

    println!("Waiting for authorization...");

    let token = poll_for_token(&http_client, &sso_config, &registration, &device_auth)
        .await
        .context("SSO authorization failed")?;

    let expires_at = token.expires_at.clone();
    save_access_token(&sso_config, &token).context("failed to cache SSO access token")?;

    println!("Authenticated successfully. Token expires at {expires_at}");
    Ok(())
}
