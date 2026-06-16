// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws login` — authenticate to AWS IAM Identity Center.

use anyhow::{Context, Result};
use vouch_cli::{tr, tr_println};

use crate::integrations::aws::config::AwsConfig;
use crate::integrations::aws::sso::{
    SsoConfig, load_cached_token, poll_for_token, register_client, save_access_token,
    start_device_authorization,
};

/// Arguments for `vouch aws login`.
#[derive(clap::Args)]
pub(crate) struct LoginArgs {
    /// SSO session name from ~/.aws/config (default: first found).
    #[arg(long, help = tr!("arg-aws-sso-session-help"))]
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
        tr_println!("aws-login-already-authenticated", expires_at = expires_at);
        return Ok(());
    }

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .with_context(|| tr!("aws-login-err-http-client"))?;

    // Register or reuse cached client
    let registration = register_client(&http_client, &sso_config)
        .await
        .with_context(|| tr!("aws-login-err-register"))?;

    // Start device authorization
    let device_auth = start_device_authorization(&http_client, &sso_config, &registration)
        .await
        .with_context(|| tr!("aws-login-err-device-auth"))?;

    tr_println!(
        "aws-login-browser-prompt",
        url = device_auth.verification_uri_complete.as_str(),
        code = device_auth.user_code.as_str(),
    );

    // Best-effort browser open
    if let Err(e) = open::that(&device_auth.verification_uri_complete) {
        tracing::debug!("failed to open browser: {e}");
    }

    tr_println!("aws-login-waiting");

    let token = poll_for_token(&http_client, &sso_config, &registration, &device_auth)
        .await
        .with_context(|| tr!("aws-login-err-authorization"))?;

    let expires_at = token.expires_at.clone();
    save_access_token(&sso_config, &token).with_context(|| tr!("aws-login-err-cache-token"))?;

    tr_println!("aws-login-success", expires_at = expires_at);
    Ok(())
}
