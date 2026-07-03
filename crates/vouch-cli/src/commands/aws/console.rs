// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws console` — open the AWS Management Console via federation.
//!
//! Uses the custom identity broker flow described in the AWS documentation:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_cli::{tr, tr_args, tr_eprintln, tr_println};

use crate::integrations::aws;

/// Arguments for `vouch aws console`.
#[derive(clap::Args)]
pub(crate) struct ConsoleArgs {
    /// AWS IAM role ARN to assume via STS (auto-detected from
    /// ~/.aws/config if not specified and no --account is given).
    #[arg(
        long,
        conflicts_with_all = ["account", "permission_set"],
        help = tr!("arg-aws-console-role-help"),
    )]
    pub role: Option<String>,

    /// AWS account ID for Identity Center (`GetRoleCredentials`) path.
    #[arg(long, requires = "permission_set", conflicts_with = "role")]
    pub account: Option<String>,

    /// IAM Identity Center permission-set name.
    #[arg(long, requires = "account", conflicts_with = "role")]
    pub permission_set: Option<String>,

    /// Management role ARN to chain through when multiple organizations are
    /// configured (STS role path only; not valid with --account/--permission-set).
    #[arg(long, conflicts_with_all = ["idc_application", "account", "permission_set"])]
    pub via: Option<String>,

    /// Identity Center application ARN disambiguator for multi-instance setups.
    #[arg(long, conflicts_with = "via")]
    pub idc_application: Option<String>,
}

/// Temporary AWS credentials for opening the console, plus the HTTP client and partition.
struct ConsoleCreds {
    access_key_id: String,
    secret_access_key: SecretString,
    session_token: SecretString,
    partition: vouch_common::aws::Partition,
    http_client: reqwest::Client,
}

/// Response from the AWS federation `getSigninToken` action.
#[derive(Deserialize)]
struct SigninTokenResponse {
    #[serde(rename = "SigninToken")]
    signin_token: String,
}

/// Obtain console credentials via the Identity Center path.
async fn get_idc_console_creds(server: &str, args: &ConsoleArgs) -> Result<ConsoleCreds> {
    use crate::commands::credential::aws::{detect_agent_source, obtain_identity_center_token};
    use crate::integrations::aws::sso_portal::get_role_credentials;
    use vouch_common::http::credential_client;

    // Block AI agents early (fast-fail before config load): permission-set
    // credentials cannot be downscoped.
    if detect_agent_source().is_some() {
        return Err(
            crate::exit_code::CliError::ConfigError(tr!("aws-err-agent-idc-unsupported")).into(),
        );
    }

    let account_id = args.account.as_deref().context("account is required")?;
    let permission_set = args
        .permission_set
        .as_deref()
        .context("permission_set is required")?;

    let vouch_config = crate::config::Config::load()?;
    let aws_cfg = vouch_config
        .aws()
        .ok_or_else(|| crate::exit_code::CliError::ConfigError(tr!("aws-err-not-configured")))?;

    // `resolve_identity_center` returns the owning org+idc pair so the
    // management role always comes from the same org as the IdC instance.
    let (org, idc) = crate::commands::credential::aws::resolve_identity_center(
        aws_cfg,
        args.idc_application.as_deref(),
    )?
    .ok_or_else(|| crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured")))?;

    // If --via is supplied it must match the owning org's management role;
    // cross-org pairings are rejected.
    if let Some(via_role) = args.via.as_deref()
        && via_role != org.management_role
    {
        return Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "aws-err-via-not-found",
            management_role = via_role.to_string()
        ))
        .into());
    }
    let management_role = org.management_role.clone();

    let http_client = credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
        .context("failed to create HTTP client")?;

    let idc_token = obtain_identity_center_token(&http_client, server, &management_role, idc)
        .await
        .with_context(|| tr!("aws-console-err-aws-credentials"))?;

    let creds = get_role_credentials(
        &http_client,
        &idc.region,
        &idc_token,
        account_id,
        permission_set,
    )
    .await
    .with_context(|| tr!("aws-console-err-aws-credentials"))?;

    let partition = vouch_common::aws::Partition::from_region(&idc.region);
    Ok(ConsoleCreds {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        partition,
        http_client,
    })
}

/// Obtain console credentials via the STS role path.
async fn get_sts_console_creds(server: &str, args: ConsoleArgs) -> Result<ConsoleCreds> {
    // Resolve role ARN from explicit arg or from ~/.aws/config
    let role_arn = match args.role {
        Some(r) => r,
        None => aws::get_local_aws_role()
            .ok_or_else(|| anyhow::anyhow!(tr!("aws-err-not-configured")))?,
    };

    // Determine partition and region from role ARN
    let partition = vouch_common::aws::Partition::from_arn(&role_arn)
        .with_context(|| tr!("aws-console-err-invalid-role-arn"))?;
    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region = match aws::resolve_region(None, &profile_name) {
        Ok(r) => r,
        Err(_) => {
            let default = partition.default_sts_region();
            tracing::debug!("no region configured, defaulting to {default}");
            default.to_string()
        }
    };

    // Validate/resolve --via the same way `vouch credential aws` does, so an
    // unconfigured management role fails fast with a Vouch error instead of an
    // opaque AWS AccessDenied at the STS call.
    let vouch_config = crate::config::Config::load()?;
    let management_role = crate::commands::credential::aws::resolve_management_role_for(
        &vouch_config,
        &role_arn,
        args.via.as_deref(),
    )?;

    let agent_source = crate::commands::credential::aws::detect_agent_source();
    let result = crate::commands::credential::aws::exchange_for_sts_credentials(
        crate::commands::credential::aws::StsRequest {
            server,
            role_arn: &role_arn,
            region: &region,
            management_role: management_role.as_deref(),
            agent_source: agent_source.as_deref(),
        },
    )
    .await
    .with_context(|| tr!("aws-console-err-aws-credentials"))?;

    Ok(ConsoleCreds {
        access_key_id: result.credentials.access_key_id.clone(),
        secret_access_key: result.credentials.secret_access_key.clone(),
        session_token: result.credentials.session_token.clone(),
        partition,
        http_client: result.http_client,
    })
}

/// Run `vouch aws console`.
pub(crate) async fn run(server: &str, args: ConsoleArgs) -> Result<()> {
    let console_creds = if args.account.is_some() {
        get_idc_console_creds(server, &args).await?
    } else {
        get_sts_console_creds(server, args).await?
    };

    let partition = &console_creds.partition;
    let federation_url = partition.federation_endpoint()?;
    let console_url = partition.console_url()?;

    // Build federation session JSON — expose secrets only here
    let session_encoded = serde_json::to_string(&serde_json::json!({
        "sessionId": console_creds.access_key_id,
        "sessionKey": console_creds.secret_access_key.expose_secret(),
        "sessionToken": console_creds.session_token.expose_secret(),
    }))
    .with_context(|| tr!("aws-console-err-serialize-session"))?;

    // POST to federation endpoint for a signin token
    let resp = console_creds
        .http_client
        .post(federation_url)
        .form(&[("Action", "getSigninToken"), ("Session", &session_encoded)])
        .send()
        .await
        .with_context(|| tr!("aws-console-err-signin-request"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(tr_args!(
            "aws-console-err-signin-failed",
            status = status.to_string(),
            body = body,
        ));
    }

    let token_resp: SigninTokenResponse = resp
        .json()
        .await
        .with_context(|| tr!("aws-console-err-signin-parse"))?;

    // Construct login URL using url::Url for safe encoding
    let mut login_url = url::Url::parse(federation_url)
        .with_context(|| tr!("aws-console-err-invalid-federation-url"))?;
    login_url
        .query_pairs_mut()
        .append_pair("Action", "login")
        .append_pair("Issuer", server)
        .append_pair("Destination", console_url)
        .append_pair("SigninToken", &token_resp.signin_token);

    // Open browser (print URL only as fallback)
    let login_str = login_url.as_str();
    match open::that(login_str) {
        Ok(()) => {
            tr_println!("aws-console-opening");
        }
        Err(e) => {
            tracing::debug!("failed to open browser: {e}");
            println!("{login_str}");
            tr_eprintln!("aws-console-browser-failed");
        }
    }

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // Agent-block test --------------------------------------------------------
    //
    // The agent check fires as the very first statement in `get_idc_console_creds`,
    // before Config::load or any network I/O, so the test does not need real
    // server/config state.

    #[tokio::test]
    #[expect(
        unsafe_code,
        reason = "env mutation to trigger agent detection in an isolated test; var is restored after assertion"
    )]
    async fn agent_block_in_get_idc_console_creds_fires_before_config_load() {
        let _guard = crate::commands::credential::aws::test_support::ENV_LOCK
            .lock()
            .await;
        // SAFETY: agent check is the first statement; Config::load is never reached.
        unsafe {
            std::env::set_var("CLAUDECODE", "1");
        }
        let args = ConsoleArgs {
            role: None,
            account: Some("111111111111".to_string()),
            permission_set: Some("Admin".to_string()),
            via: None,
            idc_application: None,
        };
        let result = get_idc_console_creds("https://example.com", &args).await;
        // SAFETY: env var restored regardless of assertion outcome.
        unsafe {
            std::env::remove_var("CLAUDECODE");
        }
        // `.err().unwrap()` avoids the `T: Debug` bound that `.unwrap_err()` requires.
        let err = result.err().unwrap();
        assert!(
            matches!(
                err.downcast_ref::<crate::exit_code::CliError>(),
                Some(crate::exit_code::CliError::ConfigError(_))
            ),
            "expected ConfigError(aws-err-agent-idc-unsupported), got: {err}"
        );
    }

    #[test]
    fn test_signin_token_response_deserialize() {
        let json = r#"{"SigninToken": "abc123"}"#;
        let resp: SigninTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signin_token, "abc123");
    }

    #[test]
    fn test_login_url_construction() {
        let mut login_url = url::Url::parse("https://signin.aws.amazon.com/federation").unwrap();
        login_url
            .query_pairs_mut()
            .append_pair("Action", "login")
            .append_pair("Issuer", "https://vouch.example.com")
            .append_pair("Destination", "https://console.aws.amazon.com/")
            .append_pair("SigninToken", "tok-123");

        let s = login_url.as_str();
        assert!(s.starts_with("https://signin.aws.amazon.com/federation?"));
        assert!(s.contains("Action=login"));
        assert!(s.contains("Issuer=https%3A%2F%2Fvouch.example.com"));
        assert!(s.contains("Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F"));
        assert!(s.contains("SigninToken=tok-123"));
    }
}
