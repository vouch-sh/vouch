// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws console` — open the AWS Management Console via federation.
//!
//! Uses the custom identity broker flow described in the AWS documentation:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use serde::Deserialize;
use vouch_cli::{tr, tr_args, tr_eprintln, tr_println};

use crate::integrations::aws;
use crate::integrations::aws::sts::StsCredentials;

/// Arguments for `vouch aws console`.
#[derive(clap::Args)]
pub(crate) struct ConsoleArgs {
    /// AWS IAM role ARN to assume (STS path), or permission-set name
    /// (IdC path when --account is set). Auto-detected from ~/.aws/config
    /// if not specified and --account is not set.
    #[arg(long, help = tr!("arg-aws-console-role-help"))]
    pub role: Option<String>,
    /// AWS account ID for the Identity Center path. When set, --role is
    /// interpreted as a permission-set name (not an ARN) and credentials
    /// are obtained via the SSO portal `GetRoleCredentials` call.
    #[arg(long, help = tr!("arg-aws-console-account-help"))]
    pub account: Option<String>,
    /// SSO session name from ~/.aws/config (auto-detected if not specified).
    #[arg(long, help = tr!("arg-aws-sso-session-help"))]
    pub sso_session: Option<String>,
}

/// Response from the AWS federation `getSigninToken` action.
#[derive(Deserialize)]
struct SigninTokenResponse {
    #[serde(rename = "SigninToken")]
    signin_token: String,
}

/// Run `vouch aws console`.
pub(crate) async fn run(server: &str, args: ConsoleArgs) -> Result<()> {
    let (creds, federation_url, console_url) = if let Some(account_id) = args.account.as_deref() {
        get_idc_creds(server, &args, account_id).await?
    } else {
        get_sts_creds(server, &args).await?
    };

    // Build federation session JSON — expose secrets only here.
    let session_encoded = serde_json::to_string(&serde_json::json!({
        "sessionId": creds.access_key_id,
        "sessionKey": creds.secret_access_key.expose_secret(),
        "sessionToken": creds.session_token.expose_secret(),
    }))
    .with_context(|| tr!("aws-console-err-serialize-session"))?;

    // POST to federation endpoint for a signin token.
    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let resp = http_client
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

    // Construct login URL using url::Url for safe encoding.
    let mut login_url = url::Url::parse(federation_url)
        .with_context(|| tr!("aws-console-err-invalid-federation-url"))?;
    login_url
        .query_pairs_mut()
        .append_pair("Action", "login")
        .append_pair("Issuer", server)
        .append_pair("Destination", console_url)
        .append_pair("SigninToken", &token_resp.signin_token);

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

/// Credentials plus the federation and console URLs for the caller's partition.
type FedInfo = (StsCredentials, &'static str, &'static str);

/// STS `AssumeRoleWithWebIdentity` credential path (single account / chaining).
async fn get_sts_creds(server: &str, args: &ConsoleArgs) -> Result<FedInfo> {
    let role_arn = match &args.role {
        Some(r) => r.clone(),
        None => aws::get_local_aws_role()
            .ok_or_else(|| anyhow::anyhow!(tr!("aws-err-not-configured")))?,
    };

    let partition = vouch_common::aws::Partition::from_arn(&role_arn)
        .with_context(|| tr!("aws-console-err-invalid-role-arn"))?;
    let federation_url = partition.federation_endpoint()?;
    let console_url = partition.console_url()?;

    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region = match aws::resolve_region(None, &profile_name) {
        Ok(r) => r,
        Err(_) => {
            let default = partition.default_sts_region();
            tracing::debug!("no region configured, defaulting to {default}");
            default.to_string()
        }
    };

    // Resolve the management-role hop from the requested SSO session so a
    // multi-session chaining setup opens the console via the correct org,
    // rather than falling back to the first session inside the exchange.
    let vouch_config = crate::config::Config::load()?;
    let management_role = crate::commands::credential::aws::resolve_management_role(
        &vouch_config,
        args.sso_session.as_deref(),
    )?
    .filter(|m| m != &role_arn);

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

    Ok((result.credentials, federation_url, console_url))
}

/// Identity Center portal `GetRoleCredentials` path (TTI exchange + portal).
async fn get_idc_creds(server: &str, args: &ConsoleArgs, account_id: &str) -> Result<FedInfo> {
    use crate::integrations::aws::sso_portal::get_role_credentials;

    // Fail closed for coding agents, matching the credential IdC path: SSO portal
    // `GetRoleCredentials` returns the permission set's full access and cannot be
    // downscoped to ReadOnlyAccess, so an agent must not obtain it (issue #398).
    if let Some(source) = crate::commands::credential::aws::detect_agent_source() {
        return Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "aws-err-agent-idc-readonly-unsupported",
            source = source,
        ))
        .into());
    }

    let role_name = args.role.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--role (permission-set name) is required with --account")
    })?;

    let aws_config = crate::integrations::aws::config::AwsConfig::load()?;
    let session =
        crate::commands::aws::resolve_sso_session(&aws_config, args.sso_session.as_deref())?;
    let region = session.region.clone();

    let partition = vouch_common::aws::Partition::from_region(&region);
    let federation_url = partition.federation_endpoint()?;
    let console_url = partition.console_url()?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let bearer = crate::commands::credential::aws::resolve_bearer_token(server, &session, &region)
        .await
        .with_context(|| tr!("aws-console-err-aws-credentials"))?;

    let creds = get_role_credentials(&http_client, &region, &bearer, account_id, role_name)
        .await
        .with_context(|| tr!("aws-console-err-aws-credentials"))?;

    Ok((creds, federation_url, console_url))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

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
