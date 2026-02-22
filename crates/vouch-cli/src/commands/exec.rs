// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exec command - run a command with Vouch-provided credentials in the environment.

use anyhow::{Context, Result, bail};
use std::process::Command;

use super::CredentialType;
use super::credential::cache;

/// CodeArtifact-specific options for exec/env commands.
#[derive(Default)]
pub struct CodeArtifactOptions<'a> {
    pub domain: Option<&'a str>,
    pub domain_owner: Option<&'a str>,
    pub region: Option<&'a str>,
    pub profile: Option<&'a str>,
}

/// Cached AWS credentials extracted from `serde_json::Value`.
///
/// Derives `ZeroizeOnDrop` to clear secret key material from memory when dropped.
/// `expiration` is not sensitive and is skipped.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct AwsEnvCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    #[zeroize(skip)]
    pub expiration: Option<String>,
}

/// Fetch AWS credentials (cache-first) and extract environment variable values.
pub async fn fetch_aws_credentials(
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
) -> Result<AwsEnvCredentials> {
    let cache_key = format!("aws:{role_arn}");

    let data = cache::get_or_fetch(&cache_key, "AWS credentials", || async {
        let output =
            super::credential::aws::fetch_and_assume(server, role_arn, session_name).await?;
        let expires_at = output.expiration.clone();
        let data = serde_json::to_value(&output).context("failed to serialize credentials")?;
        Ok((data, expires_at))
    })
    .await?;

    let access_key_id = data
        .get("AccessKeyId")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing AccessKeyId")?
        .to_string();
    let secret_access_key = data
        .get("SecretAccessKey")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing SecretAccessKey")?
        .to_string();
    let session_token = data
        .get("SessionToken")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing SessionToken")?
        .to_string();
    let expiration = data
        .get("Expiration")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(AwsEnvCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

/// Cached GitHub token extracted from `serde_json::Value`.
///
/// Derives `ZeroizeOnDrop` to clear the token from memory when dropped.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct GitHubEnvToken {
    pub token: String,
}

/// Fetch a GitHub token (cache-first) and extract the token value.
pub async fn fetch_github_token_cached(server: &str) -> Result<GitHubEnvToken> {
    let cache_key = "github";

    let data = cache::get_or_fetch(cache_key, "GitHub token", || async {
        let response = fetch_github_token(server).await?;
        let expires_at = response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(cache::default_expiry);
        Ok((response, expires_at))
    })
    .await?;

    let token = data
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("GitHub credential missing 'token' field")?
        .to_string();

    Ok(GitHubEnvToken { token })
}

/// Run a command with credentials injected as environment variables.
pub async fn run(
    server: &str,
    credential_type: &CredentialType,
    role: Option<&str>,
    session_name: Option<&str>,
    command: &[String],
    ca_opts: CodeArtifactOptions<'_>,
) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified. Usage: vouch exec -- <command> [args...]");
    }

    let program = command.first().context("no command specified")?;
    let args = command.get(1..).unwrap_or_default();

    let mut cmd = Command::new(program);
    cmd.args(args);

    match credential_type {
        CredentialType::Aws => {
            let role_arn = role.context(
                "AWS credentials require --role. Usage: vouch exec --type aws --role <ARN> -- <command>",
            )?;
            inject_aws_credentials(&mut cmd, server, role_arn, session_name).await?;
        }
        CredentialType::Github => {
            inject_github_credentials(&mut cmd, server).await?;
        }
        CredentialType::Codeartifact => {
            inject_codeartifact_credentials(&mut cmd, server, &ca_opts).await?;
        }
    }

    // On Unix, replace our process so signals propagate correctly.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        bail!("failed to execute {program}: {err}");
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to execute: {program}"))?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            bail!("command exited with status {code}");
        }

        Ok(())
    }
}

/// Fetch AWS STS credentials (cache-first) and inject them into the environment.
async fn inject_aws_credentials(
    cmd: &mut Command,
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
) -> Result<()> {
    let creds = fetch_aws_credentials(server, role_arn, session_name).await?;

    cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id);
    cmd.env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key);
    cmd.env("AWS_SESSION_TOKEN", &creds.session_token);

    if let Some(ref v) = creds.expiration {
        cmd.env("AWS_CREDENTIAL_EXPIRATION", v);
    }

    Ok(())
}

/// Fetch a GitHub token (cache-first) and inject it into the environment.
async fn inject_github_credentials(cmd: &mut Command, server: &str) -> Result<()> {
    let gh = fetch_github_token_cached(server).await?;

    cmd.env("GITHUB_TOKEN", &gh.token);
    cmd.env("GH_TOKEN", &gh.token);

    Ok(())
}

/// Fetch a GitHub token from the Vouch server.
pub(crate) async fn fetch_github_token(server: &str) -> Result<serde_json::Value> {
    let client = crate::client::VouchClient::new(server).await?;
    client
        .get_authenticated("/v1/credentials/github/token")
        .await
        .context("failed to get GitHub token from Vouch server")
}

/// Fetch a CodeArtifact token and inject it into the environment.
async fn inject_codeartifact_credentials(
    cmd: &mut Command,
    server: &str,
    opts: &CodeArtifactOptions<'_>,
) -> Result<()> {
    use secrecy::ExposeSecret;
    let (domain, domain_owner, region) =
        super::credential::codeartifact::resolve_codeartifact_params(
            opts.domain,
            opts.domain_owner,
            opts.region,
            opts.profile,
        )?;

    let token = super::credential::codeartifact::get_token(server, &domain, &domain_owner, &region)
        .await
        .context("failed to get CodeArtifact token")?;

    cmd.env(
        "CODEARTIFACT_AUTH_TOKEN",
        token.authorization_token.expose_secret(),
    );

    Ok(())
}
