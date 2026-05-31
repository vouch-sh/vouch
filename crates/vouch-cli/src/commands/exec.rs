// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exec command - run a command with Vouch-provided credentials in the environment.

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use std::process::Command;

use super::CredentialType;
use super::credential::cache;

/// CodeArtifact-specific options for exec/env commands.
#[derive(Default)]
pub(crate) struct CodeArtifactOptions<'a> {
    pub domain: Option<&'a str>,
    pub domain_owner: Option<&'a str>,
    pub region: Option<&'a str>,
    pub profile: Option<&'a str>,
}

/// RDS-specific options for exec/env commands.
#[derive(Default)]
pub(crate) struct RdsOptions<'a> {
    pub hostname: Option<&'a str>,
    pub port: u16,
    pub username: Option<&'a str>,
    pub region: Option<&'a str>,
}

/// Redshift-specific options for exec/env commands.
#[derive(Default)]
pub(crate) struct RedshiftOptions<'a> {
    pub cluster_id: Option<&'a str>,
    pub workgroup: Option<&'a str>,
    pub db_name: Option<&'a str>,
    pub duration: Option<u32>,
    pub region: Option<&'a str>,
}

/// Cached AWS credentials extracted from `serde_json::Value`.
///
/// `access_key_id` is a plain `String` because AWS access key IDs are semi-public
/// identifiers (they appear in CloudTrail logs, IAM consoles, etc.).
/// Only `secret_access_key` and `session_token` are wrapped in `SecretString`
/// for automatic zeroization on drop and redacted `Debug` output.
pub(crate) struct AwsEnvCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: Option<String>,
}

impl std::fmt::Debug for AwsEnvCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsEnvCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Fetch AWS credentials (cache-first) and extract environment variable values.
pub(crate) async fn fetch_aws_credentials(
    server: &str,
    role_arn: &str,
) -> Result<AwsEnvCredentials> {
    let data = super::credential::aws::get_aws_credentials(server, role_arn).await?;

    let access_key_id = data
        .get("AccessKeyId")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing AccessKeyId")?
        .to_string();
    let secret_access_key = SecretString::from(
        data.get("SecretAccessKey")
            .and_then(|v| v.as_str())
            .context("AWS credentials missing SecretAccessKey")?
            .to_string(),
    );
    let session_token = SecretString::from(
        data.get("SessionToken")
            .and_then(|v| v.as_str())
            .context("AWS credentials missing SessionToken")?
            .to_string(),
    );
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
/// Token is wrapped in `SecretString` for automatic zeroization on drop
/// and redacted `Debug` output.
pub(crate) struct GitHubEnvToken {
    pub token: SecretString,
}

impl std::fmt::Debug for GitHubEnvToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubEnvToken")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Fetch a GitHub token (cache-first) and extract the token value.
pub(crate) async fn fetch_github_token_cached(server: &str) -> Result<GitHubEnvToken> {
    let cache_key = "github";

    let data = cache::get_or_fetch(cache_key, "GitHub token", || async {
        let response = fetch_github_token(server).await?;
        let expires_at = response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(cache::default_expiry, String::from);
        Ok((response, expires_at))
    })
    .await?;

    let token = SecretString::from(
        data.get("token")
            .and_then(serde_json::Value::as_str)
            .context("GitHub credential missing 'token' field")?
            .to_string(),
    );

    Ok(GitHubEnvToken { token })
}

/// Run a command with credentials injected as environment variables.
pub(crate) async fn run(
    server: &str,
    credential_type: &CredentialType,
    role: Option<&str>,
    command: &[String],
    ca_opts: CodeArtifactOptions<'_>,
    rds_opts: RdsOptions<'_>,
    rs_opts: RedshiftOptions<'_>,
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
            inject_aws_credentials(&mut cmd, server, role_arn).await?;
        }
        CredentialType::Github => {
            inject_github_credentials(&mut cmd, server).await?;
        }
        CredentialType::Codeartifact => {
            inject_codeartifact_credentials(&mut cmd, server, &ca_opts).await?;
        }
        CredentialType::Rds => {
            inject_rds_credentials(&mut cmd, server, role, &rds_opts).await?;
        }
        CredentialType::Redshift => {
            inject_redshift_credentials(&mut cmd, server, role, &rs_opts).await?;
        }
        CredentialType::Anthropic => {
            inject_anthropic_credentials(&mut cmd, server).await?;
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
///
/// Also sets `AWS_EXECUTION_ENV` so that AWS SDK calls include Vouch in
/// the CloudTrail user-agent string.
///
/// See: <https://hackingthe.cloud/aws/general-knowledge/aws_cli_tips_and_tricks/#modifying-the-cloudtrail-log-user-agent-with-aws_execution_env>
async fn inject_aws_credentials(cmd: &mut Command, server: &str, role_arn: &str) -> Result<()> {
    let creds = fetch_aws_credentials(server, role_arn).await?;

    cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id);
    cmd.env(
        "AWS_SECRET_ACCESS_KEY",
        creds.secret_access_key.expose_secret(),
    );
    cmd.env("AWS_SESSION_TOKEN", creds.session_token.expose_secret());

    if let Some(ref v) = creds.expiration {
        cmd.env("AWS_CREDENTIAL_EXPIRATION", v);
    }

    cmd.env(
        "AWS_EXECUTION_ENV",
        format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")),
    );

    Ok(())
}

/// Fetch a GitHub token (cache-first) and inject it into the environment.
async fn inject_github_credentials(cmd: &mut Command, server: &str) -> Result<()> {
    let gh = fetch_github_token_cached(server).await?;

    cmd.env("GITHUB_TOKEN", gh.token.expose_secret());
    cmd.env("GH_TOKEN", gh.token.expose_secret());

    Ok(())
}

/// Fetch an Anthropic federation token (cache-first) and inject it into the
/// environment as `ANTHROPIC_AUTH_TOKEN`.
///
/// The minted `sk-ant-oat01-...` is an OAuth access token, so it is supplied
/// as a Bearer token (`ANTHROPIC_AUTH_TOKEN`), not an API key
/// (`ANTHROPIC_API_KEY`). It acts as a service account — the workload path,
/// intended for CI/headless automation.
async fn inject_anthropic_credentials(cmd: &mut Command, server: &str) -> Result<()> {
    let token = super::credential::anthropic::get_token(server).await?;
    cmd.env("ANTHROPIC_AUTH_TOKEN", token.expose_secret());
    Ok(())
}

/// Fetch a GitHub token from the Vouch server.
pub(crate) async fn fetch_github_token(server: &str) -> Result<serde_json::Value> {
    let client = crate::client::VouchClient::new(server).await?;
    client
        .post_authenticated(
            "/v1/credentials/github/token",
            &vouch_common::GitHubTokenRequest::default(),
        )
        .await
        .context("failed to get GitHub token from Vouch server")
}

/// Resolve CodeArtifact parameters and fetch a token.
pub(super) async fn fetch_codeartifact_token(
    server: &str,
    opts: &CodeArtifactOptions<'_>,
) -> Result<crate::integrations::aws::codeartifact::CodeArtifactToken> {
    let (domain, domain_owner, region) =
        super::credential::codeartifact::resolve_codeartifact_params(
            opts.domain,
            opts.domain_owner,
            opts.region,
            opts.profile,
        )?;

    super::credential::codeartifact::get_token(server, &domain, &domain_owner, &region)
        .await
        .context("failed to get CodeArtifact token")
}

/// Validated RDS credentials ready for environment injection.
pub(super) struct RdsEnvCredentials {
    pub token: SecretString,
    pub hostname: String,
    pub port: u16,
    pub username: String,
}

/// Validate RDS options and fetch an IAM auth token.
pub(super) async fn fetch_rds_with_opts(
    server: &str,
    role: Option<&str>,
    opts: &RdsOptions<'_>,
) -> Result<RdsEnvCredentials> {
    let hostname = opts.hostname.context(
        "RDS credentials require --rds-hostname. \
         Usage: vouch {exec|env} --type rds --rds-hostname <host> --rds-username <user>",
    )?;
    let username = opts.username.context(
        "RDS credentials require --rds-username. \
         Usage: vouch {exec|env} --type rds --rds-hostname <host> --rds-username <user>",
    )?;

    let token = super::credential::rds::fetch_rds_token(
        server,
        hostname,
        opts.port,
        username,
        opts.region,
        role,
    )
    .await?;

    Ok(RdsEnvCredentials {
        token,
        hostname: hostname.to_string(),
        port: opts.port,
        username: username.to_string(),
    })
}

/// Resolve Redshift target, role, and region, then fetch credentials.
pub(super) async fn fetch_redshift_with_opts(
    server: &str,
    role: Option<&str>,
    opts: &RedshiftOptions<'_>,
) -> Result<crate::integrations::aws::redshift::RedshiftCredentials> {
    let target = super::credential::redshift::resolve_target(
        opts.cluster_id,
        opts.workgroup,
        opts.duration,
    )?;

    let (role_arn, region_name) =
        crate::integrations::aws::resolve_role_and_region(role, opts.region)?;

    let agent_source = super::credential::aws::detect_agent_source();
    super::credential::redshift::fetch_redshift_credentials(
        server,
        &target,
        opts.db_name,
        &region_name,
        &role_arn,
        agent_source.as_deref(),
    )
    .await
}

/// Fetch a CodeArtifact token and inject it into the environment.
async fn inject_codeartifact_credentials(
    cmd: &mut Command,
    server: &str,
    opts: &CodeArtifactOptions<'_>,
) -> Result<()> {
    let token = fetch_codeartifact_token(server, opts).await?;

    cmd.env(
        "CODEARTIFACT_AUTH_TOKEN",
        token.authorization_token.expose_secret(),
    );

    Ok(())
}

/// Fetch an RDS IAM auth token and inject PostgreSQL env vars.
async fn inject_rds_credentials(
    cmd: &mut Command,
    server: &str,
    role: Option<&str>,
    opts: &RdsOptions<'_>,
) -> Result<()> {
    let rds = fetch_rds_with_opts(server, role, opts).await?;

    cmd.env("PGPASSWORD", rds.token.expose_secret());
    cmd.env("PGHOST", &rds.hostname);
    cmd.env("PGPORT", rds.port.to_string());
    cmd.env("PGUSER", &rds.username);
    cmd.env("PGSSLMODE", "require");

    Ok(())
}

/// Fetch Redshift credentials and inject PostgreSQL env vars.
async fn inject_redshift_credentials(
    cmd: &mut Command,
    server: &str,
    role: Option<&str>,
    opts: &RedshiftOptions<'_>,
) -> Result<()> {
    let creds = fetch_redshift_with_opts(server, role, opts).await?;

    cmd.env("PGPASSWORD", creds.db_password.expose_secret());
    cmd.env("PGUSER", &creds.db_user);
    cmd.env("PGSSLMODE", "require");

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::commands::credential::aws::CredentialProcessOutput;

    /// Verify that `AwsEnvCredentials` can be extracted from the JSON produced
    /// by `CredentialProcessOutput::to_json()`. This tests the contract between
    /// the serialization in `aws.rs` and the extraction in `exec.rs`.
    #[test]
    fn test_aws_env_credentials_from_cached_json() {
        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: SecretString::from("secret-key".to_string()),
            session_token: SecretString::from("session-token".to_string()),
            expiration: "2024-01-14T18:00:00Z".to_string(),
        };

        let data = output.to_json();

        // Extract using the same logic as fetch_aws_credentials
        let access_key_id = data
            .get("AccessKeyId")
            .and_then(|v| v.as_str())
            .expect("AccessKeyId must be present");
        let secret_access_key = data
            .get("SecretAccessKey")
            .and_then(|v| v.as_str())
            .expect("SecretAccessKey must be present");
        let session_token = data
            .get("SessionToken")
            .and_then(|v| v.as_str())
            .expect("SessionToken must be present");
        let expiration = data
            .get("Expiration")
            .and_then(|v| v.as_str())
            .map(String::from);

        assert_eq!(access_key_id, "AKIAEXAMPLE");
        assert_eq!(secret_access_key, "secret-key");
        assert_eq!(session_token, "session-token");
        assert_eq!(expiration.as_deref(), Some("2024-01-14T18:00:00Z"));
    }

    /// Verify the `GitHubEnvToken` Debug impl redacts the token.
    #[test]
    fn test_github_env_token_debug_redacts() {
        let gh = GitHubEnvToken {
            token: SecretString::from("ghu_secret_token".to_string()),
        };
        let debug = format!("{gh:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ghu_secret_token"));
    }

    /// Verify the `AwsEnvCredentials` Debug impl redacts secrets but shows access_key_id.
    #[test]
    fn test_aws_env_credentials_debug_redacts() {
        let creds = AwsEnvCredentials {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: SecretString::from("wJalrXUtnFEMI".to_string()),
            session_token: SecretString::from("FwoGZXIvYXdz".to_string()),
            expiration: Some("2024-01-14T18:00:00Z".to_string()),
        };
        let debug = format!("{creds:?}");
        assert!(debug.contains("[REDACTED]"));
        // access_key_id is semi-public and should be visible in debug output
        assert!(debug.contains("AKIAEXAMPLE"));
        // secret fields must not appear
        assert!(!debug.contains("wJalrXUtnFEMI"));
        assert!(!debug.contains("FwoGZXIvYXdz"));
    }
}
