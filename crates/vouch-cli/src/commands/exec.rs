// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exec command - run a command with Vouch-provided credentials in the environment.

use anyhow::{Context, Result, bail};
use std::process::Command;

use super::credential::cache;

/// Credential type to inject into the subprocess environment.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum CredentialType {
    /// AWS temporary credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
    Aws,
    /// GitHub token (GITHUB_TOKEN, GH_TOKEN).
    Github,
}

/// Run a command with credentials injected as environment variables.
pub async fn run(
    server: &str,
    credential_type: &CredentialType,
    role: Option<&str>,
    session_name: Option<&str>,
    command: &[String],
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
    }

    // Execute the command, replacing our process
    let status = cmd
        .status()
        .with_context(|| format!("failed to execute: {program}"))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        bail!("command exited with status {code}");
    }

    Ok(())
}

/// Fetch AWS STS credentials (cache-first) and inject them into the environment.
async fn inject_aws_credentials(
    cmd: &mut Command,
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
) -> Result<()> {
    let cache_key = format!("aws:{role_arn}");

    // Try cache first, then server + STS, then cache fallback on network error
    let data = match cache::get(&cache_key).await {
        Some(cached) => cached,
        None => {
            match super::credential::aws::fetch_and_assume(server, role_arn, session_name).await {
                Ok(output) => {
                    let data =
                        serde_json::to_value(&output).context("failed to serialize credentials")?;
                    cache::store(&cache_key, data.clone(), &output.expiration).await;
                    data
                }
                Err(e) if cache::is_network_error(&e) => {
                    if let Some(cached) = cache::get(&cache_key).await {
                        eprintln!("vouch: using cached AWS credentials (server unreachable)");
                        cached
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    };

    if let Some(v) = data.get("AccessKeyId").and_then(|v| v.as_str()) {
        cmd.env("AWS_ACCESS_KEY_ID", v);
    }
    if let Some(v) = data.get("SecretAccessKey").and_then(|v| v.as_str()) {
        cmd.env("AWS_SECRET_ACCESS_KEY", v);
    }
    if let Some(v) = data.get("SessionToken").and_then(|v| v.as_str()) {
        cmd.env("AWS_SESSION_TOKEN", v);
    }
    if let Some(v) = data.get("Expiration").and_then(|v| v.as_str()) {
        cmd.env("AWS_CREDENTIAL_EXPIRATION", v);
    }

    Ok(())
}

/// Fetch a GitHub token (cache-first) and inject it into the environment.
async fn inject_github_credentials(cmd: &mut Command, server: &str) -> Result<()> {
    let cache_key = "github";

    let data = match cache::get(cache_key).await {
        Some(cached) => cached,
        None => match fetch_github_token(server).await {
            Ok(response) => {
                let expires_at = response
                    .get("expires_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                cache::store(cache_key, response.clone(), expires_at).await;
                response
            }
            Err(e) if cache::is_network_error(&e) => {
                if let Some(cached) = cache::get(cache_key).await {
                    eprintln!("vouch: using cached GitHub token (server unreachable)");
                    cached
                } else {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        },
    };

    let token = data
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("cached credential missing 'token' field")?;

    cmd.env("GITHUB_TOKEN", token);
    cmd.env("GH_TOKEN", token);

    Ok(())
}

/// Fetch a GitHub token from the Vouch server.
pub(crate) async fn fetch_github_token(server: &str) -> Result<serde_json::Value> {
    let client = crate::client::VouchClient::new(server)?;
    client
        .get_authenticated("/v1/credentials/github/token")
        .await
        .context("failed to get GitHub token from Vouch server")
}
