// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Env command - output credential environment variables for the current shell.

use anyhow::{Context, Result};

use super::credential::cache;

/// Shell format for environment variable output.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Shell {
    /// Bash / Zsh (export VAR=value).
    Bash,
    /// Fish (set -gx VAR value).
    Fish,
}

/// Credential type to export.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum CredentialType {
    Aws,
    Github,
}

/// Run the env command - output shell-evaluable credential exports.
pub async fn run(
    server: &str,
    credential_type: &CredentialType,
    shell: &Shell,
    role: Option<&str>,
    session_name: Option<&str>,
) -> Result<()> {
    match credential_type {
        CredentialType::Aws => {
            let role_arn = role.context(
                "AWS credentials require --role. Usage: vouch env --type aws --role <ARN>",
            )?;
            print_aws_env(server, role_arn, session_name, shell).await
        }
        CredentialType::Github => print_github_env(server, shell).await,
    }
}

/// Fetch AWS credentials (cache-first) and print export statements.
async fn print_aws_env(
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
    shell: &Shell,
) -> Result<()> {
    let cache_key = format!("aws:{role_arn}");

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
        print_export(shell, "AWS_ACCESS_KEY_ID", v);
    }
    if let Some(v) = data.get("SecretAccessKey").and_then(|v| v.as_str()) {
        print_export(shell, "AWS_SECRET_ACCESS_KEY", v);
    }
    if let Some(v) = data.get("SessionToken").and_then(|v| v.as_str()) {
        print_export(shell, "AWS_SESSION_TOKEN", v);
    }
    if let Some(v) = data.get("Expiration").and_then(|v| v.as_str()) {
        print_export(shell, "AWS_CREDENTIAL_EXPIRATION", v);
    }

    Ok(())
}

/// Fetch GitHub token (cache-first) and print export statements.
async fn print_github_env(server: &str, shell: &Shell) -> Result<()> {
    let cache_key = "github";

    let data = match cache::get(cache_key).await {
        Some(cached) => cached,
        None => match super::exec::fetch_github_token(server).await {
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

    if let Some(token) = data.get("token").and_then(|v| v.as_str()) {
        print_export(shell, "GITHUB_TOKEN", token);
        print_export(shell, "GH_TOKEN", token);
    }

    Ok(())
}

/// Print a single shell export statement.
fn print_export(shell: &Shell, key: &str, value: &str) {
    match shell {
        Shell::Bash => println!("export {key}={value};"),
        Shell::Fish => println!("set -gx {key} {value};"),
    }
}
