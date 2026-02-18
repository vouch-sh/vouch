// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Env command - output credential environment variables for the current shell.

use anyhow::{Context, Result};

use super::credential::cache;
use super::exec::CodeArtifactOptions;

/// Shell format for environment variable output.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Shell {
    /// Bash / Zsh (export VAR=value).
    Bash,
    /// Fish (set -gx VAR value).
    Fish,
}

/// Run the env command - output shell-evaluable credential exports.
pub async fn run(
    server: &str,
    credential_type: &super::exec::CredentialType,
    shell: &Shell,
    role: Option<&str>,
    session_name: Option<&str>,
    ca_opts: CodeArtifactOptions<'_>,
) -> Result<()> {
    use super::exec::CredentialType;
    match credential_type {
        CredentialType::Aws => {
            let role_arn = role.context(
                "AWS credentials require --role. Usage: vouch env --type aws --role <ARN>",
            )?;
            print_aws_env(server, role_arn, session_name, shell).await
        }
        CredentialType::Github => print_github_env(server, shell).await,
        CredentialType::Codeartifact => print_codeartifact_env(server, &ca_opts, shell).await,
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

    let data = cache::get_or_fetch(&cache_key, "AWS credentials", || async {
        let output =
            super::credential::aws::fetch_and_assume(server, role_arn, session_name).await?;
        let expires_at = output.expiration.clone();
        let data = serde_json::to_value(&output).context("failed to serialize credentials")?;
        Ok((data, expires_at))
    })
    .await?;

    let key_id = data
        .get("AccessKeyId")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing AccessKeyId")?;
    let secret = data
        .get("SecretAccessKey")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing SecretAccessKey")?;
    let token = data
        .get("SessionToken")
        .and_then(|v| v.as_str())
        .context("AWS credentials missing SessionToken")?;

    print_export(shell, "AWS_ACCESS_KEY_ID", key_id);
    print_export(shell, "AWS_SECRET_ACCESS_KEY", secret);
    print_export(shell, "AWS_SESSION_TOKEN", token);

    if let Some(v) = data.get("Expiration").and_then(|v| v.as_str()) {
        print_export(shell, "AWS_CREDENTIAL_EXPIRATION", v);
    }

    Ok(())
}

/// Fetch GitHub token (cache-first) and print export statements.
async fn print_github_env(server: &str, shell: &Shell) -> Result<()> {
    let cache_key = "github";

    let data = cache::get_or_fetch(cache_key, "GitHub token", || async {
        let response = super::exec::fetch_github_token(server).await?;
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
        .and_then(|v| v.as_str())
        .context("GitHub credential missing 'token' field")?;

    print_export(shell, "GITHUB_TOKEN", token);
    print_export(shell, "GH_TOKEN", token);

    Ok(())
}

/// Fetch CodeArtifact token and print export statement.
async fn print_codeartifact_env(
    server: &str,
    opts: &CodeArtifactOptions<'_>,
    shell: &Shell,
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

    print_export(
        shell,
        "CODEARTIFACT_AUTH_TOKEN",
        token.authorization_token.expose_secret(),
    );

    Ok(())
}

/// Print a single shell export statement with proper quoting.
///
/// Values are single-quoted to prevent shell injection. Any embedded single
/// quotes are escaped using the `'\''` idiom (end quote, escaped quote, start
/// quote).
fn print_export(shell: &Shell, key: &str, value: &str) {
    let escaped = value.replace('\'', "'\\''");
    match shell {
        Shell::Bash => println!("export {key}='{escaped}';"),
        Shell::Fish => println!("set -gx {key} '{escaped}';"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_export_bash_simple() {
        // Just verify it doesn't panic - output goes to stdout
        print_export(&Shell::Bash, "FOO", "bar");
    }

    #[test]
    fn test_print_export_fish_simple() {
        print_export(&Shell::Fish, "FOO", "bar");
    }

    #[test]
    fn test_shell_quoting_escapes_single_quotes() {
        // The value contains a single quote which must be escaped
        let value = "it's a test";
        let escaped = value.replace('\'', "'\\''");
        assert_eq!(escaped, "it'\\''s a test");
    }

    #[test]
    fn test_shell_quoting_preserves_special_chars() {
        // Verify that shell metacharacters are safely contained within single quotes
        let value = "$(whoami) `id` ; rm -rf /";
        let escaped = value.replace('\'', "'\\''");
        // No single quotes in input, so no escaping needed - single quotes protect everything
        assert_eq!(escaped, value);
    }
}
