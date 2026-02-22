// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Env command - output credential environment variables for the current shell.

use anyhow::{Context, Result};

use super::CredentialType;
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
    credential_type: &CredentialType,
    shell: &Shell,
    role: Option<&str>,
    session_name: Option<&str>,
    ca_opts: CodeArtifactOptions<'_>,
) -> Result<()> {
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
    let creds = super::exec::fetch_aws_credentials(server, role_arn, session_name).await?;

    print_export(shell, "AWS_ACCESS_KEY_ID", &creds.access_key_id);
    print_export(shell, "AWS_SECRET_ACCESS_KEY", &creds.secret_access_key);
    print_export(shell, "AWS_SESSION_TOKEN", &creds.session_token);

    if let Some(ref v) = creds.expiration {
        print_export(shell, "AWS_CREDENTIAL_EXPIRATION", v);
    }

    Ok(())
}

/// Fetch GitHub token (cache-first) and print export statements.
async fn print_github_env(server: &str, shell: &Shell) -> Result<()> {
    let gh = super::exec::fetch_github_token_cached(server).await?;

    print_export(shell, "GITHUB_TOKEN", &gh.token);
    print_export(shell, "GH_TOKEN", &gh.token);

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
