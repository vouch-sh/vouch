// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Env command - output credential environment variables for the current shell.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use super::CredentialType;
use super::exec::{CodeArtifactOptions, RdsOptions, RedshiftOptions};

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
    ca_opts: CodeArtifactOptions<'_>,
    rds_opts: RdsOptions<'_>,
    rs_opts: RedshiftOptions<'_>,
) -> Result<()> {
    match credential_type {
        CredentialType::Aws => {
            let role_arn = role.context(
                "AWS credentials require --role. Usage: vouch env --type aws --role <ARN>",
            )?;
            print_aws_env(server, role_arn, shell).await
        }
        CredentialType::Github => print_github_env(server, shell).await,
        CredentialType::Codeartifact => print_codeartifact_env(server, &ca_opts, shell).await,
        CredentialType::Rds => print_rds_env(server, role, &rds_opts, shell).await,
        CredentialType::Redshift => print_redshift_env(server, role, &rs_opts, shell).await,
    }
}

/// Fetch AWS credentials (cache-first) and print export statements.
///
/// Also sets `AWS_EXECUTION_ENV` so that AWS SDK calls include Vouch in
/// the CloudTrail user-agent string.
///
/// See: <https://hackingthe.cloud/aws/general-knowledge/aws_cli_tips_and_tricks/#modifying-the-cloudtrail-log-user-agent-with-aws_execution_env>
async fn print_aws_env(server: &str, role_arn: &str, shell: &Shell) -> Result<()> {
    let creds = super::exec::fetch_aws_credentials(server, role_arn).await?;

    print_export(shell, "AWS_ACCESS_KEY_ID", &creds.access_key_id);
    print_export(
        shell,
        "AWS_SECRET_ACCESS_KEY",
        creds.secret_access_key.expose_secret(),
    );
    print_export(
        shell,
        "AWS_SESSION_TOKEN",
        creds.session_token.expose_secret(),
    );

    if let Some(ref v) = creds.expiration {
        print_export(shell, "AWS_CREDENTIAL_EXPIRATION", v);
    }

    print_export(
        shell,
        "AWS_EXECUTION_ENV",
        &format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")),
    );

    Ok(())
}

/// Fetch GitHub token (cache-first) and print export statements.
async fn print_github_env(server: &str, shell: &Shell) -> Result<()> {
    let gh = super::exec::fetch_github_token_cached(server).await?;

    print_export(shell, "GITHUB_TOKEN", gh.token.expose_secret());
    print_export(shell, "GH_TOKEN", gh.token.expose_secret());

    Ok(())
}

/// Fetch CodeArtifact token and print export statement.
async fn print_codeartifact_env(
    server: &str,
    opts: &CodeArtifactOptions<'_>,
    shell: &Shell,
) -> Result<()> {
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

/// Fetch RDS IAM auth token and print PostgreSQL export statements.
async fn print_rds_env(
    server: &str,
    role: Option<&str>,
    opts: &RdsOptions<'_>,
    shell: &Shell,
) -> Result<()> {
    let hostname = opts.hostname.context(
        "RDS credentials require --rds-hostname. \
         Usage: vouch env --type rds --rds-hostname <host> --rds-username <user>",
    )?;
    let username = opts.username.context(
        "RDS credentials require --rds-username. \
         Usage: vouch env --type rds --rds-hostname <host> --rds-username <user>",
    )?;

    let token =
        super::credential::rds::fetch_rds_token(server, hostname, opts.port, username, None, role)
            .await?;

    print_export(shell, "PGPASSWORD", token.expose_secret());
    print_export(shell, "PGHOST", hostname);
    print_export(shell, "PGPORT", &opts.port.to_string());
    print_export(shell, "PGUSER", username);
    print_export(shell, "PGSSLMODE", "require");

    Ok(())
}

/// Fetch Redshift credentials and print PostgreSQL export statements.
async fn print_redshift_env(
    server: &str,
    role: Option<&str>,
    opts: &RedshiftOptions<'_>,
    shell: &Shell,
) -> Result<()> {
    let target = super::credential::redshift::resolve_target(
        opts.cluster_id,
        opts.workgroup,
        opts.duration,
    )?;

    let (role_arn, region_name) = crate::integrations::aws::resolve_role_and_region(role, None)?;

    let creds = super::credential::redshift::fetch_redshift_credentials(
        server,
        &target,
        opts.db_name,
        &region_name,
        &role_arn,
    )
    .await?;

    print_export(shell, "PGPASSWORD", creds.db_password.expose_secret());
    print_export(shell, "PGUSER", &creds.db_user);
    print_export(shell, "PGSSLMODE", "require");

    Ok(())
}

/// Format a single shell export statement with proper quoting.
///
/// Values are single-quoted to prevent shell injection. Any embedded single
/// quotes are escaped using the `'\''` idiom (end quote, escaped quote, start
/// quote).
fn format_export(shell: &Shell, key: &str, value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    match shell {
        Shell::Bash => format!("export {key}='{escaped}';"),
        Shell::Fish => format!("set -gx {key} '{escaped}';"),
    }
}

/// Print a single shell export statement with proper quoting.
fn print_export(shell: &Shell, key: &str, value: &str) {
    println!("{}", format_export(shell, key, value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_export_bash() {
        assert_eq!(
            format_export(&Shell::Bash, "FOO", "bar"),
            "export FOO='bar';"
        );
    }

    #[test]
    fn test_format_export_fish() {
        assert_eq!(
            format_export(&Shell::Fish, "FOO", "bar"),
            "set -gx FOO 'bar';"
        );
    }

    #[test]
    fn test_shell_quoting_escapes_single_quotes() {
        let value = "it's a test";
        assert_eq!(
            format_export(&Shell::Bash, "X", value),
            "export X='it'\\''s a test';"
        );
    }

    #[test]
    fn test_shell_quoting_preserves_special_chars() {
        // Shell metacharacters are safely contained within single quotes
        let value = "$(whoami) `id` ; rm -rf /";
        assert_eq!(
            format_export(&Shell::Bash, "X", value),
            "export X='$(whoami) `id` ; rm -rf /';"
        );
    }

    /// Verify exact AWS environment variable names used by AWS CLI/SDKs.
    #[test]
    fn test_aws_env_variable_names_bash() {
        let key_id = format_export(&Shell::Bash, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        let secret = format_export(&Shell::Bash, "AWS_SECRET_ACCESS_KEY", "secret");
        let token = format_export(&Shell::Bash, "AWS_SESSION_TOKEN", "token");
        let expiration = format_export(
            &Shell::Bash,
            "AWS_CREDENTIAL_EXPIRATION",
            "2024-01-14T18:00:00Z",
        );

        assert_eq!(key_id, "export AWS_ACCESS_KEY_ID='AKIAEXAMPLE';");
        assert_eq!(secret, "export AWS_SECRET_ACCESS_KEY='secret';");
        assert_eq!(token, "export AWS_SESSION_TOKEN='token';");
        assert_eq!(
            expiration,
            "export AWS_CREDENTIAL_EXPIRATION='2024-01-14T18:00:00Z';"
        );
    }

    /// Verify exact GitHub environment variable names.
    #[test]
    fn test_github_env_variable_names_bash() {
        let github = format_export(&Shell::Bash, "GITHUB_TOKEN", "ghu_example");
        let gh = format_export(&Shell::Bash, "GH_TOKEN", "ghu_example");

        assert_eq!(github, "export GITHUB_TOKEN='ghu_example';");
        assert_eq!(gh, "export GH_TOKEN='ghu_example';");
    }

    /// Verify exact CodeArtifact environment variable name.
    #[test]
    fn test_codeartifact_env_variable_name_bash() {
        let ca = format_export(&Shell::Bash, "CODEARTIFACT_AUTH_TOKEN", "ca-token");
        assert_eq!(ca, "export CODEARTIFACT_AUTH_TOKEN='ca-token';");
    }

    /// Verify Fish shell format with AWS variable names.
    #[test]
    fn test_aws_env_variable_names_fish() {
        let key_id = format_export(&Shell::Fish, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        assert_eq!(key_id, "set -gx AWS_ACCESS_KEY_ID 'AKIAEXAMPLE';");
    }

    /// Verify AWS_EXECUTION_ENV format matches our user-agent string.
    #[test]
    fn test_aws_execution_env_format() {
        let value = format!("vouch-cli/{}", env!("CARGO_PKG_VERSION"));
        let export = format_export(&Shell::Bash, "AWS_EXECUTION_ENV", &value);
        assert!(export.starts_with("export AWS_EXECUTION_ENV='vouch-cli/"));
        assert!(export.ends_with("';"));
    }

    /// Verify exact RDS PostgreSQL environment variable names.
    #[test]
    fn test_rds_env_variable_names_bash() {
        let pw = format_export(&Shell::Bash, "PGPASSWORD", "rds-token");
        let host = format_export(&Shell::Bash, "PGHOST", "mydb.rds.amazonaws.com");
        let port = format_export(&Shell::Bash, "PGPORT", "5432");
        let user = format_export(&Shell::Bash, "PGUSER", "admin");
        let ssl = format_export(&Shell::Bash, "PGSSLMODE", "require");

        assert_eq!(pw, "export PGPASSWORD='rds-token';");
        assert_eq!(host, "export PGHOST='mydb.rds.amazonaws.com';");
        assert_eq!(port, "export PGPORT='5432';");
        assert_eq!(user, "export PGUSER='admin';");
        assert_eq!(ssl, "export PGSSLMODE='require';");
    }

    /// Verify exact Redshift PostgreSQL environment variable names.
    #[test]
    fn test_redshift_env_variable_names_bash() {
        let pw = format_export(&Shell::Bash, "PGPASSWORD", "redshift-pw");
        let user = format_export(&Shell::Bash, "PGUSER", "IAMR:my-role");
        let ssl = format_export(&Shell::Bash, "PGSSLMODE", "require");

        assert_eq!(pw, "export PGPASSWORD='redshift-pw';");
        assert_eq!(user, "export PGUSER='IAMR:my-role';");
        assert_eq!(ssl, "export PGSSLMODE='require';");
    }

    /// Verify RDS env variables in Fish shell format.
    #[test]
    fn test_rds_env_variable_names_fish() {
        let pw = format_export(&Shell::Fish, "PGPASSWORD", "rds-token");
        let host = format_export(&Shell::Fish, "PGHOST", "mydb.rds.amazonaws.com");
        assert_eq!(pw, "set -gx PGPASSWORD 'rds-token';");
        assert_eq!(host, "set -gx PGHOST 'mydb.rds.amazonaws.com';");
    }
}
