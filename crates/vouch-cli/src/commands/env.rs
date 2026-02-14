// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Env command - output credential environment variables for the current shell.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::client::VouchClient;
use crate::integrations::aws::sts::{
    assume_role_with_web_identity, extract_partition_from_role_arn,
    get_default_region_for_partition, get_domain_suffix_for_partition,
};
use crate::session::get_user_email;

use super::credential::aws::{OidcTokenResponse, build_session_tags, decode_jwt_payload};

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

/// Fetch AWS credentials and print export statements.
async fn print_aws_env(
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
    shell: &Shell,
) -> Result<()> {
    let client = VouchClient::new(server)?;

    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    let tags = decode_jwt_payload(&token_response.id_token)
        .map(|claims| build_session_tags(&claims))
        .unwrap_or_default();

    let partition = extract_partition_from_role_arn(role_arn).unwrap_or("aws");
    let region = get_default_region_for_partition(partition);
    let domain_suffix = get_domain_suffix_for_partition(partition);

    let email = get_user_email(server).await;
    let session = session_name.or(email.as_deref()).unwrap_or("vouch-session");

    let sts_response = assume_role_with_web_identity(
        role_arn,
        session,
        &token_response.id_token,
        region,
        domain_suffix,
        &tags,
    )
    .await
    .context("failed to assume AWS role")?;

    let creds = &sts_response
        .assume_role_with_web_identity_result
        .credentials;

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
    print_export(shell, "AWS_CREDENTIAL_EXPIRATION", &creds.expiration);

    Ok(())
}

/// Fetch GitHub token and print export statements.
async fn print_github_env(server: &str, shell: &Shell) -> Result<()> {
    let client = VouchClient::new(server)?;

    let response: serde_json::Value = client
        .get_authenticated("/v1/credentials/github/token")
        .await
        .context("failed to get GitHub token from Vouch server")?;

    let token = response
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("server response missing 'token' field")?;

    print_export(shell, "GITHUB_TOKEN", token);
    print_export(shell, "GH_TOKEN", token);

    Ok(())
}

/// Print a single shell export statement.
fn print_export(shell: &Shell, key: &str, value: &str) {
    match shell {
        Shell::Bash => println!("export {key}={value};"),
        Shell::Fish => println!("set -gx {key} {value};"),
    }
}
