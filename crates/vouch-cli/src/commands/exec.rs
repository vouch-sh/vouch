// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exec command - run a command with Vouch-provided credentials in the environment.

use anyhow::{Context, Result, bail};
use secrecy::ExposeSecret;
use std::process::Command;

use crate::client::VouchClient;
use crate::integrations::aws::sts::{
    assume_role_with_web_identity, extract_partition_from_role_arn,
    get_default_region_for_partition, get_domain_suffix_for_partition,
};
use crate::session::get_user_email;

use super::credential::aws::{OidcTokenResponse, build_session_tags, decode_jwt_payload};

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
        // Propagate the child's exit code via a special error
        // The main function will classify this as GENERAL (exit code 1)
        // but we use std::process::ExitCode::from directly
        bail!("command exited with status {code}");
    }

    Ok(())
}

/// Fetch AWS STS credentials and inject them into the command's environment.
async fn inject_aws_credentials(
    cmd: &mut Command,
    server: &str,
    role_arn: &str,
    session_name: Option<&str>,
) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Get OIDC token from Vouch server
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Decode JWT for session tags
    let tags = decode_jwt_payload(&token_response.id_token)
        .map(|claims| build_session_tags(&claims))
        .unwrap_or_default();

    // Determine region from role ARN
    let partition = extract_partition_from_role_arn(role_arn).unwrap_or("aws");
    let region = get_default_region_for_partition(partition);
    let domain_suffix = get_domain_suffix_for_partition(partition);

    // Get session name
    let email = get_user_email(server).await;
    let session = session_name.or(email.as_deref()).unwrap_or("vouch-session");

    // Call STS
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

    cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id);
    cmd.env(
        "AWS_SECRET_ACCESS_KEY",
        creds.secret_access_key.expose_secret(),
    );
    cmd.env("AWS_SESSION_TOKEN", creds.session_token.expose_secret());
    cmd.env("AWS_CREDENTIAL_EXPIRATION", &creds.expiration);

    Ok(())
}

/// Fetch a GitHub token and inject it into the command's environment.
async fn inject_github_credentials(cmd: &mut Command, server: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Use the same endpoint as `vouch credential github`
    let response: serde_json::Value = client
        .get_authenticated("/v1/credentials/github/token")
        .await
        .context("failed to get GitHub token from Vouch server")?;

    let token = response
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("server response missing 'token' field")?;

    cmd.env("GITHUB_TOKEN", token);
    cmd.env("GH_TOKEN", token);

    Ok(())
}
