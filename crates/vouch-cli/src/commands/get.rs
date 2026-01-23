//! Get credentials for various services

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;
use crate::config::Config;
use crate::AwsOutputFormat;

// ============================================================================
// GitHub
// ============================================================================

#[derive(Serialize)]
struct GitHubCredentialRequest {
    repository: Option<String>,
}

#[derive(Deserialize)]
struct GitHubCredentialResponse {
    token: String,
    expires_at: String,
    repositories: Vec<String>,
}

pub async fn github(
    client: &VouchClient,
    config: &Config,
    repo: Option<String>,
) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    let req = GitHubCredentialRequest { repository: repo };
    let resp: GitHubCredentialResponse = client
        .post("/v1/credentials/github", &req, Some(token))
        .await
        .context("failed to get GitHub token")?;

    // Output just the token for easy piping
    println!("{}", resp.token);

    // Log details to stderr so they don't interfere with piping
    eprintln!(
        "{}",
        format!(
            "✓ GitHub token (expires {})",
            resp.expires_at
        )
        .green()
    );
    if !resp.repositories.is_empty() {
        eprintln!("  Repos: {}", resp.repositories.join(", "));
    }

    Ok(())
}

// ============================================================================
// AWS
// ============================================================================

#[derive(Serialize)]
struct AwsCredentialRequest {
    role_arn: String,
    session_name: Option<String>,
}

#[derive(Deserialize)]
struct AwsCredentialResponse {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at: String,
}

pub async fn aws(
    client: &VouchClient,
    config: &Config,
    role: String,
    session_name: Option<String>,
    format: AwsOutputFormat,
) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    let req = AwsCredentialRequest {
        role_arn: role,
        session_name,
    };
    let resp: AwsCredentialResponse = client
        .post("/v1/credentials/aws", &req, Some(token))
        .await
        .context("failed to get AWS credentials")?;

    match format {
        AwsOutputFormat::Env => {
            println!("export AWS_ACCESS_KEY_ID={}", resp.access_key_id);
            println!("export AWS_SECRET_ACCESS_KEY={}", resp.secret_access_key);
            println!("export AWS_SESSION_TOKEN={}", resp.session_token);
        }
        AwsOutputFormat::Json => {
            // Format expected by credential_process
            let output = serde_json::json!({
                "Version": 1,
                "AccessKeyId": resp.access_key_id,
                "SecretAccessKey": resp.secret_access_key,
                "SessionToken": resp.session_token,
                "Expiration": resp.expires_at
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        AwsOutputFormat::Ini => {
            println!("[default]");
            println!("aws_access_key_id = {}", resp.access_key_id);
            println!("aws_secret_access_key = {}", resp.secret_access_key);
            println!("aws_session_token = {}", resp.session_token);
        }
    }

    eprintln!(
        "{}",
        format!("✓ AWS credentials (expires {})", resp.expires_at).green()
    );

    Ok(())
}

// ============================================================================
// SSH
// ============================================================================

#[derive(Serialize)]
struct SshCredentialRequest {
    public_key: String,
    principals: Vec<String>,
}

#[derive(Deserialize)]
struct SshCredentialResponse {
    certificate: String,
    expires_at: String,
    principals: Vec<String>,
}

pub async fn ssh(
    client: &VouchClient,
    config: &Config,
    key_path: Option<String>,
    principals: Vec<String>,
) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    // Read public key
    let key_path = key_path.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.ssh/id_ed25519.pub", home)
    });

    let public_key = std::fs::read_to_string(&key_path)
        .with_context(|| format!("failed to read public key from {}", key_path))?;

    let req = SshCredentialRequest {
        public_key: public_key.trim().to_string(),
        principals,
    };

    let resp: SshCredentialResponse = client
        .post("/v1/credentials/ssh", &req, Some(token))
        .await
        .context("failed to get SSH certificate")?;

    // Output certificate
    println!("{}", resp.certificate);

    eprintln!(
        "{}",
        format!("✓ SSH certificate (expires {})", resp.expires_at).green()
    );
    eprintln!("  Principals: {}", resp.principals.join(", "));

    Ok(())
}
