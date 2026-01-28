// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub credential helper for git.
//!
//! This module implements a git credential helper that provides GitHub
//! authentication using Vouch. It reads git credential protocol from stdin
//! and outputs credentials to stdout.
//!
//! Usage: Configure git to use this helper:
//!   git config --global credential.https://github.com.helper "vouch credential github"
//!
//! Or use `vouch setup github --configure` to set this up automatically.

use anyhow::{Context, Result};
use std::io::{BufRead, Write};
use vouch_common::{GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse};

use crate::client::VouchClient;
use crate::config::Config;

/// Git credential protocol input.
#[derive(Debug, Default)]
struct CredentialInput {
    protocol: Option<String>,
    host: Option<String>,
    path: Option<String>,
}

/// Parse git credential protocol input from stdin.
fn read_credential_input() -> Result<CredentialInput> {
    let stdin = std::io::stdin();
    let mut input = CredentialInput::default();

    for line in stdin.lock().lines() {
        let line = line.context("failed to read stdin")?;
        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = line.split_once('=') {
            match key {
                "protocol" => input.protocol = Some(value.to_string()),
                "host" => input.host = Some(value.to_string()),
                "path" => input.path = Some(value.to_string()),
                _ => {} // Ignore other fields
            }
        }
    }

    Ok(input)
}

/// Check if the host is a GitHub host.
fn is_github_host(host: &str) -> bool {
    let host = host.to_lowercase();
    host == "github.com"
        || host.ends_with(".github.com")
        || host.ends_with(".ghe.com")
        || host == "ghe.com"
}

/// Extract the owner from a repository path.
/// Path format: "owner/repo.git" or "owner/repo"
fn extract_owner(path: Option<&str>) -> Option<String> {
    path.and_then(|p| {
        let p = p.trim_start_matches('/');
        p.split('/').next().map(String::from)
    })
}

/// Run the git credential helper.
///
/// # Arguments
/// * `operation` - The git credential operation ("get", "store", or "erase")
pub async fn run(operation: &str) -> Result<()> {
    match operation {
        "get" => get_credential().await,
        "store" | "erase" => {
            // These operations are no-ops for Vouch since we don't store credentials
            Ok(())
        }
        _ => {
            // Unknown operation, silently ignore
            Ok(())
        }
    }
}

/// Handle the "get" operation - provide credentials to git.
async fn get_credential() -> Result<()> {
    // Read credential request from stdin
    let input = read_credential_input()?;

    // Only handle HTTPS to GitHub hosts
    let protocol = input.protocol.as_deref().unwrap_or("");
    let host = input.host.as_deref().unwrap_or("");

    if protocol != "https" || !is_github_host(host) {
        // Not a GitHub request, let git try other helpers
        return Ok(());
    }

    // Load config
    let config = Config::load().map_err(|e| {
        eprintln!("vouch: failed to load config: {e}");
        e
    })?;

    let server = config.server_url().ok_or_else(|| {
        eprintln!("vouch: not configured - run 'vouch enroll' first");
        anyhow::anyhow!("not configured")
    })?;

    // Create client
    let client = VouchClient::new(server).map_err(|e| {
        eprintln!("vouch: failed to create client: {e}");
        e
    })?;

    // Extract owner from path (e.g., "acme-corp/my-repo.git" -> "acme-corp")
    let owner = extract_owner(input.path.as_deref());

    // Request token from server
    let request = GitHubTokenRequest {
        owner,
        repositories: None,
    };

    let response: GitHubTokenResponse = client
        .post_authenticated("/v1/credentials/github/token", &request)
        .await
        .map_err(|e| {
            eprintln!("vouch: failed to get GitHub token: {e}");
            e
        })?;

    // Output credentials to stdout in git credential protocol format
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "protocol={protocol}")?;
    writeln!(out, "host={host}")?;
    writeln!(out, "username=x-access-token")?;
    writeln!(out, "password={}", response.token)?;
    writeln!(out)?;

    Ok(())
}

/// Check GitHub integration status.
pub async fn check_status(server: &str) -> Result<GitHubStatusResponse> {
    let client = VouchClient::new(server)?;
    client
        .get_authenticated("/v1/credentials/github/status")
        .await
}
