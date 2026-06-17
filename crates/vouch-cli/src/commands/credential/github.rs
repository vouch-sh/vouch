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

use anyhow::Result;
use secrecy::ExposeSecret;
use vouch_common::{GitHubStatusResponse, GitHubTokenRequest, GitHubTokenResponse};

use crate::client::VouchClient;
use crate::commands::credential::git_protocol::read_credential_input;
use crate::session::resolve_session;

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
pub(crate) async fn run(operation: &str) -> Result<()> {
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

    // Resolve session (tries agent first, then config)
    let session = resolve_session().await.inspect_err(|_| {
        vouch_cli::tr_eprintln!("credential-helper-err-not-configured");
    })?;

    // Create authenticated client
    let client = VouchClient::from_session(&session).inspect_err(|e| {
        vouch_cli::tr_eprintln!("credential-github-err-create-client", error = e.to_string());
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
        .inspect_err(|e| {
            vouch_cli::tr_eprintln!("credential-github-err-fetch-token", error = e.to_string());
        })?;

    // Output credentials to stdout in git credential protocol format
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    super::git_protocol::write_credential_output(
        &mut out,
        protocol,
        host,
        "x-access-token",
        response.token.expose_secret(),
    )?;

    Ok(())
}

/// Check GitHub integration status.
pub(crate) async fn check_status(server: &str) -> Result<GitHubStatusResponse> {
    let client = VouchClient::new(server).await?;
    client
        .get_authenticated("/v1/credentials/github/status")
        .await
}
