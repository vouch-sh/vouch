// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeCommit credential helper and remote helper.
//!
//! Provides two modes of operation:
//!
//! 1. **Git credential helper** (`vouch credential codecommit get`):
//!    Called by git for `https://git-codecommit.*.amazonaws.com` URLs.
//!    Reads the git credential protocol from stdin, signs with SigV4,
//!    and outputs username/password.
//!
//! 2. **Git remote helper** (invoked as `git-remote-codecommit`):
//!    Called by git for `codecommit://` URLs. Generates a signed HTTPS URL
//!    and delegates to `git remote-http`.
//!
//! Both modes use the same signing core: Vouch OIDC -> STS -> SigV4 for CodeCommit.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use std::io::Write;

use crate::commands::credential::git_protocol::read_credential_input;
use crate::integrations::aws::codecommit::{
    extract_region_from_hostname, hostname_for_region, is_codecommit_host, parse_codecommit_url,
    sign_request,
};
use crate::integrations::aws::get_local_aws_role;
use crate::integrations::aws::sts::StsCredentials;

/// Run the git credential helper for CodeCommit.
///
/// # Arguments
/// * `operation` - The git credential operation ("get", "store", or "erase")
pub async fn run(operation: &str) -> Result<()> {
    match operation {
        "get" => get_credential().await,
        "store" | "erase" => {
            // No-ops for Vouch — we don't store credentials
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Handle the "get" operation — provide CodeCommit credentials to git.
async fn get_credential() -> Result<()> {
    let input = read_credential_input()?;

    let protocol = input.protocol.as_deref().unwrap_or("");
    let host = input.host.as_deref().unwrap_or("");

    if protocol != "https" || !is_codecommit_host(host) {
        return Ok(());
    }

    // Path is required for signing (useHttpPath must be true in git config)
    let path = input.path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "git did not provide the repository path.\n\
             Ensure useHttpPath is set:\n  \
             git config --global credential.\"https://git-codecommit.*.amazonaws.com\".useHttpPath true"
        )
    })?;

    let region = extract_region_from_hostname(host)
        .context("could not extract region from CodeCommit hostname")?;

    // Path from git doesn't have leading slash; SigV4 canonical URI requires it
    let canonical_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    let creds = get_sts_credentials(region).await?;
    let signed = sign_request(&creds, host, &canonical_path, region);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "protocol={protocol}")?;
    writeln!(out, "host={host}")?;
    writeln!(out, "username={}", signed.username.expose_secret())?;
    writeln!(out, "password={}", signed.password.expose_secret())?;
    writeln!(out)?;

    Ok(())
}

/// Run the git remote helper for `codecommit://` URLs.
///
/// Called when the binary is invoked as `git-remote-codecommit`.
/// Parses the `codecommit://` URL, generates a signed HTTPS URL,
/// and delegates to `git remote-http`.
///
/// # Arguments
/// * `remote_name` - The git remote name (e.g., "origin")
/// * `url` - The `codecommit://` URL
pub async fn run_remote_helper(remote_name: &str, url: &str) -> Result<()> {
    let parsed = parse_codecommit_url(url).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid CodeCommit URL: {url}\n\
             Expected: codecommit://[profile@]repo-name\n\
             Or:       codecommit::region://[profile@]repo-name"
        )
    })?;

    // Resolve region: URL > AWS config > default
    let region = resolve_region(parsed.region.as_deref(), parsed.profile.as_deref())?;

    let hostname = hostname_for_region(&region);
    let path = format!("/v1/repos/{}", parsed.repository);

    let creds = get_sts_credentials(&region).await?;
    let signed = sign_request(&creds, &hostname, &path, &region);

    // Percent-encode credentials for URL embedding
    let encoded_username = percent_encode(signed.username.expose_secret());
    let encoded_password = percent_encode(signed.password.expose_secret());

    let signed_url = format!("https://{encoded_username}:{encoded_password}@{hostname}{path}");

    // Delegate to git remote-http, replacing this process on Unix
    exec_git_remote_http(remote_name, &signed_url)
}

/// Get temporary AWS credentials via Vouch OIDC -> STS flow, with caching.
///
/// Reuses the shared `fetch_and_assume` from the AWS credential module to avoid
/// duplicating the OIDC → STS logic, and wraps it with the agent credential cache.
async fn get_sts_credentials(_region: &str) -> Result<StsCredentials> {
    let session = crate::session::resolve_session()
        .await
        .context("not configured - run 'vouch enroll' first")?;

    let server = session.server_url;

    let role_arn = get_local_aws_role().ok_or_else(|| {
        anyhow::anyhow!(
            "AWS not configured. Run 'vouch setup aws --role <role-arn>' with a role \
             that has CodeCommit permissions"
        )
    })?;

    let cache_key = format!("aws:{role_arn}");

    let data = super::cache::get_or_fetch(&cache_key, "AWS credentials", || async {
        let output =
            super::aws::fetch_and_assume(&server, &role_arn, Some("vouch-codecommit")).await?;
        let expires_at = output.expiration.clone();
        let data = serde_json::to_value(&output).context("failed to serialize credentials")?;
        Ok((data, expires_at))
    })
    .await?;

    // Extract STS credentials from the cached JSON
    let access_key_id = data
        .get("AccessKeyId")
        .and_then(serde_json::Value::as_str)
        .context("missing AccessKeyId in cached credentials")?
        .to_string();
    let secret_access_key = data
        .get("SecretAccessKey")
        .and_then(serde_json::Value::as_str)
        .context("missing SecretAccessKey in cached credentials")?
        .to_string();
    let session_token = data
        .get("SessionToken")
        .and_then(serde_json::Value::as_str)
        .context("missing SessionToken in cached credentials")?
        .to_string();
    let expiration = data
        .get("Expiration")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

    Ok(StsCredentials {
        access_key_id,
        secret_access_key: secrecy::SecretString::from(secret_access_key),
        session_token: secrecy::SecretString::from(session_token),
        expiration,
    })
}

/// Resolve the AWS region for a CodeCommit operation.
///
/// Priority: explicit URL region > specified profile's region > vouch profile region > us-east-1.
fn resolve_region(url_region: Option<&str>, profile: Option<&str>) -> Result<String> {
    if let Some(region) = url_region {
        return Ok(region.to_string());
    }

    if let Ok(aws_config) = crate::integrations::aws::AwsConfig::load() {
        // If a profile was specified in the URL, try to look up its region
        if let Some(profile_name) = profile
            && let Some(profile_data) = aws_config.get_profile(profile_name)
            && let Some(region) = profile_data.region
        {
            return Ok(region);
        }

        // Fall back to the vouch AWS profile's region
        if let Some(vouch_profile) = aws_config.find_vouch_profile()
            && let Some(region) = vouch_profile.region
        {
            return Ok(region);
        }
    }

    // Default to us-east-1
    Ok("us-east-1".to_string())
}

/// Percent-encode a string for use in a URL.
///
/// Encodes all characters except unreserved characters (RFC 3986):
/// `A-Z a-z 0-9 - _ . ~`
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Execute `git remote-http` with the signed URL.
///
/// On Unix, this replaces the current process using `exec`.
/// On other platforms, it spawns a subprocess and waits.
fn exec_git_remote_http(remote_name: &str, signed_url: &str) -> Result<()> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["remote-http", remote_name, signed_url]);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process — only returns on error
        let err = cmd.exec();
        anyhow::bail!("failed to exec git remote-http: {err}");
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status().context("failed to run git remote-http")?;
        if !status.success() {
            anyhow::bail!(
                "git remote-http exited with code {}",
                status.code().unwrap_or(1)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode_simple() {
        assert_eq!(percent_encode("AKIAEXAMPLE"), "AKIAEXAMPLE");
    }

    #[test]
    fn test_percent_encode_special_chars() {
        assert_eq!(percent_encode("a/b+c=d"), "a%2Fb%2Bc%3Dd");
    }

    #[test]
    fn test_percent_encode_unreserved() {
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn test_percent_encode_percent() {
        assert_eq!(percent_encode("50%done"), "50%25done");
    }
}
