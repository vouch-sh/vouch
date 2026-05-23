// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RDS IAM auth token command.
//!
//! Generates an RDS IAM authentication token using a presigned STS URL.
//! The token is used as the database password when connecting to RDS
//! instances with IAM database authentication enabled.
//!
//! This replaces `aws rds generate-db-auth-token`, eliminating the AWS
//! CLI as a runtime dependency.
//!
//! Protocol:
//! 1. Exchange Vouch session for STS credentials (OIDC → STS)
//! 2. Build a presigned URL: `GET https://{host}:{port}/?Action=connect&DBUser={user}`
//!    with service name `rds-db`, valid for 900 seconds
//! 3. Strip `https://` prefix and print to stdout

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::commands::credential::aws::exchange_for_sts_credentials;
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::sigv4::{
    PresignedUrlParams, build_presigned_url, validate_sigv4_input,
};

/// RDS auth tokens are valid for 15 minutes (900 seconds).
const RDS_TOKEN_EXPIRES_SECONDS: u64 = 900;

/// Cache safety margin: cache for 14 minutes (1 minute before expiry).
const RDS_CACHE_VALIDITY_MINUTES: i64 = 14;

/// Run the RDS credential command.
///
/// Prints an RDS IAM auth token to stdout, compatible with
/// `aws rds generate-db-auth-token` output.
pub(crate) async fn run(
    server: &str,
    hostname: &str,
    port: u16,
    username: &str,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    let token = fetch_rds_token(server, hostname, port, username, region, role).await?;
    println!("{}", token.expose_secret());
    Ok(())
}

/// Fetch an RDS IAM auth token (cached).
///
/// Returns the token as a `SecretString` for use in environment injection.
/// If `region` is `None`, attempts to extract it from the RDS hostname
/// before falling back to AWS profile/env detection.
pub(crate) async fn fetch_rds_token(
    server: &str,
    hostname: &str,
    port: u16,
    username: &str,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<SecretString> {
    validate_sigv4_input(hostname, "hostname")?;
    validate_sigv4_input(username, "username")?;

    let hostname_region = extract_region_from_rds_hostname(hostname);
    let effective_region = region.or(hostname_region);
    let (role_arn, region_name) = aws::resolve_role_and_region(role, effective_region)?;

    let cache_key = format!("rds:{hostname}:{port}:{username}:{role_arn}");

    let data = cache::get_or_fetch(&cache_key, "RDS token", || async {
        let token =
            generate_rds_token(server, hostname, port, username, &region_name, &role_arn).await?;
        let expires_at = rds_cache_expiry()?;
        let value = serde_json::Value::String(token);
        Ok((value, expires_at))
    })
    .await?;

    // Extract token string from cached JSON value
    let token = data.as_str().context("cached RDS token is not a string")?;
    Ok(SecretString::from(token.to_string()))
}

/// Generate an RDS IAM auth token.
async fn generate_rds_token(
    server: &str,
    hostname: &str,
    port: u16,
    username: &str,
    region: &str,
    role_arn: &str,
) -> Result<String> {
    let agent_source = crate::commands::credential::aws::detect_agent_source();
    let result =
        exchange_for_sts_credentials(server, role_arn, region, None, agent_source.as_deref())
            .await?;

    // Build presigned URL for RDS IAM auth
    let endpoint = format!("https://{hostname}:{port}");
    let presigned = build_presigned_url(&PresignedUrlParams {
        method: "GET",
        endpoint: &endpoint,
        path: "/",
        query_params: &[("Action", "connect"), ("DBUser", username)],
        extra_signed_headers: &[],
        service: "rds-db",
        region,
        creds: &result.credentials,
        expires_seconds: RDS_TOKEN_EXPIRES_SECONDS,
    });

    // Strip the https:// prefix (RDS tokens are the URL without scheme)
    let token = presigned
        .strip_prefix("https://")
        .unwrap_or(&presigned)
        .to_string();

    Ok(token)
}

/// Extract the AWS region from an RDS hostname.
///
/// RDS hostnames follow the pattern `{id}.{random}.{region}.rds.amazonaws.com`.
/// Returns `None` if the hostname doesn't match.
fn extract_region_from_rds_hostname(hostname: &str) -> Option<&str> {
    let parts: Vec<&str> = hostname.split('.').collect();
    let rds_idx = parts.iter().position(|&p| p == "rds")?;
    let region_idx = rds_idx.checked_sub(1)?;
    parts.get(region_idx).copied()
}

/// Compute cache expiry: 14 minutes from now (1 minute safety margin).
fn rds_cache_expiry() -> Result<String> {
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_mins(RDS_CACHE_VALIDITY_MINUTES))
        .context("failed to compute RDS token cache expiry")?;
    Ok(expires.to_string())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_rds_token_strips_https_prefix() {
        let url = "https://mydb.us-east-1.rds.amazonaws.com:5432/?Action=connect&DBUser=admin&X-Amz-Algorithm=AWS4-HMAC-SHA256";
        let token = url.strip_prefix("https://").unwrap_or(url);
        assert!(token.starts_with("mydb.us-east-1.rds.amazonaws.com:5432"));
        assert!(!token.starts_with("https://"));
    }

    #[test]
    fn test_rds_endpoint_format() {
        let hostname = "mydb.us-east-1.rds.amazonaws.com";
        let port: u16 = 5432;
        let endpoint = format!("https://{hostname}:{port}");
        assert_eq!(endpoint, "https://mydb.us-east-1.rds.amazonaws.com:5432");
    }

    #[test]
    fn test_rds_cache_key_format() {
        let hostname = "mydb.us-east-1.rds.amazonaws.com";
        let port: u16 = 5432;
        let username = "admin";
        let role_arn = "arn:aws:iam::123456789012:role/MyRole";
        let key = format!("rds:{hostname}:{port}:{username}:{role_arn}");
        assert_eq!(
            key,
            "rds:mydb.us-east-1.rds.amazonaws.com:5432:admin:arn:aws:iam::123456789012:role/MyRole"
        );
    }

    #[test]
    fn test_rds_cache_expiry_valid() {
        let expiry = rds_cache_expiry().expect("should compute");
        assert!(expiry.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_extract_region_from_standard_hostname() {
        let hostname = "vouch-demo-rds.cjcxqsog7mxa.us-east-1.rds.amazonaws.com";
        assert_eq!(
            extract_region_from_rds_hostname(hostname),
            Some("us-east-1")
        );
    }

    #[test]
    fn test_extract_region_from_govcloud_hostname() {
        let hostname = "mydb.abc123.us-gov-west-1.rds.us-gov.amazonaws.com";
        assert_eq!(
            extract_region_from_rds_hostname(hostname),
            Some("us-gov-west-1")
        );
    }

    #[test]
    fn test_extract_region_from_non_rds_hostname() {
        assert_eq!(extract_region_from_rds_hostname("localhost"), None);
        assert_eq!(
            extract_region_from_rds_hostname("my-custom-proxy.example.com"),
            None
        );
    }
}
