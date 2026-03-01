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
pub async fn run(
    server: &str,
    hostname: &str,
    port: u16,
    username: &str,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    validate_sigv4_input(hostname, "hostname")?;
    validate_sigv4_input(username, "username")?;

    // Resolve role ARN from flag or local AWS config
    let role_arn = match role {
        Some(r) => r.to_string(),
        None => aws::get_local_aws_role().ok_or_else(|| {
            anyhow::anyhow!(
                "AWS not configured. Run 'vouch setup aws --role <role-arn>' \
                 first, or specify --role."
            )
        })?,
    };

    // Resolve region
    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region_name = aws::resolve_region(region, &profile_name)?;

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
    println!("{token}");
    Ok(())
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
    let result = exchange_for_sts_credentials(server, role_arn, region, "vouch-rds").await?;

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

/// Compute cache expiry: 14 minutes from now (1 minute safety margin).
fn rds_cache_expiry() -> Result<String> {
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_mins(RDS_CACHE_VALIDITY_MINUTES))
        .context("failed to compute RDS token cache expiry")?;
    Ok(expires.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
}
