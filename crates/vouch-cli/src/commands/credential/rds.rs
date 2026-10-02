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
use vouch_cli::tr;

use crate::commands::credential::aws::{
    StsRequest, detect_agent_source, exchange_for_sts_credentials,
};
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::sigv4::{
    PresignedUrlParams, build_presigned_url, validate_sigv4_input,
};
use crate::server_url::ServerUrl;
use vouch_common::aws::Partition;

/// RDS auth tokens are valid for 15 minutes (900 seconds).
const RDS_TOKEN_EXPIRES_SECONDS: u64 = 900;

/// Cache safety margin: cache for 14 minutes (1 minute before expiry).
const RDS_CACHE_VALIDITY_MINUTES: i64 = 14;

/// Run the RDS credential command.
///
/// Prints an RDS IAM auth token to stdout, compatible with
/// `aws rds generate-db-auth-token` output.
pub(crate) async fn run(
    server: &ServerUrl,
    hostname: &str,
    port: u16,
    username: &str,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    let token = fetch_rds_token(server, hostname, port, username, region, role).await?;
    // Machine-readable token output: stays English (consumed by RDS driver).
    println!("{}", token.expose_secret());
    Ok(())
}

/// Fetch an RDS IAM auth token (cached).
///
/// Returns the token as a `SecretString` for use in environment injection.
/// If `region` is `None`, attempts to extract it from the RDS hostname
/// before falling back to AWS profile/env detection.
pub(crate) async fn fetch_rds_token(
    server: &ServerUrl,
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
    let (role_arn, region_name) = aws::resolve_role_and_region(role, effective_region, None)?;

    // Detect agent context BEFORE the cache lookup. Folding the source into
    // the cache key ensures agent and non-agent invocations never share a
    // cached entry, which would otherwise hand the agent credentials minted
    // without ReadOnlyAccess / `vouch:AccessType=ai` tags (issue #426).
    let agent = detect_agent_source();
    let key = cache_key(
        hostname,
        port,
        username,
        &region_name,
        &role_arn,
        agent.as_deref(),
    );
    let data = cache::get_or_fetch(&key, "RDS token", || async {
        let token = generate_rds_token(
            server,
            hostname,
            port,
            username,
            &region_name,
            &role_arn,
            agent.as_deref(),
        )
        .await?;
        let expires_at = rds_cache_expiry()?;
        let value = serde_json::Value::String(token);
        Ok((value, expires_at))
    })
    .await?;

    // Extract token string from cached JSON value
    let token = data
        .as_str()
        .context(tr!("err-cached-rds-token-is-not-string"))?;
    Ok(SecretString::from(token.to_string()))
}

/// Generate an RDS IAM auth token.
async fn generate_rds_token(
    server: &ServerUrl,
    hostname: &str,
    port: u16,
    username: &str,
    region: &str,
    role_arn: &str,
    agent_source: Option<&str>,
) -> Result<String> {
    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn,
        region,
        management_role: None,
        agent_source,
    })
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

/// Extract the AWS region from an RDS endpoint hostname, or `None` when the
/// hostname is not an RDS endpoint (a custom DNS name, for example).
///
/// RDS endpoints end in `<region>.rds.<partition DNS suffix>`, except in the
/// China partition, where they end in `rds.<region>.amazonaws.com.cn`. The
/// candidate region must select the partition whose suffix ends the hostname.
fn extract_region_from_rds_hostname(hostname: &str) -> Option<&str> {
    hostname.split('.').find(|label| {
        is_region_shaped(label) && {
            let partition = Partition::from_region(label);
            let tail = if partition == Partition::AwsCn {
                format!(".rds.{label}.{}", partition.dns_suffix())
            } else {
                format!(".{label}.rds.{}", partition.dns_suffix())
            };
            hostname.ends_with(&tail)
        }
    })
}

/// Whether `label` has the shape of an AWS region code (`us-east-1`).
fn is_region_shaped(label: &str) -> bool {
    label.contains('-')
        && label.ends_with(|c: char| c.is_ascii_digit())
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The token cache key. Every input that changes the presigned token is part
/// of it, so a request for a different region or role never reuses a token.
fn cache_key(
    hostname: &str,
    port: u16,
    username: &str,
    region: &str,
    role_arn: &str,
    agent: Option<&str>,
) -> String {
    let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    format!("rds:{hostname}:{port}:{username}:{region}:{role_arn}{agent_suffix}")
}

/// Compute cache expiry: 14 minutes from now (1 minute safety margin).
fn rds_cache_expiry() -> Result<String> {
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_mins(RDS_CACHE_VALIDITY_MINUTES))
        .context(tr!("err-failed-compute-rds-token-cache-expiry"))?;
    Ok(expires.to_string())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    const ROLE: &str = "arn:aws:iam::123456789012:role/MyRole";
    const HOST: &str = "mydb.abc123.us-east-1.rds.amazonaws.com";

    #[test]
    fn test_rds_cache_key_format() {
        assert_eq!(
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, None),
            format!("rds:{HOST}:5432:admin:us-east-1:{ROLE}")
        );
    }

    /// A token presigned for one region must not be reused for another.
    #[test]
    fn test_rds_cache_key_differs_by_region() {
        assert_ne!(
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, None),
            cache_key(HOST, 5432, "admin", "us-west-2", ROLE, None)
        );
    }

    /// Agent and non-agent invocations must never share a cached entry —
    /// issue #426.
    #[test]
    fn test_rds_cache_key_differs_when_agent_detected() {
        assert_ne!(
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, None),
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, Some("claude-code"))
        );
    }

    #[test]
    fn test_rds_cache_key_differs_between_agents() {
        assert_ne!(
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, Some("claude-code")),
            cache_key(HOST, 5432, "admin", "us-east-1", ROLE, Some("cursor"))
        );
    }

    #[test]
    fn test_rds_cache_expiry_valid() {
        let expiry = rds_cache_expiry().expect("should compute");
        assert!(expiry.parse::<jiff::Timestamp>().is_ok());
    }

    /// Endpoint shapes from AWS documentation and the Public Suffix List
    /// entries AWS registered for RDS (`*.<region>.rds.amazonaws.com`,
    /// `*.rds.cn-north-1.amazonaws.com.cn`).
    #[test]
    fn test_extract_region_from_rds_endpoints() {
        for (hostname, region) in [
            (
                "vouch-demo-rds.cjcxqsog7mxa.us-east-1.rds.amazonaws.com",
                "us-east-1",
            ),
            (
                "mycluster.cluster-ro-cjcxqsog7mxa.eu-west-1.rds.amazonaws.com",
                "eu-west-1",
            ),
            (
                "myproxy.proxy-cjcxqsog7mxa.ap-southeast-2.rds.amazonaws.com",
                "ap-southeast-2",
            ),
            (
                "mydb.cjcxqsog7mxa.us-gov-west-1.rds.amazonaws.com",
                "us-gov-west-1",
            ),
            (
                "btusi123.cmz7kenwo2ye.rds.cn-north-1.amazonaws.com.cn",
                "cn-north-1",
            ),
            ("mydb.abc123.us-iso-east-1.rds.c2s.ic.gov", "us-iso-east-1"),
            (
                "mydb.abc123.us-isob-east-1.rds.sc2s.sgov.gov",
                "us-isob-east-1",
            ),
        ] {
            assert_eq!(
                extract_region_from_rds_hostname(hostname),
                Some(region),
                "{hostname}"
            );
        }
    }

    /// A hostname that is not an RDS endpoint yields no region, so the
    /// profile or environment region applies.
    #[test]
    fn test_extract_region_from_non_rds_hostname() {
        for hostname in [
            "localhost",
            "my-custom-proxy.example.com",
            "db.rds.internal.example.com",
            "rds.prod.us-east-1.example.com",
            "mydb.abc123.us-east-1.rds.amazonaws.com.evil.example",
            "mydb.abc123.cn-north-1.rds.amazonaws.com.cn",
            "mydb.abc123.rds.us-east-1.amazonaws.com",
        ] {
            assert_eq!(
                extract_region_from_rds_hostname(hostname),
                None,
                "{hostname}"
            );
        }
    }
}
