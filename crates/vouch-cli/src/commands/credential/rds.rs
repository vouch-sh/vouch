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
use vouch_common::aws::Partition;

use crate::commands::credential::aws::{
    StsRequest, detect_agent_source, exchange_for_sts_credentials,
};
use crate::commands::credential::cache;
use crate::integrations::aws;
use crate::integrations::aws::sigv4::{
    PresignedUrlParams, build_presigned_url, validate_sigv4_input,
};
use crate::server_url::ServerUrl;

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
    let agent_source = detect_agent_source();
    let agent_suffix = agent_source
        .as_deref()
        .map_or(String::new(), |src| format!(":agent:{src}"));
    let cache_key = format!("rds:{hostname}:{port}:{username}:{role_arn}{agent_suffix}");

    let agent = agent_source;
    let data = cache::get_or_fetch(&cache_key, "RDS token", || async {
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

/// All AWS partitions the codebase supports.
///
/// Used to anchor RDS hostname region extraction to a real AWS DNS suffix
/// (via [`Partition::dns_suffix`]) instead of any DNS label named `rds`,
/// which can appear in private DNS aliases and proxies.
const ALL_PARTITIONS: [Partition; 8] = [
    Partition::Aws,
    Partition::AwsCn,
    Partition::AwsUsGov,
    Partition::AwsEusc,
    Partition::AwsIso,
    Partition::AwsIsoB,
    Partition::AwsIsoE,
    Partition::AwsIsoF,
];

/// Extract the AWS region from an RDS hostname.
///
/// RDS hostnames follow the pattern
/// `{id}.{random}.{region}.rds[.<service-seg>].<partition-dns-suffix>` — e.g.
/// `mydb.abc.us-east-1.rds.amazonaws.com` (commercial),
/// `mydb.abc.us-gov-west-1.rds.us-gov.amazonaws.com` (GovCloud), or
/// `mydb.abc.cn-north-1.rds.amazonaws.com.cn` (China).
///
/// The labels after `rds` must end with a known AWS partition DNS suffix,
/// matched on label boundaries, so a custom DNS alias that merely contains an
/// `rds` label — e.g. `db.rds.mycompany.com` or
/// `us-west-2.rds.mycompany.com` — returns `None` and the caller falls back to
/// the region from `--region`, the AWS profile, or `AWS_REGION`/
/// `AWS_DEFAULT_REGION`.
///
/// Returns `None` if the hostname doesn't match an AWS RDS shape.
fn extract_region_from_rds_hostname(hostname: &str) -> Option<&str> {
    let parts: Vec<&str> = hostname.split('.').collect();
    let rds_idx = parts.iter().position(|&p| p == "rds")?;
    // The labels after `rds` must end with a known AWS partition DNS suffix,
    // matched on label boundaries so a domain such as `xamazonaws.com` is not
    // mistaken for `amazonaws.com`. The GovCloud RDS endpoint inserts a
    // `us-gov` service segment (`rds.us-gov.amazonaws.com`) before the shared
    // `amazonaws.com` suffix, so an exact-equality check on the suffix portion
    // would regress GovCloud; a label-aligned suffix match still accepts it.
    let after_rds = parts.get(rds_idx.saturating_add(1)..).unwrap_or_default();
    if !ends_with_partition_dns_suffix(after_rds) {
        return None;
    }
    let region_idx = rds_idx.checked_sub(1)?;
    parts.get(region_idx).copied()
}

/// Whether `labels` ends with a known AWS partition DNS suffix, compared
/// label-by-label so a partial-string match (e.g. `xamazonaws.com` vs.
/// `amazonaws.com`) is not accepted.
fn ends_with_partition_dns_suffix(labels: &[&str]) -> bool {
    ALL_PARTITIONS.iter().any(|partition| {
        let suffix: Vec<&str> = partition.dns_suffix().split('.').collect();
        labels
            .len()
            .checked_sub(suffix.len())
            .is_some_and(|start| labels.get(start..).is_some_and(|tail| tail == suffix))
    })
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

    /// Mirror the cache-key construction in `fetch_rds_token()` so we can lock
    /// in the invariant that agent and non-agent invocations land on different
    /// keys.
    fn build_rds_cache_key(
        hostname: &str,
        port: u16,
        username: &str,
        role_arn: &str,
        agent: Option<&str>,
    ) -> String {
        let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
        format!("rds:{hostname}:{port}:{username}:{role_arn}{agent_suffix}")
    }

    #[test]
    fn test_rds_cache_key_format() {
        let key = build_rds_cache_key(
            "mydb.us-east-1.rds.amazonaws.com",
            5432,
            "admin",
            "arn:aws:iam::123456789012:role/MyRole",
            None,
        );
        assert_eq!(
            key,
            "rds:mydb.us-east-1.rds.amazonaws.com:5432:admin:arn:aws:iam::123456789012:role/MyRole"
        );
    }

    /// Agent and non-agent invocations must never share a cached entry —
    /// issue #426.
    #[test]
    fn test_rds_cache_key_differs_when_agent_detected() {
        let without = build_rds_cache_key(
            "mydb.us-east-1.rds.amazonaws.com",
            5432,
            "admin",
            "arn:aws:iam::123456789012:role/MyRole",
            None,
        );
        let with = build_rds_cache_key(
            "mydb.us-east-1.rds.amazonaws.com",
            5432,
            "admin",
            "arn:aws:iam::123456789012:role/MyRole",
            Some("claude-code"),
        );
        assert_ne!(without, with);
    }

    #[test]
    fn test_rds_cache_key_differs_between_agents() {
        let claude = build_rds_cache_key(
            "mydb.us-east-1.rds.amazonaws.com",
            5432,
            "admin",
            "arn:aws:iam::123456789012:role/MyRole",
            Some("claude-code"),
        );
        let cursor = build_rds_cache_key(
            "mydb.us-east-1.rds.amazonaws.com",
            5432,
            "admin",
            "arn:aws:iam::123456789012:role/MyRole",
            Some("cursor"),
        );
        assert_ne!(claude, cursor);
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

    #[test]
    fn test_extract_region_from_china_hostname() {
        let hostname = "mydb.abc123.cn-north-1.rds.amazonaws.com.cn";
        assert_eq!(
            extract_region_from_rds_hostname(hostname),
            Some("cn-north-1")
        );
    }

    /// Every partition's DNS suffix must anchor extraction; this guards
    /// against a partition being silently dropped from `ALL_PARTITIONS`.
    #[test]
    fn test_extract_region_recognizes_every_partition_suffix() {
        let cases: [(Partition, &str, &str); 8] = [
            (Partition::Aws, "amazonaws.com", "us-east-1"),
            (Partition::AwsCn, "amazonaws.com.cn", "cn-north-1"),
            (Partition::AwsUsGov, "amazonaws.com", "us-gov-west-1"),
            (Partition::AwsEusc, "amazonaws.eu", "eusc-de-east-1"),
            (Partition::AwsIso, "c2s.ic.gov", "us-iso-east-1"),
            (Partition::AwsIsoB, "sc2s.sgov.gov", "us-isob-east-1"),
            (Partition::AwsIsoE, "cloud.adc-e.uk", "eu-isoe-west-1"),
            (Partition::AwsIsoF, "csp.hci.ic.gov", "us-isof-south-1"),
        ];
        for (partition, dns_suffix, region) in cases {
            let hostname = format!("mydb.abc.{region}.rds.{dns_suffix}");
            assert_eq!(
                extract_region_from_rds_hostname(&hostname),
                Some(region),
                "partition {partition:?} did not extract region {region} for {hostname}"
            );
        }
    }

    /// Custom non-AWS hostnames that merely contain an `rds` label must yield
    /// no region, satisfying the documented contract, so the caller falls back
    /// to the user's configured region instead of inferring a garbage one.
    #[test]
    fn test_extract_region_rejects_custom_proxy_with_rds_label() {
        assert_eq!(
            extract_region_from_rds_hostname("db.rds.mycompany.com"),
            None
        );
        assert_eq!(
            extract_region_from_rds_hostname("proxy.rds.internal.corp"),
            None
        );
        assert_eq!(
            extract_region_from_rds_hostname("primary.rds.staging.mycloud.io"),
            None
        );
    }

    /// A pre-`rds` label that happens to be a valid AWS region code must still
    /// be rejected when the suffix is not an AWS partition DNS suffix, so it
    /// cannot override the user's configured region with a wrong-but-valid one.
    #[test]
    fn test_extract_region_rejects_valid_region_label_with_non_aws_suffix() {
        assert_eq!(
            extract_region_from_rds_hostname("us-west-2.rds.mycompany.com"),
            None
        );
        assert_eq!(
            extract_region_from_rds_hostname("ap-south-1.rds.mycompany.com"),
            None
        );
        assert_eq!(
            extract_region_from_rds_hostname("eu-west-1.rds.internal.corp"),
            None
        );
    }

    /// A domain whose final labels merely contain a DNS suffix as a substring
    /// (not aligned to a label boundary) must be rejected, otherwise
    /// `xamazonaws.com` would be mistaken for `amazonaws.com`.
    #[test]
    fn test_extract_region_rejects_partial_label_suffix_match() {
        assert_eq!(
            extract_region_from_rds_hostname("db.rds.xamazonaws.com"),
            None
        );
        assert_eq!(
            extract_region_from_rds_hostname("db.rds.not-amazonaws.com"),
            None
        );
    }

    /// `rds` with no suffix after it, or with no region label before it, yields
    /// no region; the minimal valid AWS RDS shape still extracts the region.
    #[test]
    fn test_extract_region_rejects_rds_without_suffix_or_region() {
        // No labels after `rds` -> not an AWS RDS hostname.
        assert_eq!(extract_region_from_rds_hostname("foo.rds"), None);
        // No label before `rds` -> no region to extract.
        assert_eq!(extract_region_from_rds_hostname("rds.amazonaws.com"), None);
        // Minimal valid AWS RDS shape extracts the single preceding label.
        assert_eq!(
            extract_region_from_rds_hostname("us-east-1.rds.amazonaws.com"),
            Some("us-east-1")
        );
    }
}
