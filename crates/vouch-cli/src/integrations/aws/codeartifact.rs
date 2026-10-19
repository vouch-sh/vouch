// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS CodeArtifact integration utilities.
//!
//! Provides SigV4-signed `GetAuthorizationToken` calls to obtain bearer tokens
//! for authenticating with AWS CodeArtifact package repositories. Supports all
//! package formats: Cargo, pip/PyPI, npm, Maven, NuGet, Swift, and generic.

use anyhow::{Context, Result};
use secrecy::SecretString;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sigv4::sign_and_send_rest;
use super::sts::StsCredentials;

/// CodeArtifact authorization token and expiration.
pub(crate) struct CodeArtifactToken {
    /// Bearer token for authenticating with CodeArtifact.
    pub authorization_token: SecretString,
    /// Unix timestamp when the token expires.
    pub expiration: i64,
}

impl std::fmt::Debug for CodeArtifactToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeArtifactToken")
            .field("authorization_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Parsed components of a CodeArtifact registry URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeArtifactRegistry {
    /// CodeArtifact domain name.
    pub domain: String,
    /// AWS account ID that owns the domain.
    pub domain_owner: String,
    /// AWS region (e.g., "us-east-1").
    pub region: String,
    /// AWS domain suffix (e.g., "amazonaws.com").
    pub domain_suffix: String,
}

/// Parse a CodeArtifact URL into its components.
///
/// CodeArtifact URLs follow the pattern:
/// `{domain}-{domainOwner}.d.codeartifact.{region}.{domain_suffix}`
///
/// Examples:
/// - `https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/`
/// - `sparse+https://my-domain-123456789012.d.codeartifact.eu-west-1.amazonaws.com/cargo/r/`
///
/// Only HTTPS URLs are accepted: a token minted for any other scheme would
/// travel in the clear. The host must end in an AWS partition DNS suffix, and
/// the URL must carry no userinfo or non-default port.
#[must_use]
pub(crate) fn parse_codeartifact_url(url: &str) -> Option<CodeArtifactRegistry> {
    let url = url.strip_prefix("sparse+").unwrap_or(url);
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return None;
    }
    // `Url` lowercases the host. A trailing dot names the same host and does
    // not change where the token goes.
    let host = parsed.host_str()?;
    let host = host.strip_suffix('.').unwrap_or(host);

    // Expected: {domain}-{owner}.d.codeartifact.{region}.{suffix}
    let (domain_owner_part, rest) = host.split_once(".d.codeartifact.")?;

    // rest = "{region}.{suffix}"; the suffix must end the host, so
    // `…amazonaws.evil.com` is rejected.
    let (region, domain_suffix) = Partition::ALL.iter().find_map(|partition| {
        let suffix = partition.dns_suffix();
        let region = rest.strip_suffix(suffix)?.strip_suffix('.')?;
        Some((region, suffix))
    })?;

    // domain_owner_part = "{domain}-{owner}" where owner is a 12-digit AWS account ID
    // The owner is the last segment after the final hyphen (since domain names can contain hyphens)
    let last_hyphen = domain_owner_part.rfind('-')?;
    let domain = domain_owner_part.get(..last_hyphen)?;
    let domain_owner = domain_owner_part.get(last_hyphen.saturating_add(1)..)?;

    let is_label = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !is_label(region)
        || !is_label(domain)
        || domain_owner.len() != 12
        || !domain_owner.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    Some(CodeArtifactRegistry {
        domain: domain.to_string(),
        domain_owner: domain_owner.to_string(),
        region: region.to_string(),
        domain_suffix: domain_suffix.to_string(),
    })
}

impl CodeArtifactRegistry {
    /// Stable cache key for deduplicating token fetches across repositories.
    ///
    /// All repositories within a single domain share one authorization token,
    /// so this key combines domain, owner, and region.
    pub(crate) fn token_cache_key(&self) -> String {
        format!("{}:{}:{}", self.domain, self.domain_owner, self.region)
    }
}

/// Response from CodeArtifact `GetAuthorizationToken` API.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetAuthorizationTokenResponse {
    authorization_token: SecretString,
    expiration: f64,
}

impl std::fmt::Debug for GetAuthorizationTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetAuthorizationTokenResponse")
            .field("authorization_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Get a CodeArtifact authorization token via SigV4-signed REST API call.
///
/// This calls the CodeArtifact `GetAuthorizationToken` REST API
/// (`POST /v1/authorization-token?domain=...&domain-owner=...`) using the
/// provided STS credentials. The returned token can be used as a bearer
/// token for authenticating with any CodeArtifact repository in the domain.
///
/// # Arguments
/// * `registry` - CodeArtifact registry details (domain, owner, region)
/// * `creds` - Temporary AWS credentials from STS
pub(crate) async fn get_authorization_token(
    http_client: &reqwest::Client,
    registry: &CodeArtifactRegistry,
    creds: &StsCredentials,
) -> Result<CodeArtifactToken> {
    let endpoint = format!(
        "https://codeartifact.{}.{}",
        registry.region, registry.domain_suffix
    );

    let query_params: Vec<(&str, &str)> = vec![
        ("domain", &registry.domain),
        ("domain-owner", &registry.domain_owner),
    ];

    let response_body = sign_and_send_rest(
        http_client,
        reqwest::Method::POST,
        &endpoint,
        "/v1/authorization-token",
        &query_params,
        "codeartifact",
        &registry.region,
        creds,
    )
    .await
    .context(tr!("err-failed-call-codeartifact-getauthorizationtoken"))?;

    let ca_response: GetAuthorizationTokenResponse = serde_json::from_str(&response_body)
        .context(tr!("err-failed-parse-codeartifact-response"))?;

    #[expect(
        clippy::cast_possible_truncation,
        reason = "CodeArtifact expiration is a Unix timestamp (seconds), well below i64::MAX"
    )]
    let expiration = ca_response.expiration as i64;

    Ok(CodeArtifactToken {
        authorization_token: ca_response.authorization_token,
        expiration,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_codeartifact_url_basic() {
        let url = "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "us-east-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_with_scheme_and_path() {
        let url =
            "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "us-east-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_sparse_cargo() {
        let url = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "us-east-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_govcloud() {
        let url = "https://my-domain-123456789012.d.codeartifact.us-gov-west-1.amazonaws.com";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "us-gov-west-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_hyphenated_domain() {
        let url = "https://my-cool-domain-123456789012.d.codeartifact.eu-west-1.amazonaws.com";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-cool-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "eu-west-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_npm_path() {
        let url =
            "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
    }

    #[test]
    fn test_parse_codeartifact_url_pypi_path() {
        let url = "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/my-repo/simple/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
    }

    #[test]
    fn test_parse_codeartifact_url_invalid_not_codeartifact() {
        assert!(parse_codeartifact_url("https://index.crates.io").is_none());
        assert!(parse_codeartifact_url("https://registry.npmjs.org").is_none());
        assert!(parse_codeartifact_url("https://pypi.org/simple/").is_none());
    }

    #[test]
    fn test_parse_codeartifact_url_invalid_missing_parts() {
        // Missing domain owner
        assert!(
            parse_codeartifact_url("https://.d.codeartifact.us-east-1.amazonaws.com").is_none()
        );
        // Missing domain
        assert!(
            parse_codeartifact_url("https://-123456789012.d.codeartifact.us-east-1.amazonaws.com")
                .is_none()
        );
    }

    #[test]
    fn test_parse_codeartifact_url_rejects_lookalike_hosts() {
        for host in [
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.evil.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com.evil.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.cn.evil.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.evil.com/amazonaws.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.notamazonaws.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.org",
            // `amazonaws.cn` is not an AWS partition DNS suffix.
            "my-domain-123456789012.d.codeartifact.cn-north-1.amazonaws.cn",
            "my-domain-123456789012.d.codeartifact.amazonaws.com",
            "evil.com@my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com:8443",
            "my-domain-12345678901.d.codeartifact.us-east-1.amazonaws.com",
            "my-domain-abcdefghijkl.d.codeartifact.us-east-1.amazonaws.com",
        ] {
            for prefix in ["https://", "sparse+https://"] {
                let url = format!("{prefix}{host}/cargo/my-repo/");
                assert!(parse_codeartifact_url(&url).is_none(), "{url}");
            }
        }
    }

    // Cargo's URL parser reads `https://http://…` as host `http`, so the token
    // would go somewhere other than the CodeArtifact host in the path.
    #[test]
    fn test_parse_codeartifact_url_rejects_double_scheme() {
        let host = "victim-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        for url in [
            format!("sparse+https://http://{host}/cargo/r/"),
            format!("https://http://{host}/cargo/r/"),
            format!("https://https://{host}/cargo/r/"),
            format!("sparse+sparse+https://{host}/cargo/r/"),
            format!("https://x@{host}/cargo/r/"),
            format!("https://user:pw@{host}/cargo/r/"),
            format!("https://{host}:8443/cargo/r/"),
            format!("https://{host}:80/cargo/r/"),
        ] {
            assert!(parse_codeartifact_url(&url).is_none(), "{url}");
        }
    }

    #[test]
    fn test_parse_codeartifact_url_requires_https() {
        let host = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
        for url in [
            format!("http://{host}/cargo/r/"),
            format!("sparse+http://{host}/cargo/r/"),
            format!("{host}/cargo/r/"),
            format!("//{host}/npm/r/"),
            format!("ftp://{host}/"),
        ] {
            assert!(parse_codeartifact_url(&url).is_none(), "{url}");
        }
    }

    #[test]
    fn test_parse_codeartifact_url_accepts_default_https_port() {
        let url =
            "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com:443/cargo/r/";
        assert!(parse_codeartifact_url(url).is_some());
    }

    // Each AWS partition DNS suffix is accepted, taken from `Partition::dns_suffix`.
    #[test]
    fn test_parse_codeartifact_url_accepts_partition_suffixes() {
        for partition in Partition::ALL {
            let suffix = partition.dns_suffix();
            let url =
                format!("https://my-domain-123456789012.d.codeartifact.r-1.{suffix}/cargo/r/");
            let result = parse_codeartifact_url(&url).expect("should parse");
            assert_eq!(result.domain_suffix, suffix, "{url}");
        }
    }

    #[test]
    fn test_parse_codeartifact_url_is_case_insensitive() {
        let url =
            "sparse+https://My-Domain-123456789012.D.CodeArtifact.US-East-1.AmazonAWS.com/cargo/r/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.region, "us-east-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_trailing_dot() {
        let url = "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com./cargo/r/";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.region, "us-east-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_empty() {
        assert!(parse_codeartifact_url("").is_none());
    }
}
