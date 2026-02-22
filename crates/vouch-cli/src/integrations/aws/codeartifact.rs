// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS CodeArtifact integration utilities.
//!
//! Provides SigV4-signed `GetAuthorizationToken` calls to obtain bearer tokens
//! for authenticating with AWS CodeArtifact package repositories. Supports all
//! package formats: Cargo, pip/PyPI, npm, Maven, NuGet, Swift, and generic.

use anyhow::{Context, Result};
use secrecy::SecretString;

use super::sigv4::sign_and_send_rest_post;
use super::sts::StsCredentials;

/// CodeArtifact authorization token and expiration.
pub struct CodeArtifactToken {
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
pub struct CodeArtifactRegistry {
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
/// - `my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com`
/// - `my-domain-123456789012.d.codeartifact.cn-north-1.amazonaws.cn`
///
/// The URL may include a scheme (`https://`) and a path (e.g., `/cargo/my-repo/`).
#[must_use]
pub fn parse_codeartifact_url(url: &str) -> Option<CodeArtifactRegistry> {
    // Strip scheme and path to get just the host
    let url = url.strip_prefix("sparse+").unwrap_or(url);
    let url = url.strip_prefix("https://").unwrap_or(url);
    let url = url.strip_prefix("http://").unwrap_or(url);
    // Take only the host part (before any path)
    let host = url.split('/').next()?;

    // Expected: {domain}-{owner}.d.codeartifact.{region}.{suffix}
    let (domain_owner_part, rest) = host.split_once(".d.codeartifact.")?;

    // rest = "{region}.{suffix}" e.g., "us-east-1.amazonaws.com"
    // Region may contain dots (unlikely but defensive), but the suffix always
    // starts with "amazonaws." so split on the first "amazonaws." occurrence.
    let amazonaws_idx = rest.find("amazonaws.")?;
    if amazonaws_idx == 0 {
        return None; // No region component
    }
    // region is everything before the dot preceding "amazonaws."
    let region = rest.get(..amazonaws_idx.checked_sub(1)?)?;
    let domain_suffix = rest.get(amazonaws_idx..)?;

    if region.is_empty() || domain_suffix.is_empty() {
        return None;
    }

    // domain_owner_part = "{domain}-{owner}" where owner is a 12-digit AWS account ID
    // The owner is the last segment after the final hyphen (since domain names can contain hyphens)
    let last_hyphen = domain_owner_part.rfind('-')?;
    let domain = domain_owner_part.get(..last_hyphen)?;
    let domain_owner = domain_owner_part.get(last_hyphen + 1..)?;

    if domain.is_empty() || domain_owner.is_empty() {
        return None;
    }

    Some(CodeArtifactRegistry {
        domain: domain.to_string(),
        domain_owner: domain_owner.to_string(),
        region: region.to_string(),
        domain_suffix: domain_suffix.to_string(),
    })
}

/// Response from CodeArtifact `GetAuthorizationToken` API.
#[derive(serde::Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct GetAuthorizationTokenResponse {
    authorization_token: String,
    #[zeroize(skip)]
    expiration: f64,
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
pub async fn get_authorization_token(
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

    let response_body = sign_and_send_rest_post(
        http_client,
        &endpoint,
        "/v1/authorization-token",
        &query_params,
        "codeartifact",
        &registry.region,
        creds,
    )
    .await
    .context("failed to call CodeArtifact GetAuthorizationToken")?;

    let mut ca_response: GetAuthorizationTokenResponse =
        serde_json::from_str(&response_body).context("failed to parse CodeArtifact response")?;

    #[allow(clippy::cast_possible_truncation)]
    let expiration = ca_response.expiration as i64;

    // Take the token out, leaving an empty string that ZeroizeOnDrop will handle
    let token = std::mem::take(&mut ca_response.authorization_token);

    Ok(CodeArtifactToken {
        authorization_token: SecretString::from(token),
        expiration,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_codeartifact_url_basic() {
        let url = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";
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
    fn test_parse_codeartifact_url_china() {
        let url = "my-domain-123456789012.d.codeartifact.cn-north-1.amazonaws.cn";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "cn-north-1");
        assert_eq!(result.domain_suffix, "amazonaws.cn");
    }

    #[test]
    fn test_parse_codeartifact_url_govcloud() {
        let url = "my-domain-123456789012.d.codeartifact.us-gov-west-1.amazonaws.com";
        let result = parse_codeartifact_url(url).expect("should parse");
        assert_eq!(result.domain, "my-domain");
        assert_eq!(result.domain_owner, "123456789012");
        assert_eq!(result.region, "us-gov-west-1");
        assert_eq!(result.domain_suffix, "amazonaws.com");
    }

    #[test]
    fn test_parse_codeartifact_url_hyphenated_domain() {
        let url = "my-cool-domain-123456789012.d.codeartifact.eu-west-1.amazonaws.com";
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
        assert!(parse_codeartifact_url("index.crates.io").is_none());
        assert!(parse_codeartifact_url("https://registry.npmjs.org").is_none());
        assert!(parse_codeartifact_url("https://pypi.org/simple/").is_none());
    }

    #[test]
    fn test_parse_codeartifact_url_invalid_missing_parts() {
        // Missing domain owner
        assert!(parse_codeartifact_url(".d.codeartifact.us-east-1.amazonaws.com").is_none());
        // Missing domain
        assert!(
            parse_codeartifact_url("-123456789012.d.codeartifact.us-east-1.amazonaws.com")
                .is_none()
        );
    }

    #[test]
    fn test_parse_codeartifact_url_empty() {
        assert!(parse_codeartifact_url("").is_none());
    }
}
