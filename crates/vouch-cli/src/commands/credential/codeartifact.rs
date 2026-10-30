// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeArtifact credential command.
//!
//! Obtains a CodeArtifact authorization token using Vouch session,
//! STS `AssumeRoleWithWebIdentity`, and SigV4-signed `GetAuthorizationToken`.
//!
//! Usage:
//!   vouch credential codeartifact --domain my-domain --domain-owner 123456789012
//!
//! The token is printed to stdout and can be used as a bearer token for any
//! package manager that supports CodeArtifact (Cargo, pip, npm, Maven, etc.).

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use vouch_cli::tr;

use crate::commands::credential::aws::{StsRequest, exchange_for_sts_credentials};
use crate::commands::credential::{aws, cache};
use crate::config::{CodeArtifactProfile, Config};
use crate::integrations::aws::codeartifact::{
    CodeArtifactRegistry, CodeArtifactToken, get_authorization_token,
};
use crate::integrations::aws::{ProfileOverride, RoleTarget, resolve_vouch_profile};
use crate::server_url::ServerUrl;

/// A CodeArtifact domain plus the AWS account that mints tokens for it.
#[derive(Debug, Clone)]
pub(crate) struct CodeArtifactTarget {
    /// CodeArtifact domain name.
    pub domain: String,
    /// AWS account ID that owns the domain.
    pub domain_owner: String,
    /// AWS region hosting the domain.
    pub region: String,
    /// AWS profile whose role mints the token, when one is anchored.
    ///
    /// `None` means "resolve a Vouch profile from `~/.aws/config`", which only
    /// succeeds when the choice is unambiguous.
    pub profile: Option<String>,
}

impl CodeArtifactTarget {
    /// Build a target, adopting the AWS profile anchored to this domain by
    /// `vouch setup codeartifact` when one matches.
    ///
    /// Package managers reach us through argument-less shims and rebuild the
    /// domain from an index URL, so the anchor has to be recovered from saved
    /// domain profiles rather than passed along.
    pub(crate) fn new(domain: String, domain_owner: String, region: String) -> Self {
        let profile = match Config::load() {
            Ok(config) => config.codeartifact().and_then(|ca| {
                anchor_for(ca.domain_profiles.values(), &domain, &domain_owner, &region)
            }),
            Err(_) => None,
        };
        Self {
            domain,
            domain_owner,
            region,
            profile,
        }
    }
}

/// The AWS profile anchored to this domain by the saved domain profiles.
///
/// The domain and region come from a URL host, which is lowercased, while a
/// saved profile may have been typed in any case, so those two compare
/// case-insensitively. Several profiles naming this domain but disagreeing on
/// the account is exactly the case the resolver refuses to guess at; it gets
/// none rather than one picked by map order.
fn anchor_for<'a>(
    saved: impl Iterator<Item = &'a CodeArtifactProfile>,
    domain: &str,
    domain_owner: &str,
    region: &str,
) -> Option<String> {
    let mut anchors: Vec<&String> = Vec::new();
    for profile in saved {
        let matches = profile.domain.eq_ignore_ascii_case(domain)
            && profile.domain_owner == domain_owner
            && profile.region.eq_ignore_ascii_case(region);
        if let Some(anchor) = profile.aws_profile.as_ref()
            && matches
            && !anchors.contains(&anchor)
        {
            anchors.push(anchor);
        }
    }
    match anchors.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

/// Resolve CodeArtifact domain/owner/region from CLI flags, a domain profile,
/// or the default domain profile.
///
/// Resolution order:
/// 1. Explicit flags (if all three are provided)
/// 2. Named domain profile (`--domain-profile <name>`)
/// 3. Default domain profile (`codeartifact.default`)
/// 4. Error with helpful message
///
/// `profile` names an AWS profile in `~/.aws/config` and overrides whatever
/// the saved domain profile records. Note that `domain_profile` names a
/// *Vouch CodeArtifact domain* bundle — the two are deliberately separate
/// flags, since AWS CodeArtifact has no "profile" concept of its own.
pub(crate) fn resolve_codeartifact_params(
    domain: Option<&str>,
    domain_owner: Option<&str>,
    region: Option<&str>,
    domain_profile: Option<&str>,
    profile: Option<&str>,
) -> Result<CodeArtifactTarget> {
    // If all three flags are provided, use them directly. An explicit
    // --profile wins; otherwise fall back to the anchor saved for whichever
    // domain profile was named, then to one saved for this same domain.
    if let (Some(d), Some(o), Some(r)) = (domain, domain_owner, region) {
        let mut target = CodeArtifactTarget::new(d.to_string(), o.to_string(), r.to_string());
        if let Some(p) = profile {
            target.profile = Some(p.to_string());
        } else if let Some(name) = domain_profile {
            let config = Config::load().context(tr!("err-failed-load-config"))?;
            if let Some(saved) = config
                .codeartifact()
                .and_then(|c| c.domain_profiles.get(name))
            {
                target.profile = saved.aws_profile.clone();
            }
        }
        return Ok(target);
    }

    // Try to load from a saved domain profile
    let config = Config::load().context(tr!("err-failed-load-config"))?;
    let ca_config = config.codeartifact();

    let resolved_profile = if let Some(name) = domain_profile {
        // Explicit --domain-profile flag
        ca_config
            .and_then(|c| c.domain_profiles.get(name))
            .ok_or_else(|| {
                let available = ca_config
                    .map(|c| {
                        c.domain_profiles
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                if available.is_empty() {
                    anyhow::anyhow!(
                        "CodeArtifact domain profile '{name}' not found. \
                         No domain profiles configured. Run 'vouch setup codeartifact' first."
                    )
                } else {
                    anyhow::anyhow!(
                        "CodeArtifact domain profile '{name}' not found. \
                         Available domain profiles: {available}"
                    )
                }
            })?
    } else {
        // Try the default domain profile
        let default_name = ca_config.and_then(|c| c.default.as_deref());
        match default_name {
            Some(name) => ca_config
                .and_then(|c| c.domain_profiles.get(name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Default CodeArtifact domain profile '{name}' not found in config. \
                         Run 'vouch setup codeartifact' to reconfigure."
                    )
                })?,
            None => {
                return Err(anyhow::anyhow!(
                    "No CodeArtifact domain specified. Either:\n  \
                     - Pass --domain, --domain-owner, and --region flags\n  \
                     - Run 'vouch setup codeartifact' to save a domain profile\n  \
                     - Pass --domain-profile <name> to use a saved domain profile"
                ));
            }
        }
    };

    // Allow individual flags to override the domain profile's values
    Ok(CodeArtifactTarget {
        domain: domain.unwrap_or(&resolved_profile.domain).to_string(),
        domain_owner: domain_owner
            .unwrap_or(&resolved_profile.domain_owner)
            .to_string(),
        region: region.unwrap_or(&resolved_profile.region).to_string(),
        profile: profile
            .map(str::to_string)
            .or_else(|| resolved_profile.aws_profile.clone()),
    })
}

/// Run the CodeArtifact credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Calls AWS STS `AssumeRoleWithWebIdentity`
/// 3. Calls CodeArtifact `GetAuthorizationToken` with SigV4 signing
/// 4. Outputs the bearer token to stdout
pub(crate) async fn run(
    server: &ServerUrl,
    domain: Option<&str>,
    domain_owner: Option<&str>,
    region: Option<&str>,
    domain_profile: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    let target =
        resolve_codeartifact_params(domain, domain_owner, region, domain_profile, profile)?;

    let token = get_token(server, &target).await?;
    println!("{}", token.authorization_token.expose_secret());
    Ok(())
}

/// Get a CodeArtifact token using the full Vouch → STS → CodeArtifact flow,
/// with agent-side caching.
///
/// This is the shared core used by both the standalone command and the
/// Cargo credential provider when it detects a CodeArtifact index URL.
pub(crate) async fn get_token(
    server: &ServerUrl,
    target: &CodeArtifactTarget,
) -> Result<CodeArtifactToken> {
    // Resolve the role BEFORE the cache lookup: `target.profile` is only the
    // *configured* anchor, and is `None` whenever the account has to be
    // inferred (AWS_PROFILE, or the sole remaining Vouch profile). Keying the
    // cache on that optional field would let two invocations that resolve to
    // different accounts share an entry; the resolved role ARN is the value
    // that actually determines which account's token comes back.
    let profile = resolve_vouch_profile(target.profile.as_deref(), ProfileOverride::Profile)?;

    // Detect the agent context BEFORE the cache lookup and fold it into the
    // cache key so agent and non-agent invocations never share a cached
    // entry — an agent must not receive a token minted without the
    // ReadOnlyAccess session policy / `vouch:AccessType=ai` tags
    // (issues #398, #426).
    let agent_source = aws::detect_agent_source();
    let cache_key = build_cache_key(target, &profile.role_arn, agent_source.as_deref());

    let agent = agent_source;
    let data = cache::get_or_fetch(&cache_key, "CodeArtifact token", || async {
        let token = fetch_token(server, target, profile.target(), agent.as_deref()).await?;
        let expires_at = jiff::Timestamp::from_second(token.expiration)
            .map_or_else(|_| cache::default_expiry(), |ts| ts.to_string());
        let data = serde_json::json!({
            "authorization_token": token.authorization_token.expose_secret(),
            "expiration": token.expiration,
        });
        Ok((data, expires_at))
    })
    .await?;

    let auth_token = data
        .get("authorization_token")
        .and_then(|v| v.as_str())
        .context(tr!(
            "err-cached-codeartifact-token-missing-authorization-toke"
        ))?;
    let expiration = data
        .get("expiration")
        .and_then(|v| v.as_i64())
        .context(tr!("err-cached-codeartifact-token-missing-expiration"))?;

    Ok(CodeArtifactToken {
        authorization_token: SecretString::from(auth_token.to_string()),
        expiration,
    })
}

/// Build the cache key for CodeArtifact tokens.
///
/// The resolved role ARN is part of the key — not the optional
/// `target.profile` — because two invocations against the same domain can
/// resolve to different accounts (different `AWS_PROFILE` values, or a
/// changed set of Vouch profiles) even when neither names an AWS profile
/// explicitly. The agent source is folded in so that agent and non-agent
/// invocations never share a cached entry (same pattern as the STS, EKS,
/// RDS, and Redshift credential caches).
fn build_cache_key(target: &CodeArtifactTarget, role_arn: &str, agent: Option<&str>) -> String {
    let suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    format!(
        "codeartifact:{}:{}:{}:{role_arn}{suffix}",
        target.domain, target.domain_owner, target.region
    )
}

/// Fetch a fresh CodeArtifact token (no caching).
async fn fetch_token(
    server: &ServerUrl,
    target: &CodeArtifactTarget,
    role: RoleTarget<'_>,
    agent_source: Option<&str>,
) -> Result<CodeArtifactToken> {
    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role,
        region: &target.region,
        management_role: None,
        agent_source,
    })
    .await?;

    let registry = CodeArtifactRegistry {
        domain: target.domain.clone(),
        domain_owner: target.domain_owner.clone(),
        region: target.region.clone(),
        domain_suffix: result.domain_suffix.to_string(),
    };

    let ca_token = get_authorization_token(&result.http_client, &registry, &result.credentials)
        .await
        .context(tr!("err-failed-get-codeartifact-authorization-token"))?;

    Ok(ca_token)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{CodeArtifactTarget, anchor_for, build_cache_key};
    use crate::config::CodeArtifactProfile;

    const PROD_ROLE: &str = "arn:aws:iam::111111111111:role/vouch-prod";
    const DEMO_ROLE: &str = "arn:aws:iam::222222222222:role/vouch-demo";

    fn target(profile: Option<&str>) -> CodeArtifactTarget {
        CodeArtifactTarget {
            domain: "my-domain".to_string(),
            domain_owner: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            profile: profile.map(str::to_string),
        }
    }

    fn saved(domain: &str, owner: &str, region: &str, aws_profile: &str) -> CodeArtifactProfile {
        CodeArtifactProfile {
            domain: domain.to_string(),
            domain_owner: owner.to_string(),
            region: region.to_string(),
            aws_profile: Some(aws_profile.to_string()),
        }
    }

    // The parsed URL host is lowercased, so a domain saved in another case must
    // still find its anchor.
    #[test]
    fn test_anchor_matches_domain_and_region_case_insensitively() {
        let profiles = [saved("My-Domain", "123456789012", "US-East-1", "prod")];
        assert_eq!(
            anchor_for(profiles.iter(), "my-domain", "123456789012", "us-east-1"),
            Some("prod".to_string())
        );
    }

    #[test]
    fn test_anchor_requires_the_same_owner() {
        let profiles = [saved("my-domain", "111111111111", "us-east-1", "prod")];
        assert_eq!(
            anchor_for(profiles.iter(), "my-domain", "123456789012", "us-east-1"),
            None
        );
    }

    #[test]
    fn test_anchor_is_none_when_profiles_disagree() {
        let profiles = [
            saved("my-domain", "123456789012", "us-east-1", "prod"),
            saved("MY-DOMAIN", "123456789012", "us-east-1", "demo"),
        ];
        assert_eq!(
            anchor_for(profiles.iter(), "my-domain", "123456789012", "us-east-1"),
            None
        );
    }

    /// Agent and non-agent invocations must never share a cached token:
    /// the agent-restricted STS exchange (ReadOnlyAccess session policy)
    /// would otherwise be bypassed by a full-access cached entry (#716).
    #[test]
    fn test_cache_key_includes_agent_source() {
        let plain = build_cache_key(&target(None), PROD_ROLE, None);
        let agent = build_cache_key(&target(None), PROD_ROLE, Some("claude-code"));
        assert_eq!(
            plain,
            format!("codeartifact:my-domain:123456789012:us-east-1:{PROD_ROLE}")
        );
        assert_eq!(
            agent,
            format!("codeartifact:my-domain:123456789012:us-east-1:{PROD_ROLE}:agent:claude-code")
        );
        assert_ne!(plain, agent);
    }

    /// Two CodeArtifact profiles may name the same domain while minting tokens
    /// from different AWS accounts; sharing a cache entry would hand one
    /// account's token to the other.
    #[test]
    fn test_cache_key_separates_aws_profiles() {
        let prod = build_cache_key(&target(Some("vouch-prod")), PROD_ROLE, None);
        let demo = build_cache_key(&target(Some("vouch-demo")), DEMO_ROLE, None);
        assert_ne!(prod, demo);
    }

    /// The resolved account can differ between two calls that never name an
    /// AWS profile at all — e.g. `AWS_PROFILE` changes, or the set of
    /// Vouch-managed profiles in `~/.aws/config` changes between them.
    /// `target.profile` is `None` in both cases here; keying on that field
    /// alone (rather than the resolved role ARN) would collapse both calls
    /// into one cache entry and hand one account's token to the other
    /// (reported against an earlier revision of this cache key).
    #[test]
    fn test_cache_key_separates_resolved_roles_when_profile_unset() {
        let first = build_cache_key(&target(None), PROD_ROLE, None);
        let second = build_cache_key(&target(None), DEMO_ROLE, None);
        assert_ne!(first, second);
    }

    /// Verify the CodeArtifact cache JSON round-trips correctly.
    ///
    /// The `get_token` function serializes with `json!()` and then extracts
    /// fields with `.get("authorization_token")` and `.get("expiration")`.
    /// This test ensures the field names match between serialization and extraction.
    #[test]
    fn test_codeartifact_cache_round_trip() {
        let token_value = "eyJhbGciOi...example-ca-token";
        let expiration_value: i64 = 1_705_234_567;

        // Simulate what get_token's cache closure produces
        let data = serde_json::json!({
            "authorization_token": token_value,
            "expiration": expiration_value,
        });

        // Simulate what get_token's extraction code does
        let auth_token = data
            .get("authorization_token")
            .and_then(|v| v.as_str())
            .expect("authorization_token must be present and a string");
        let expiration = data
            .get("expiration")
            .and_then(|v| v.as_i64())
            .expect("expiration must be present and an integer");

        assert_eq!(auth_token, token_value);
        assert_eq!(expiration, expiration_value);
    }
}
