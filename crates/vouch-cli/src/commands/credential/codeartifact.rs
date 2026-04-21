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

use crate::commands::credential::aws::exchange_for_sts_credentials;
use crate::commands::credential::cache;
use crate::config::Config;
use crate::integrations::aws::codeartifact::{
    CodeArtifactRegistry, CodeArtifactToken, get_authorization_token,
};
use crate::integrations::aws::get_local_aws_role;

/// Resolve CodeArtifact domain/owner/region from CLI flags, profile, or default profile.
///
/// Resolution order:
/// 1. Explicit flags (if all three are provided)
/// 2. Named profile (`--profile <name>`)
/// 3. Default profile (`codeartifact.default`)
/// 4. Error with helpful message
pub(crate) fn resolve_codeartifact_params(
    domain: Option<&str>,
    domain_owner: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<(String, String, String)> {
    // If all three flags are provided, use them directly
    if let (Some(d), Some(o), Some(r)) = (domain, domain_owner, region) {
        return Ok((d.to_string(), o.to_string(), r.to_string()));
    }

    // Try to load from config profile
    let config = Config::load().context("failed to load config")?;
    let ca_config = config.codeartifact();

    let resolved_profile = if let Some(name) = profile {
        // Explicit --profile flag
        ca_config
            .and_then(|c| c.profiles.get(name))
            .ok_or_else(|| {
                let available = ca_config
                    .map(|c| {
                        c.profiles
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                if available.is_empty() {
                    anyhow::anyhow!(
                        "CodeArtifact profile '{name}' not found. \
                         No profiles configured. Run 'vouch setup codeartifact' first."
                    )
                } else {
                    anyhow::anyhow!(
                        "CodeArtifact profile '{name}' not found. \
                         Available profiles: {available}"
                    )
                }
            })?
    } else {
        // Try default profile
        let default_name = ca_config.and_then(|c| c.default.as_deref());
        match default_name {
            Some(name) => ca_config
                .and_then(|c| c.profiles.get(name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Default CodeArtifact profile '{name}' not found in config. \
                         Run 'vouch setup codeartifact' to reconfigure."
                    )
                })?,
            None => {
                return Err(anyhow::anyhow!(
                    "No CodeArtifact domain specified. Either:\n  \
                     - Pass --domain, --domain-owner, and --region flags\n  \
                     - Run 'vouch setup codeartifact' to save a profile\n  \
                     - Pass --profile <name> to use a saved profile"
                ));
            }
        }
    };

    // Allow individual flags to override profile values
    Ok((
        domain.unwrap_or(&resolved_profile.domain).to_string(),
        domain_owner
            .unwrap_or(&resolved_profile.domain_owner)
            .to_string(),
        region.unwrap_or(&resolved_profile.region).to_string(),
    ))
}

/// Run the CodeArtifact credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Calls AWS STS `AssumeRoleWithWebIdentity`
/// 3. Calls CodeArtifact `GetAuthorizationToken` with SigV4 signing
/// 4. Outputs the bearer token to stdout
pub(crate) async fn run(
    server: &str,
    domain: Option<&str>,
    domain_owner: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    let (domain, domain_owner, region) =
        resolve_codeartifact_params(domain, domain_owner, region, profile)?;

    let token = get_token(server, &domain, &domain_owner, &region).await?;
    println!("{}", token.authorization_token.expose_secret());
    Ok(())
}

/// Get a CodeArtifact token using the full Vouch → STS → CodeArtifact flow,
/// with agent-side caching.
///
/// This is the shared core used by both the standalone command and the
/// Cargo credential provider when it detects a CodeArtifact index URL.
pub(crate) async fn get_token(
    server: &str,
    domain: &str,
    domain_owner: &str,
    region: &str,
) -> Result<CodeArtifactToken> {
    let cache_key = format!("codeartifact:{domain}:{domain_owner}:{region}");

    let data = cache::get_or_fetch(&cache_key, "CodeArtifact token", || async {
        let token = fetch_token(server, domain, domain_owner, region).await?;
        let expires_at = jiff::Timestamp::from_second(token.expiration)
            .map(|ts| ts.to_string())
            .unwrap_or_else(|_| cache::default_expiry());
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
        .context("cached CodeArtifact token missing authorization_token")?;
    let expiration = data
        .get("expiration")
        .and_then(|v| v.as_i64())
        .context("cached CodeArtifact token missing expiration")?;

    Ok(CodeArtifactToken {
        authorization_token: SecretString::from(auth_token.to_string()),
        expiration,
    })
}

/// Fetch a fresh CodeArtifact token (no caching).
async fn fetch_token(
    server: &str,
    domain: &str,
    domain_owner: &str,
    region: &str,
) -> Result<CodeArtifactToken> {
    let role_arn = get_local_aws_role().ok_or_else(|| {
        anyhow::anyhow!(
            "AWS not configured. Run 'vouch setup aws --role <role-arn>' \
             with a role that has CodeArtifact permissions"
        )
    })?;

    let result = exchange_for_sts_credentials(
        server,
        &role_arn,
        region,
        "vouch-codeartifact",
        None,
        &[],
        None,
    )
    .await?;

    let registry = CodeArtifactRegistry {
        domain: domain.to_string(),
        domain_owner: domain_owner.to_string(),
        region: region.to_string(),
        domain_suffix: result.domain_suffix.to_string(),
    };

    let ca_token = get_authorization_token(&result.http_client, &registry, &result.credentials)
        .await
        .context("failed to get CodeArtifact authorization token")?;

    Ok(ca_token)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
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
