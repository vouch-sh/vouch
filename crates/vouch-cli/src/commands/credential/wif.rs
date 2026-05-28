// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared Workload Identity Federation helpers for AI providers.
//!
//! Both `vouch credential anthropic` and `vouch credential openai` follow
//! the same two-step exchange:
//!
//! 1. Fetch a clean OIDC ID token from `GET /v1/credentials/oidc/token` on
//!    the Vouch server (the *assertion*). This call uses DPoP-authenticated
//!    `VouchClient` and is non-interactive — `resolve_token()` only reads
//!    the existing session, never triggers FIDO2.
//! 2. POST the assertion to the provider's token endpoint (Anthropic's
//!    RFC 7523 jwt-bearer or OpenAI's RFC 8693 token-exchange grant) and
//!    receive a short-lived provider token.
//!
//! The assertion is intentionally **not** cached separately:
//! - each minted ID token carries a unique `jti` and is meant for single use;
//! - the audience differs per provider, so an assertion fetched for Anthropic
//!   is not reusable for OpenAI.
//!
//! Only the provider's response is cached (by the caller via
//! [`super::cache::get_or_fetch`]).
//!
//! [`super::cache::get_or_fetch`]: super::cache::get_or_fetch

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::Deserialize;

use crate::client::VouchClient;

/// Number of seconds shaved off the provider's stated `expires_in` when
/// computing the cache expiry — gives callers a window to refresh before
/// the token actually expires.
const REFRESH_MARGIN_SECS: i64 = 60;

/// Response from the Vouch generic OIDC token endpoint.
///
/// Mirrors `vouch_common::OidcTokenResponse`. Held locally so the secret
/// can be wrapped in `SecretString` rather than `String`.
#[derive(Deserialize)]
struct VouchOidcTokenResponse {
    id_token: SecretString,
}

impl std::fmt::Debug for VouchOidcTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VouchOidcTokenResponse")
            .field("id_token", &"[REDACTED]")
            .finish()
    }
}

/// Fetch a generic OIDC ID token from the Vouch server to use as the WIF
/// assertion. `audience`, when set, is requested as the token's `aud` claim;
/// when `None`, the server defaults to its own issuer URL.
pub(crate) async fn fetch_assertion(server: &str, audience: Option<&str>) -> Result<SecretString> {
    let client = VouchClient::new(server).await?;
    let path = match audience.filter(|s| !s.is_empty()) {
        Some(aud) => {
            let q = serde_urlencoded::to_string([("audience", aud)])
                .context("failed to encode audience query parameter")?;
            format!("/v1/credentials/oidc/token?{q}")
        }
        None => "/v1/credentials/oidc/token".to_string(),
    };
    let resp: VouchOidcTokenResponse = client
        .get_authenticated(&path)
        .await
        .context("failed to fetch federation assertion from Vouch server")?;
    Ok(resp.id_token)
}

/// Standard OAuth 2.0 token response from a provider's token endpoint
/// (RFC 6749 §5.1). Both Anthropic and OpenAI return this shape.
#[derive(Deserialize)]
struct ProviderTokenResponse {
    access_token: SecretString,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl std::fmt::Debug for ProviderTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// POST a JSON token-exchange request to a provider and return the minted
/// access token paired with an ISO 8601 cache-expiry timestamp.
///
/// `body` is the provider-specific request (Anthropic: `jwt-bearer` grant;
/// OpenAI: `token-exchange` grant). `label` names the provider in error
/// messages.
pub(crate) async fn exchange(
    endpoint: &str,
    body: &serde_json::Value,
    label: &str,
) -> Result<(SecretString, String)> {
    let client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let payload = serde_json::to_vec(body).context("failed to serialize token-exchange request")?;

    let response = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .with_context(|| format!("failed to reach {label} token endpoint at {endpoint}"))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("failed to read {label} token response body"))?;

    if !status.is_success() {
        anyhow::bail!("{label} token exchange failed ({status}): {text}");
    }

    let parsed: ProviderTokenResponse = serde_json::from_str(&text)
        .with_context(|| format!("invalid {label} token response: {text}"))?;

    let expiry = cache_expiry(parsed.expires_in);
    Ok((parsed.access_token, expiry))
}

/// Compute the cache-expiry timestamp from a provider's `expires_in` (seconds),
/// applying [`REFRESH_MARGIN_SECS`] of safety margin so we never hand out a
/// token about to die. Falls back to [`super::cache::default_expiry`] when
/// the provider omits `expires_in`.
fn cache_expiry(expires_in: Option<u64>) -> String {
    let Some(secs) = expires_in else {
        return super::cache::default_expiry();
    };
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let lifetime = secs.saturating_sub(REFRESH_MARGIN_SECS).max(1);
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(lifetime))
        .map_or_else(|_| super::cache::default_expiry(), |ts| ts.to_string())
}

/// Build the agent-aware cache key used by the provider commands.
///
/// Folding the detected agent source into the key mirrors the AWS
/// rationale (issue #398): agent and non-agent invocations must not
/// share a cached token, since they may carry different attribution
/// claims when an agent is detected.
pub(crate) fn build_cache_key(provider: &str, id: &str, agent: Option<&str>) -> String {
    match agent {
        Some(src) => format!("{provider}:{id}:agent:{src}"),
        None => format!("{provider}:{id}"),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_expiry_none_returns_default() {
        let ts = cache_expiry(None);
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_cache_expiry_applies_safety_margin() {
        let before = jiff::Timestamp::now();
        let ts = cache_expiry(Some(3600));
        let parsed: jiff::Timestamp = ts.parse().unwrap();
        // Should be roughly 3540s in the future (3600 - 60s margin), allowing slop.
        let delta_s = (parsed.as_second()).saturating_sub(before.as_second());
        assert!(
            delta_s > 3500,
            "expiry was {delta_s}s from now (expected ~3540)"
        );
        assert!(
            delta_s < 3600,
            "expiry was {delta_s}s from now (expected ~3540)"
        );
    }

    #[test]
    fn test_cache_expiry_handles_u64_max() {
        // u64::MAX → i64::MAX via try_from fallback, then checked_add fails
        // → fall back to default_expiry without panicking.
        let ts = cache_expiry(Some(u64::MAX));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_cache_expiry_small_value_does_not_underflow() {
        // 30s lifetime − 60s margin would underflow without the .max(1) clamp.
        let ts = cache_expiry(Some(30));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    /// A provider returning `expires_in: 0` is malformed but must not panic
    /// or loop — the `.max(1)` clamp gives the cache a 1-second TTL so the
    /// next invocation re-fetches without thrashing in a tight loop.
    #[test]
    fn test_cache_expiry_zero_value_does_not_panic() {
        let ts = cache_expiry(Some(0));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_build_cache_key_with_and_without_agent() {
        assert_eq!(
            build_cache_key("anthropic", "fdrl_abc", None),
            "anthropic:fdrl_abc"
        );
        assert_eq!(
            build_cache_key("anthropic", "fdrl_abc", Some("claude-code")),
            "anthropic:fdrl_abc:agent:claude-code"
        );
    }

    #[test]
    fn test_build_cache_key_differs_per_agent() {
        let a = build_cache_key("openai", "wip_1", Some("claude-code"));
        let b = build_cache_key("openai", "wip_1", Some("cursor"));
        assert_ne!(a, b);
    }
}
