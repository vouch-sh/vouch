// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent-side credential caching helpers.
//!
//! All operations are best-effort: if the agent is not running or the cache
//! is empty, these functions return `None` / silently succeed without
//! blocking the caller.

use std::future::Future;

use anyhow::Result;
#[cfg(unix)]
use tracing::debug;

/// Try to retrieve a cached credential from the agent.
///
/// Returns the credential data as a JSON value, or `None` if the agent is
/// unreachable, the cache key is missing, or the cached credential has expired.
pub(crate) async fn get(cache_key: &str) -> Option<serde_json::Value> {
    #[cfg(not(unix))]
    {
        let _ = cache_key;
        return None;
    }

    #[cfg(unix)]
    {
        let mut client = vouch_agent::AgentClient::connect().await.ok()?;
        match client.get_cached_credential(cache_key).await {
            Ok(Some(cached)) => Some(cached.data()),
            Ok(None) => None,
            Err(e) => {
                debug!("credential cache miss for {cache_key}: {e}");
                None
            }
        }
    }
}

/// Store a credential in the agent cache (best-effort).
///
/// Does nothing if the agent is unreachable.
pub(crate) async fn store(cache_key: &str, data: serde_json::Value, expires_at: &str) {
    #[cfg(not(unix))]
    {
        let _ = (cache_key, data, expires_at);
    }

    #[cfg(unix)]
    {
        if let Ok(mut client) = vouch_agent::AgentClient::connect().await
            && let Err(e) = client.cache_credential(cache_key, data, expires_at).await
        {
            debug!("failed to cache credential {cache_key}: {e}");
        }
    }
}

/// Fetch a credential using a cache-first strategy with network error fallback.
///
/// 1. Check agent cache — return immediately if valid cached credentials exist
/// 2. Call `fetch` to get fresh data, cache the result
/// 3. On network error, fall back to cached credentials (if any)
///
/// The `fetch` closure must return `(data, expires_at)` where `expires_at` is
/// an ISO 8601 timestamp string for the cache TTL.
pub(crate) async fn get_or_fetch<F, Fut>(
    cache_key: &str,
    label: &str,
    fetch: F,
) -> Result<serde_json::Value>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(serde_json::Value, String)>>,
{
    // 1. Check cache
    if let Some(cached) = get(cache_key).await {
        return Ok(cached);
    }

    // 2. Fetch fresh
    match fetch().await {
        Ok((data, expires_at)) => {
            store(cache_key, data.clone(), &expires_at).await;
            Ok(data)
        }
        Err(e) if is_network_error(&e) => {
            // 3. Network error — fall back to cache
            if let Some(cached) = get(cache_key).await {
                eprintln!("vouch: using cached {label} (server unreachable)");
                Ok(cached)
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

/// Check if an error is a network/connectivity error that warrants cache fallback.
///
/// Delegates to [`crate::exit_code::classify`] which checks for `reqwest::Error`,
/// `CliError::NetworkError`, and message-based patterns in a single place.
pub(crate) fn is_network_error(err: &anyhow::Error) -> bool {
    crate::exit_code::classify(err) == std::process::ExitCode::from(crate::exit_code::NETWORK_ERROR)
}

/// Build a default expiry timestamp (1 hour from now) for tokens that don't
/// include an explicit expiration.
pub(crate) fn default_expiry() -> String {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_hours(1))
        .map(|ts| ts.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_network_error_connection_refused() {
        let err =
            anyhow::anyhow!("failed to connect to https://vouch.example.com: connection refused");
        assert!(is_network_error(&err));
    }

    #[test]
    fn test_is_network_error_timeout() {
        let err = anyhow::anyhow!("request timed out waiting for server");
        assert!(is_network_error(&err));
    }

    #[test]
    fn test_is_network_error_dns() {
        let err = anyhow::anyhow!("dns error: failed to resolve hostname");
        assert!(is_network_error(&err));
    }

    #[test]
    fn test_is_network_error_false_for_auth() {
        let err = anyhow::anyhow!("not authenticated - run 'vouch login' first");
        assert!(!is_network_error(&err));
    }

    #[test]
    fn test_is_network_error_false_for_generic() {
        let err = anyhow::anyhow!("invalid role ARN format");
        assert!(!is_network_error(&err));
    }

    #[test]
    fn test_default_expiry_returns_valid_timestamp() {
        let expiry = default_expiry();
        assert!(!expiry.is_empty());
        // Should be parseable as a jiff Timestamp
        assert!(expiry.parse::<jiff::Timestamp>().is_ok());
    }
}
