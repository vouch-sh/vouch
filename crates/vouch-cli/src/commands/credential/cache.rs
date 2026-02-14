// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent-side credential caching helpers.
//!
//! All operations are best-effort: if the agent is not running or the cache
//! is empty, these functions return `None` / silently succeed without
//! blocking the caller.

use tracing::debug;

/// Try to retrieve a cached credential from the agent.
///
/// Returns the credential data as a JSON value, or `None` if the agent is
/// unreachable, the cache key is missing, or the cached credential has expired.
pub async fn get(cache_key: &str) -> Option<serde_json::Value> {
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
pub async fn store(cache_key: &str, data: serde_json::Value, expires_at: &str) {
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

/// Check if an error is a network/connectivity error that warrants cache fallback.
pub fn is_network_error(err: &anyhow::Error) -> bool {
    // Check for reqwest connection/timeout errors
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        return reqwest_err.is_connect() || reqwest_err.is_timeout();
    }

    // Check error message for common network failure patterns
    let msg = format!("{err:#}").to_lowercase();
    msg.contains("failed to connect")
        || msg.contains("connection refused")
        || msg.contains("server unreachable")
        || msg.contains("dns error")
        || msg.contains("timed out")
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
}
