// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Remote JWKS fetching and cache freshness.
//!
//! Every consumer of a client's `jwks_uri` needs the same guarantees — HTTPS
//! only, SSRF-guarded egress, a response size cap, and a cache that is checked
//! for freshness rather than trusted indefinitely. This module owns that core so
//! the RFC 7523 assertion path (`services::oidc::jwt_bearer::jwks`) and the RFC
//! 9421 signature path (`infra::httpsig`) cannot drift apart on it.
//!
//! Callers differ in *policy* — how stale is too stale, and what to do when a
//! fetch fails — so that stays with them. [`fetch_and_cache`] is the primitive;
//! [`resolve_cached_jwks`] adds the TTL plus stale-while-revalidate policy that
//! both request-verification paths want.

use crate::db;
use crate::db::documents::jwks_cache::{JWKS_STALE_MAX_AGE_SECONDS, JwksCacheDoc};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};

/// Maximum JWKS response size (256KB).
const MAX_JWKS_RESPONSE_SIZE: usize = 256 * 1024;

/// JWKS URI cache TTL in seconds (1 hour).
pub(crate) const JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Per-request timeout for a JWKS fetch (seconds).
///
/// `AppState::http_client` has no client-level timeout configured, so an
/// unbounded request to a stalling `jwks_uri` server would hang the calling
/// request indefinitely — including the token endpoint, which resolves this
/// synchronously as part of authenticating a client. Applied per-request
/// here rather than on the shared client.
const JWKS_FETCH_TIMEOUT_SECONDS: u64 = 10;

/// Fetch a JWKS document from a remote URI.
///
/// Enforces HTTPS-only and a response size cap.
async fn fetch_jwks(
    uri: &str,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<String> {
    // HTTPS-only
    if !uri.starts_with("https://") {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS URI must use HTTPS",
        ));
    }

    // SSRF egress guard: a client-registered `jwks_uri` is fetched here while
    // verifying a `private_key_jwt` assertion or an RFC 9421 signature, and
    // dynamic client registration is unauthenticated — refuse to dial
    // private/link-local targets. Loopback is permitted only in local
    // development (`allow_loopback`).
    crate::infra::ssrf::assert_public_destination(
        uri,
        allow_loopback,
        OAuthErrorCode::InvalidClient,
    )
    .await?;

    let response = http_client
        .get(uri)
        .timeout(std::time::Duration::from_secs(JWKS_FETCH_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("Failed to fetch JWKS from {uri}: {e}");
            ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Failed to fetch JWKS from URI",
            )
        })?;

    if !response.status().is_success() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS URI request failed",
        ));
    }

    // Check content length before reading body
    if let Some(len) = response.content_length()
        && len > MAX_JWKS_RESPONSE_SIZE as u64
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response exceeds maximum size (256KB)",
        ));
    }

    let body = response.bytes().await.map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!("Failed to read JWKS response: {e}"),
        )
    })?;

    if body.len() > MAX_JWKS_RESPONSE_SIZE {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response exceeds maximum size (256KB)",
        ));
    }

    String::from_utf8(body.to_vec()).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response is not valid UTF-8",
        )
    })
}

/// Fetch a JWKS from `uri` and write it to the cache under `parent_id`.
///
/// A cache-write failure is logged and swallowed: the freshly fetched keys are
/// still correct, and failing the request would turn a caching problem into an
/// authentication outage.
///
/// This is the unconditional fetch. Callers that want to consult a cache first
/// use [`resolve_cached_jwks`], or apply their own freshness rule.
pub(crate) async fn fetch_and_cache(
    store: &db::store::DocumentStore,
    parent_id: &str,
    uri: &str,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<serde_json::Value> {
    let jwks_json = fetch_jwks(uri, allow_loopback, http_client).await?;
    let jwks_value: serde_json::Value = serde_json::from_str(&jwks_json).map_err(|e| {
        tracing::debug!("Failed to parse JWKS as JSON value: {e}");
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid JWKS format")
    })?;

    if let Err(e) = db::upsert_jwks_cache(store, parent_id, &jwks_value).await {
        tracing::warn!("Failed to update JWKS cache for {parent_id}: {e}");
    }

    Ok(jwks_value)
}

/// Whether [`resolve_cached_jwks`] made a live network call.
///
/// Reported by the function itself rather than inferred by a caller from its
/// inputs — a caller re-deriving this from the cache's freshness would be a
/// second encoding of the same branch rule, liable to silently diverge if
/// the TTL policy or fetch logic here changes without the mirror keeping up.
#[derive(Debug)]
pub(crate) enum JwksOrigin {
    /// Served from a cache row within [`JWKS_CACHE_TTL_SECONDS`] — no
    /// network call.
    NoFetch,
    /// A fetch was attempted — successfully, or falling back to a stale
    /// cache after a failed one.
    Fetched,
}

/// Resolve a client's JWKS, refetching when the cache is past its TTL.
///
/// Returns the cached document while it is younger than
/// [`JWKS_CACHE_TTL_SECONDS`]; otherwise refetches. If the refetch fails, falls
/// back to the stale cache while it is within [`JWKS_STALE_MAX_AGE_SECONDS`] so
/// a brief outage at the client's JWKS host does not break verification —
/// beyond that the error is surfaced, because a key rotated out long ago must
/// stop verifying. Also reports whether it fetched, via [`JwksOrigin`].
pub(crate) async fn resolve_cached_jwks(
    store: &db::store::DocumentStore,
    parent_id: &str,
    uri: &str,
    cached: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<(serde_json::Value, JwksOrigin)> {
    if let Some(cache) = cached
        && cache.is_fresh(JWKS_CACHE_TTL_SECONDS)
    {
        return Ok((cache.value.clone(), JwksOrigin::NoFetch));
    }

    match fetch_and_cache(store, parent_id, uri, allow_loopback, http_client).await {
        Ok(value) => Ok((value, JwksOrigin::Fetched)),
        Err(e) => {
            // Stale-while-revalidate, capped so a rotated-out key cannot verify
            // indefinitely just because the client's host is unreachable.
            if let Some(cache) = cached {
                if cache.is_within_stale_window(JWKS_STALE_MAX_AGE_SECONDS) {
                    tracing::warn!("JWKS fetch failed, using stale cache: {e}");
                    return Ok((cache.value.clone(), JwksOrigin::Fetched));
                }
                tracing::warn!(
                    "JWKS fetch failed and stale cache too old ({}s)",
                    cache.age_seconds()
                );
            }
            Err(e)
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Assert the error is an `invalid_client` OAuth error rejecting non-HTTPS.
    fn assert_rejected_as_non_https(err: &ServiceError) {
        assert!(
            matches!(err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS")
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_http_url() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("http://example.com/jwks", false, &client)
            .await
            .expect_err("http:// must be rejected");
        assert_rejected_as_non_https(&err);
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_ftp_url() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("ftp://example.com/jwks", false, &client)
            .await
            .expect_err("ftp:// must be rejected");
        assert_rejected_as_non_https(&err);
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_empty_uri() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("", false, &client)
            .await
            .expect_err("empty URI must be rejected");
        assert_rejected_as_non_https(&err);
    }

    /// A cache doc aged `age_seconds` in the past, holding one key id.
    fn cache_doc(age_seconds: i64, kid: &str) -> JwksCacheDoc {
        JwksCacheDoc {
            value: serde_json::json!({ "keys": [{ "kty": "EC", "kid": kid }] }),
            cached_at: jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(age_seconds))
                .expect("cache age must be representable"),
        }
    }

    /// A URI the SSRF guard always refuses, standing in for an unreachable
    /// JWKS host without touching the network.
    const UNREACHABLE_URI: &str = "https://127.0.0.1:1/jwks.json";

    #[tokio::test]
    async fn resolve_returns_fresh_cache_without_fetching() {
        let state = crate::test_utils::test_app_state().await;
        let cached = cache_doc(60, "fresh-key");

        // The URI would fail if dialed, so a success proves no fetch happened.
        let (value, origin) = resolve_cached_jwks(
            &state.store,
            "client-fresh",
            UNREACHABLE_URI,
            Some(&cached),
            false,
            &state.http_client,
        )
        .await
        .expect("a fresh cache must be served without a fetch");

        assert_eq!(value, cached.value);
        assert!(matches!(origin, JwksOrigin::NoFetch));
    }

    /// Regression for #748: past the TTL, a key the client has rotated out must
    /// stop verifying. The RFC 9421 resolver previously read the cache verbatim,
    /// so a stale key stayed valid until the row happened to be replaced.
    #[tokio::test]
    async fn resolve_rejects_cache_older_than_the_stale_window() {
        let state = crate::test_utils::test_app_state().await;
        let cached = cache_doc(JWKS_STALE_MAX_AGE_SECONDS + 3600, "rotated-out-key");

        let result = resolve_cached_jwks(
            &state.store,
            "client-ancient",
            UNREACHABLE_URI,
            Some(&cached),
            false,
            &state.http_client,
        )
        .await;

        assert!(
            result.is_err(),
            "a cache past the stale window must not be served: {result:?}"
        );
    }

    /// Between the TTL and the stale-window cap, an unreachable JWKS host must
    /// not break verification outright.
    #[tokio::test]
    async fn resolve_serves_stale_cache_within_the_window() {
        let state = crate::test_utils::test_app_state().await;
        let cached = cache_doc(JWKS_CACHE_TTL_SECONDS + 60, "recently-stale-key");

        let (value, origin) = resolve_cached_jwks(
            &state.store,
            "client-stale",
            UNREACHABLE_URI,
            Some(&cached),
            false,
            &state.http_client,
        )
        .await
        .expect("a cache within the stale window must survive a failed fetch");

        assert_eq!(value, cached.value);
        assert!(
            matches!(origin, JwksOrigin::Fetched),
            "a fetch was attempted, even though it fell back to the stale cache"
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_loopback_when_not_allowed() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("https://127.0.0.1/jwks.json", false, &client)
            .await
            .expect_err("loopback must be rejected without allow_loopback");
        // The SSRF guard, not the HTTPS check, must be what rejects this.
        assert!(
            !matches!(&err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS"),
            "expected SSRF rejection, got: {err}"
        );
    }
}
