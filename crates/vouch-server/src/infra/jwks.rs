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
use crate::infra::egress::{BodyError, read_capped_text};
use crate::infra::ssrf;

/// Maximum JWKS response size (256KB).
const MAX_JWKS_RESPONSE_SIZE: usize = 256 * 1024;

/// JWKS URI cache TTL in seconds (1 hour).
pub(crate) const JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Per-request timeout for a JWKS fetch (seconds).
///
/// The token endpoint resolves this synchronously while authenticating a
/// client, so a stalling `jwks_uri` host holds a request slot for as long as
/// the fetch runs. Kept explicit, rather than inherited from the shared
/// client's `SERVER_TOTAL`, so loosening that budget never loosens this one.
const JWKS_FETCH_TIMEOUT_SECONDS: u64 = 5;

/// Read a JWKS response body under [`MAX_JWKS_RESPONSE_SIZE`], reporting
/// failures in the token endpoint's vocabulary.
///
/// The bounded read itself lives in [`crate::infra::egress`], which streams the
/// body and aborts the moment the running length crosses the cap — a
/// `Content-Length` check alone would not do, because `content_length()` is
/// `None` for a `Transfer-Encoding: chunked` response and a hostile `jwks_uri`
/// can stream until the fetch timeout (issue #1105). This binds that reader to
/// this endpoint's cap and maps its errors onto `invalid_client`, whose
/// descriptions RFC 6749 Section 5.2 addresses to the client developer and so
/// stay ASCII English.
async fn read_jwks_body(response: reqwest::Response) -> ServiceResult<String> {
    read_capped_text(response, MAX_JWKS_RESPONSE_SIZE)
        .await
        .map_err(|e| {
            let description = match e {
                BodyError::TooLarge { .. } => {
                    "JWKS response exceeds maximum size (256KB)".to_string()
                }
                BodyError::NotUtf8 => "JWKS response is not valid UTF-8".to_string(),
                BodyError::Transport { source } => {
                    format!("Failed to read JWKS response: {source}")
                }
                BodyError::Json { source } => format!("Failed to read JWKS response: {source}"),
            };
            ServiceError::oauth(OAuthErrorCode::InvalidClient, description)
        })
}

/// Fetch a JWKS document from a remote URI.
///
/// Enforces HTTPS-only and a response size cap.
async fn fetch_jwks(
    uri: &str,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<String> {
    // HTTPS-only. RFC 3986 §3.1: "Although schemes are case-insensitive, the
    // canonical form is lowercase". `Url::parse` lowercases the scheme, the
    // same check registration uses to admit the URI.
    let parsed = url::Url::parse(uri).map_err(|_| {
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "JWKS URI must use HTTPS")
    })?;
    if parsed.scheme() != "https" {
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
    ssrf::assert_public_destination(uri, allow_loopback, OAuthErrorCode::InvalidClient).await?;

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

    // Enforce the response size cap while streaming the body via
    // [`read_jwks_body`]. `response.bytes().await` would buffer the whole
    // response before a size check could reject it; for `Transfer-Encoding:
    // chunked` the `Content-Length` is `None`, so the incremental chunk check
    // inside the helper is what bounds memory — see
    // `test_chunked_oversize_aborts_during_streaming`.
    read_jwks_body(response).await
}

/// Fetch a JWKS from `uri` and write it to the cache under `parent_id`.
///
/// Only a body that parses as a JWK Set is cached. RFC 7517 §5: "The JSON
/// object MUST have a \"keys\" member, with its value being an array of JWKs."
/// Any other answer fails this fetch the way a non-2xx response does, and
/// leaves the last good cache row in place for the stale-cache fallback.
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
    db::parse_jwks_set(&jwks_value).map_err(|e| {
        tracing::debug!("Fetched JWKS is not a JWK Set: {e}");
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
///
/// Threaded out of `jwt_bearer::jwks::resolve_client_jwks` so the RFC 7523
/// and RFC 9101 kid-miss force-refresh paths can gate a second fetch on it,
/// the same within-request bound the mTLS self-signed path applies.
#[derive(Debug)]
pub enum JwksOrigin {
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
    use crate::test_utils;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The end-to-end-over-TLS JWKS test serves `test_tls_acceptor`'s cert, so
    // verification is bypassed (`danger_accept_invalid_certs`):
    // the cert has no IP SAN and the SSRF guard resolves domain names via
    // hickory (which does not read `/etc/hosts`), so the URL uses the `127.0.0.1`
    // IP literal to avoid a DNS lookup. The size-cap mechanism under test is
    // transport-agnostic (per the bug report) — what matters is that it runs
    // *after* TLS termination on a real `reqwest::Response` over a real TLS
    // connection, which this exercises.

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
        let state = test_utils::test_app_state().await;
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
        let state = test_utils::test_app_state().await;
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
        let state = test_utils::test_app_state().await;
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

    /// RFC 3986 §3.1: "Although schemes are case-insensitive, the canonical
    /// form is lowercase". An `HTTPS://` URI passes the scheme check and is
    /// refused by the SSRF guard instead (loopback without `allow_loopback`).
    #[tokio::test]
    async fn fetch_jwks_accepts_uppercase_scheme_https_uri() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("HTTPS://127.0.0.1/jwks.json", false, &client)
            .await
            .expect_err("loopback must still be rejected without allow_loopback");
        assert!(
            !matches!(&err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS"),
            "upper-case HTTPS:// must not be rejected by the scheme check; got: {err}"
        );
    }

    /// `HTTP://` lowercases to `http` and is still refused.
    #[tokio::test]
    async fn fetch_jwks_still_rejects_uppercase_non_https_scheme() {
        let client = reqwest::Client::new();
        let err = fetch_jwks("HTTP://example.com/jwks", false, &client)
            .await
            .expect_err("an http scheme (any case) must be rejected as non-https");
        assert_rejected_as_non_https(&err);
    }

    /// Assert the error is an `invalid_client` OAuth error with `expected_desc`.
    fn assert_invalid_client(err: &ServiceError, expected_desc: &str) {
        assert!(
            matches!(err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient),
            "expected an InvalidClient OAuth error, got: {err:?}"
        );
        assert!(
            matches!(err, ServiceError::OAuth { description, .. } if description == expected_desc),
            "expected description {expected_desc:?}, got: {err:?}"
        );
    }

    /// Write one HTTP/1.1 chunked-transfer chunk to `stream`.
    ///
    /// Returns `false` on any write error so the caller stops once the client
    /// aborts mid-stream (its response is dropped on the oversized reject).
    /// Generic over any [`tokio::io::AsyncWrite`] so the same helper frames
    /// chunked bodies over both a raw `TcpStream` and a `TlsStream<TcpStream>`.
    async fn write_chunk<W>(stream: &mut W, data: &[u8]) -> bool
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let header = format!("{:x}\r\n", data.len());
        if stream.write_all(header.as_bytes()).await.is_err() {
            return false;
        }
        if stream.write_all(data).await.is_err() {
            return false;
        }
        stream.write_all(b"\r\n").await.is_ok()
    }

    /// Finish a mock exchange without a kernel RST: flush the write side
    /// (`shutdown` sends FIN after the response), then drain the client's
    /// request and await its close. Without this, dropping a `TcpStream` with
    /// the unread client request still in the recv buffer makes the kernel send
    /// RST, which reqwest surfaces as "error decoding response body" for any
    /// large response the client is still reading — a test-only artefact that
    /// would mask the real assertion.
    async fn graceful_close(stream: &mut tokio::net::TcpStream) {
        let _shutdown = stream.shutdown().await;
        let mut buf = vec![0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
        }
    }

    /// Spawn a one-shot loopback HTTP/1.1 server: accept exactly one connection
    /// and hand the [`tokio::net::TcpStream`] to `handle`, which writes the raw
    /// response with full manual control over framing (`Transfer-Encoding`,
    /// `Content-Length`) and timing.
    ///
    /// [`read_jwks_body`] only sees the [`reqwest::Response`] after TLS
    /// termination, so plain HTTP on loopback exercises the same body-read path
    /// a remote `jwks_uri` reaches — and lets the tests assert streaming and
    /// early-abort behaviour deterministically, without HTTPS or a real host.
    async fn spawn_raw_http_server<F, Fut>(handle: F) -> std::net::SocketAddr
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        let _join = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept connection");
            handle(stream).await;
        });
        addr
    }

    /// RFC 7517 §5: a JWKS is a JSON object with a `"keys"` array. A legitimate
    /// endpoint may use `Transfer-Encoding: chunked`; the streaming cap must
    /// accept it (no false positives below the cap), and `content_length()` is
    /// `None` — the very condition that defeated the old pre-read check.
    #[tokio::test]
    async fn read_jwks_body_accepts_small_chunked_response() {
        let expected: Vec<u8> = br#"{"keys":[{"kty":"EC","kid":"k1"}]}"#.to_vec();
        let payload = expected.clone();
        let addr = spawn_raw_http_server(move |mut stream| async move {
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            if !write_chunk(&mut stream, &payload).await {
                return;
            }
            // Chunked terminator; the client may already have closed after the
            // body, so a write error here is not a failure.
            let _trail = stream.write_all(b"0\r\n\r\n").await;
            graceful_close(&mut stream).await;
        })
        .await;

        let url = format!("http://{addr}/jwks");
        let response = reqwest::get(url).await.expect("GET succeeds");
        assert_eq!(
            response.content_length(),
            None,
            "chunked responses advertise no Content-Length"
        );
        let body = read_jwks_body(response)
            .await
            .expect("a small chunked body is under the cap and must be accepted");
        assert_eq!(body.as_bytes(), expected.as_slice());
    }

    /// A sized response advertising more than the cap via `Content-Length` is
    /// refused before any body bytes are pulled. The server deliberately
    /// withholds the body for 3s; a buffering reader would block on it, while
    /// the pre-read `Content-Length` check rejects in milliseconds.
    #[tokio::test]
    async fn read_jwks_body_rejects_oversized_content_length_without_reading_body() {
        const OVERSIZED_LEN: u64 = MAX_JWKS_RESPONSE_SIZE as u64 + 1;
        let addr = spawn_raw_http_server(|mut stream| async move {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {OVERSIZED_LEN}\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            // Withhold the body: prove the rejection did not depend on it.
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        })
        .await;

        let url = format!("http://{addr}/jwks");
        let start = std::time::Instant::now();
        let response = reqwest::get(url).await.expect("GET succeeds");
        assert_eq!(response.content_length(), Some(OVERSIZED_LEN));
        let err = read_jwks_body(response)
            .await
            .expect_err("an oversized Content-Length must be rejected up front");
        assert_invalid_client(&err, "JWKS response exceeds maximum size (256KB)");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "pre-read rejection took {elapsed:?}; it must not wait for the 3s-lingering body"
        );
    }

    /// Regression for the chunked-encoding memory-exhaustion vector (introduced
    /// in de8d930): a chunked body with no `Content-Length` streams past the cap.
    /// The old `response.bytes().await` + post-read check buffered the whole
    /// body first; the streaming cap must reject while reading, well before the
    /// full slow body is delivered, and the server must observe the abort (far
    /// fewer bytes pulled than it was willing to send).
    #[tokio::test]
    async fn test_chunked_oversize_aborts_during_streaming() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        // 128 KB headstart, then 40 × 32 KB at 100 ms each ≈ 4 s read in full.
        // The cap (256 KB) is crossed ~0.5 s in: an aborting reader rejects
        // fast; a buffering reader blocks ~4 s and only then rejects.
        const CHUNK_BIG: usize = 128 * 1024;
        const CHUNK_SMALL: usize = 32 * 1024;
        const SLOW_CHUNKS: u32 = 40;
        const TOTAL_WILLING: u64 = CHUNK_BIG as u64 + SLOW_CHUNKS as u64 * CHUNK_SMALL as u64;

        let observed = Arc::new(AtomicU64::new(0));
        let observed_server = observed.clone();
        let addr = spawn_raw_http_server(move |mut stream| async move {
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let big = vec![b'.'; CHUNK_BIG];
            if !write_chunk(&mut stream, &big).await {
                return;
            }
            observed_server.fetch_add(CHUNK_BIG as u64, Ordering::SeqCst);
            let small = vec![b'.'; CHUNK_SMALL];
            for _ in 0..SLOW_CHUNKS {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !write_chunk(&mut stream, &small).await {
                    return;
                }
                observed_server.fetch_add(CHUNK_SMALL as u64, Ordering::SeqCst);
            }
            // Reached only on the no-abort path; the client always aborts here.
            let _trail = stream.write_all(b"0\r\n\r\n").await;
        })
        .await;

        let url = format!("http://{addr}/jwks");
        let start = std::time::Instant::now();
        let response = reqwest::get(url).await.expect("GET succeeds");
        assert_eq!(
            response.content_length(),
            None,
            "chunked responses advertise no Content-Length — the pre-read check is bypassed"
        );
        let err = read_jwks_body(response)
            .await
            .expect_err("an oversized chunked body must be rejected during streaming");
        assert_invalid_client(&err, "JWKS response exceeds maximum size (256KB)");
        let elapsed = start.elapsed();

        // The server keeps a stable count after the abort (its next chunked
        // write fails). Either way it is far below the full payload — proof the
        // body was not buffered before rejection.
        let bytes_pulled = observed.load(Ordering::SeqCst);
        assert!(
            bytes_pulled < TOTAL_WILLING,
            "server recorded {bytes_pulled} bytes pulled; the streaming cap must abort before the full {TOTAL_WILLING}-byte body is read"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(2500),
            "streaming reject took {elapsed:?}; a buffering reader would wait ~4s for the full slow body"
        );
    }

    /// The cap is `> MAX_JWKS_RESPONSE_SIZE` (strictly greater): a body of
    /// exactly 256 KB is accepted and one byte more is rejected. Pins the
    /// boundary over chunked transfer encoding, where the pre-read
    /// `Content-Length` check does not apply so the streaming check alone
    /// decides.
    #[tokio::test]
    async fn read_jwks_body_accepts_body_at_the_cap_and_rejects_one_byte_more() {
        const AT_CAP: usize = MAX_JWKS_RESPONSE_SIZE;
        const OVER_CAP: usize = MAX_JWKS_RESPONSE_SIZE + 1;

        let payload = vec![b'a'; AT_CAP];
        let addr = spawn_raw_http_server(move |mut stream| async move {
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            if !write_chunk(&mut stream, &payload).await {
                return;
            }
            let _trail = stream.write_all(b"0\r\n\r\n").await;
            graceful_close(&mut stream).await;
        })
        .await;
        let url = format!("http://{addr}/jwks");
        let response = reqwest::get(url).await.expect("GET succeeds");
        let body = read_jwks_body(response)
            .await
            .expect("a chunked body of exactly 256 KB is at the cap and is accepted");
        assert_eq!(body.len(), AT_CAP);

        let payload = vec![b'a'; OVER_CAP];
        let addr = spawn_raw_http_server(move |mut stream| async move {
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            if !write_chunk(&mut stream, &payload).await {
                return;
            }
            let _trail = stream.write_all(b"0\r\n\r\n").await;
            graceful_close(&mut stream).await;
        })
        .await;
        let url = format!("http://{addr}/jwks");
        let response = reqwest::get(url).await.expect("GET succeeds");
        let err = read_jwks_body(response)
            .await
            .expect_err("a chunked body of 256 KB + 1 must be rejected");
        assert_invalid_client(&err, "JWKS response exceeds maximum size (256KB)");
    }

    /// A reqwest client that performs a real TLS handshake but does not verify
    /// the server certificate. The throwaway self-signed cert has no IP SAN, the
    /// URL uses the `127.0.0.1` literal, and the size cap under test runs after
    /// TLS termination — so cert verification is irrelevant to the guarantee
    /// being pinned here. Kept off the shared `AppState::http_client` to avoid
    /// weakening any other test's trust store.
    fn https_client_trusting_any_cert() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build test https client")
    }

    /// Serve one HTTPS response with `body` as JSON on a loopback port, and
    /// return the port.
    async fn serve_json_over_tls(body: &'static str) -> u16 {
        let acceptor = test_utils::test_tls_acceptor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local_addr").port();
        let _join = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept connection");
            let mut tls = acceptor.accept(stream).await.expect("TLS handshake");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            if tls.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let _body = tls.write_all(body.as_bytes()).await;
            let _flush = tls.shutdown().await;
        });
        port
    }

    // RFC 7517 §5: "The JSON object MUST have a \"keys\" member, with its
    // value being an array of JWKs." A 200 answer that is JSON but not a JWK
    // Set fails the fetch and leaves the last good cache row for the
    // stale-cache fallback, instead of replacing it for a full TTL.
    #[tokio::test]
    async fn fetch_and_cache_keeps_the_cached_set_when_the_body_is_not_a_jwk_set() {
        let state = test_utils::test_app_state().await;
        let good = serde_json::json!({ "keys": [{ "kty": "EC", "kid": "good" }] });
        db::upsert_jwks_cache(&state.store, "client-poison", &good)
            .await
            .expect("seed cache");

        let port = serve_json_over_tls("{}").await;
        let url = format!("https://127.0.0.1:{port}/jwks");
        let err = fetch_and_cache(
            &state.store,
            "client-poison",
            &url,
            true,
            &https_client_trusting_any_cert(),
        )
        .await
        .expect_err("a JSON body without \"keys\" is not a JWK Set");
        assert_invalid_client(&err, "Invalid JWKS format");

        let cached = db::get_jwks_cache(&state.store, "client-poison")
            .await
            .expect("read cache")
            .expect("cache row kept");
        assert_eq!(cached.value, good, "the last good set stays cached");
    }

    /// Control: a valid JWK Set replaces the cached one.
    #[tokio::test]
    async fn fetch_and_cache_stores_a_valid_jwk_set() {
        let state = test_utils::test_app_state().await;
        let old = serde_json::json!({ "keys": [{ "kty": "EC", "kid": "old" }] });
        db::upsert_jwks_cache(&state.store, "client-refresh", &old)
            .await
            .expect("seed cache");

        let port = serve_json_over_tls(r#"{"keys":[{"kty":"EC","kid":"new"}]}"#).await;
        let url = format!("https://127.0.0.1:{port}/jwks");
        let value = fetch_and_cache(
            &state.store,
            "client-refresh",
            &url,
            true,
            &https_client_trusting_any_cert(),
        )
        .await
        .expect("a valid JWK Set is fetched");

        let cached = db::get_jwks_cache(&state.store, "client-refresh")
            .await
            .expect("read cache")
            .expect("cache row");
        assert_eq!(cached.value, value);
        assert_eq!(
            cached.value,
            serde_json::json!({ "keys": [{ "kty": "EC", "kid": "new" }] })
        );
    }

    /// End-to-end over real TLS (2d, case a): a chunked JWKS body with no
    /// `Content-Length` streamed past the cap over a `tokio_rustls` connection.
    /// Goes through the full `fetch_jwks` pipeline — HTTPS-only check, SSRF
    /// egress guard (loopback permitted via `allow_loopback`), 2xx status
    /// check, then `read_jwks_body` — and asserts the streaming cap rejects
    /// mid-stream after TLS termination, with memory bounded as on plaintext.
    #[tokio::test]
    async fn fetch_jwks_over_tls_rejects_oversized_chunked() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        const CHUNK_BIG: usize = 128 * 1024;
        const CHUNK_SMALL: usize = 32 * 1024;
        const SLOW_CHUNKS: u32 = 40;
        const TOTAL_WILLING: u64 = CHUNK_BIG as u64 + SLOW_CHUNKS as u64 * CHUNK_SMALL as u64;

        let acceptor = test_utils::test_tls_acceptor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local_addr").port();

        let observed = Arc::new(AtomicU64::new(0));
        let observed_server = observed.clone();
        let _join = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept connection");
            let mut tls = acceptor.accept(stream).await.expect("TLS handshake");
            if tls
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let big = vec![b'.'; CHUNK_BIG];
            if !write_chunk(&mut tls, &big).await {
                return;
            }
            observed_server.fetch_add(CHUNK_BIG as u64, Ordering::SeqCst);
            let small = vec![b'.'; CHUNK_SMALL];
            for _ in 0..SLOW_CHUNKS {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !write_chunk(&mut tls, &small).await {
                    return;
                }
                observed_server.fetch_add(CHUNK_SMALL as u64, Ordering::SeqCst);
            }
            let _trail = tls.write_all(b"0\r\n\r\n").await;
        });

        let client = https_client_trusting_any_cert();
        let url = format!("https://127.0.0.1:{port}/jwks");
        let start = std::time::Instant::now();
        let err = fetch_jwks(&url, true, &client)
            .await
            .expect_err("an oversized chunked JWKS over TLS must be rejected");
        assert_invalid_client(&err, "JWKS response exceeds maximum size (256KB)");
        let elapsed = start.elapsed();

        let bytes_pulled = observed.load(Ordering::SeqCst);
        assert!(
            bytes_pulled < TOTAL_WILLING,
            "TLS server recorded {bytes_pulled} bytes pulled; the cap must abort before the full {TOTAL_WILLING}-byte body is read"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(2500),
            "streaming reject over TLS took {elapsed:?}; a buffering reader would wait ~4s"
        );
    }
}
