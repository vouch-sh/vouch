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

/// Read a JWKS response body, rejecting it as soon as it exceeds
/// [`MAX_JWKS_RESPONSE_SIZE`].
///
/// Two checks cooperate so memory stays bounded no matter how the server
/// frames the body:
///
/// 1. A pre-read `Content-Length` rejection — a sized response advertising more
///    than the cap is refused without buffering a single byte of it.
/// 2. An incremental, chunk-by-chunk cap while streaming. `content_length()` is
///    `None` for `Transfer-Encoding: chunked` responses, so check #1 is skipped
///    for them, and reading via `response.bytes().await` would collect the
///    *entire* body into memory before a post-read size check could reject it —
///    a memory-exhaustion vector for a hostile `jwks_uri` (`chunked`, no
///    `Content-Length`, streaming until the fetch timeout). Polling
///    [`reqwest::Response::chunk`] and aborting the moment the running length
///    crosses the cap bounds memory to `MAX_JWKS_RESPONSE_SIZE` plus one frame,
///    whatever the transport or attacker bandwidth.
async fn read_capped_body(mut response: reqwest::Response) -> ServiceResult<String> {
    // Sized responses: refuse before any body I/O.
    if let Some(len) = response.content_length()
        && len > MAX_JWKS_RESPONSE_SIZE as u64
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response exceeds maximum size (256KB)",
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!("Failed to read JWKS response: {e}"),
        )
    })? {
        // Reject *before* extending so a chunk that already busts the cap is
        // never copied in; `saturating_add` keeps this panic-free arithmetic.
        if body.len().saturating_add(chunk.len()) > MAX_JWKS_RESPONSE_SIZE {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "JWKS response exceeds maximum size (256KB)",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response is not valid UTF-8",
        )
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

    // Enforce the response size cap while streaming the body via
    // [`read_capped_body`]. `response.bytes().await` would buffer the whole
    // response before a size check could reject it; for `Transfer-Encoding:
    // chunked` the `Content-Length` is `None`, so the incremental chunk check
    // inside the helper is what bounds memory — see
    // `test_chunked_oversize_aborts_during_streaming`.
    read_capped_body(response).await
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Throwaway self-signed P-256 cert (SAN: localhost) + PKCS#8 key, reused
    // from `crates/vouch-tests/tests/pq_tls.rs`. Valid until 2036. Used only to
    // stand up a loopback TLS listener for the end-to-end-over-TLS JWKS test;
    // cert verification is bypassed (`danger_accept_invalid_certs`) because
    // the cert has no IP SAN and the SSRF guard resolves domain names via
    // hickory (which does not read `/etc/hosts`), so the URL uses the `127.0.0.1`
    // IP literal to avoid a DNS lookup. The size-cap mechanism under test is
    // transport-agnostic (per the bug report) — what matters is that it runs
    // *after* TLS termination on a real `reqwest::Response` over a real TLS
    // connection, which this exercises.
    const TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBoDCCAUagAwIBAgIUPOBIDoD8Akv9FXfEjb8GEV6GYLowCgYIKoZIzj0EAwIw\n\
HDEaMBgGA1UEAwwRdm91Y2gtcHEtdGxzLXRlc3QwHhcNMjYwNzA5MTEzMDE1WhcN\n\
MzYwNzA2MTEzMDE1WjAcMRowGAYDVQQDDBF2b3VjaC1wcS10bHMtdGVzdDBZMBMG\n\
ByqGSM49AgEGCCqGSM49AwEHA0IABO7wN7GBAX4FydRe2AvENBb6WZ9XHh4NKbkO\n\
G9ulpEIAVoZaGHMAlK7ZGTLf/tBukQxhXDwQKLLot23POsF8nP+jZjBkMB0GA1Ud\n\
DgQWBBQ3svXuWL2wS8xcHilgxDuYURTVwDAfBgNVHSMEGDAWgBQ3svXuWL2wS8xc\n\
HilgxDuYURTVwDAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAK\n\
BggqhkjOPQQDAgNIADBFAiEAqVgc77k203H6G5gEaAcHuna5DKJmQPCQjQLQAtry\n\
KnMCICKcoY9vNlshsz2y7RVcfGqowba3/xXj3aYFegT/BdAW\n\
-----END CERTIFICATE-----\n";
    const TLS_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTljx1Qv2H2TQMKaX\n\
+palx1XsuLkORqDCzFBkRDcz3tihRANCAATu8DexgQF+BcnUXtgLxDQW+lmfVx4e\n\
DSm5DhvbpaRCAFaGWhhzAJSu2Rky3/7QbpEMYVw8ECiy6LdtzzrBfJz/\n\
-----END PRIVATE KEY-----\n";

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
    /// [`read_capped_body`] only sees the [`reqwest::Response`] after TLS
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
    async fn read_capped_body_accepts_small_chunked_response() {
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
        let body = read_capped_body(response)
            .await
            .expect("a small chunked body is under the cap and must be accepted");
        assert_eq!(body.as_bytes(), expected.as_slice());
    }

    /// A sized response advertising more than the cap via `Content-Length` is
    /// refused before any body bytes are pulled. The server deliberately
    /// withholds the body for 3s; a buffering reader would block on it, while
    /// the pre-read `Content-Length` check rejects in milliseconds.
    #[tokio::test]
    async fn read_capped_body_rejects_oversized_content_length_without_reading_body() {
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
        let err = read_capped_body(response)
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
        let err = read_capped_body(response)
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
    async fn read_capped_body_accepts_body_at_the_cap_and_rejects_one_byte_more() {
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
        let body = read_capped_body(response)
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
        let err = read_capped_body(response)
            .await
            .expect_err("a chunked body of 256 KB + 1 must be rejected");
        assert_invalid_client(&err, "JWKS response exceeds maximum size (256KB)");
    }

    /// A `tokio_rustls` acceptor using the throwaway self-signed cert above and
    /// an explicit aws-lc-rs provider (no reliance on a process-default
    /// provider being installed in tests).
    fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(TLS_CERT_PEM.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse test certificate");
        let key = PrivateKeyDer::from_pem_slice(TLS_KEY_PEM.as_bytes()).expect("parse test key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("configure TLS versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build server config");
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
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

    /// End-to-end over real TLS (2d, case a): a chunked JWKS body with no
    /// `Content-Length` streamed past the cap over a `tokio_rustls` connection.
    /// Goes through the full `fetch_jwks` pipeline — HTTPS-only check, SSRF
    /// egress guard (loopback permitted via `allow_loopback`), 2xx status
    /// check, then `read_capped_body` — and asserts the streaming cap rejects
    /// mid-stream after TLS termination, with memory bounded as on plaintext.
    #[tokio::test]
    async fn fetch_jwks_over_tls_rejects_oversized_chunked() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        const CHUNK_BIG: usize = 128 * 1024;
        const CHUNK_SMALL: usize = 32 * 1024;
        const SLOW_CHUNKS: u32 = 40;
        const TOTAL_WILLING: u64 = CHUNK_BIG as u64 + SLOW_CHUNKS as u64 * CHUNK_SMALL as u64;

        let acceptor = tls_acceptor();
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
