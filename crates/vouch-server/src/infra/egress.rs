// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded reads of outbound HTTP response bodies.
//!
//! Every response this server reads from a remote host is attacker-influenced
//! to some degree — a client-registered `jwks_uri`, a `request_uri` supplied on
//! the authorization endpoint, an upstream IdP's discovery document and the
//! `jwks_uri` that document names, or an API host that could be impersonated by
//! whoever controls the network path. None of them may be allowed to decide how
//! much memory this process allocates.
//!
//! `reqwest`'s own body accessors cannot provide that: `Response::bytes`,
//! `Response::text`, and `Response::json` all collect the *entire* body into
//! memory before returning, so a size check written after one of them has
//! already lost. A `Content-Length` check written before one of them is not
//! enough either, because `content_length()` is `None` for a
//! `Transfer-Encoding: chunked` response and the check simply does not run —
//! which is how a hostile `jwks_uri` could stream until the fetch timeout and
//! exhaust memory (issue #1105).
//!
//! So the readers here are the only sanctioned way to consume a response body:
//! they poll [`reqwest::Response::chunk`] and abort the moment the running
//! length crosses the caller's cap, bounding memory to that cap plus one frame
//! regardless of transfer encoding or attacker bandwidth. The cap itself stays
//! with the caller, since a 64 KB request object and a 1 MB SAML metadata
//! document are both legitimate.
//!
//! `tests/egress_body_caps.rs` enforces that this module is the only place in
//! `src/` that awaits a `reqwest` body accessor.

/// Cap for a non-2xx response body that is read only to be logged.
///
/// Diagnostic bodies are truncated for the log line anyway, so this needs to be
/// no larger than a useful excerpt — and an error path is exactly where a
/// hostile host would put a body it wants buffered.
pub(crate) const ERROR_BODY_LIMIT: usize = 64 * 1024;

/// Why reading a capped response body failed.
///
/// Deliberately not an OAuth or `anyhow` error: this module sits below both
/// `services` and the crate's error type, and its callers report failures in
/// their own vocabulary — an `invalid_client` OAuth code on the token endpoint,
/// an `anyhow` context string at startup.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyError {
    /// The body reached the cap; the read was abandoned partway through.
    #[error("response exceeds the maximum size of {limit} bytes")]
    TooLarge {
        /// The cap that was exceeded, in bytes.
        limit: usize,
    },

    /// The connection failed while streaming the body.
    #[error("failed to read response body")]
    Transport {
        /// The underlying transport failure.
        #[source]
        source: reqwest::Error,
    },

    /// The body was read but is not UTF-8.
    #[error("response is not valid UTF-8")]
    NotUtf8,

    /// The body was read but is not the JSON shape the caller expected.
    #[error("failed to parse response as JSON")]
    Json {
        /// The underlying deserialization failure.
        #[source]
        source: serde_json::Error,
    },
}

/// Read a response body, rejecting it as soon as it exceeds `limit` bytes.
///
/// Two checks cooperate so memory stays bounded however the peer frames the
/// body: a `Content-Length` rejection that refuses a sized over-cap response
/// without any body I/O at all, and the incremental per-chunk check that
/// catches everything else, chunked responses included.
pub(crate) async fn read_capped_bytes(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyError> {
    // Sized responses: refuse before reading a single byte. `try_from` cannot
    // fail for a real cap, and treating a failure as "unknown length" is safe
    // because the streaming check below still applies.
    if let Ok(cap) = u64::try_from(limit)
        && response.content_length().is_some_and(|len| len > cap)
    {
        return Err(BodyError::TooLarge { limit });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| BodyError::Transport { source })?
    {
        // Check before extending, so a chunk that already busts the cap is
        // never copied in. `saturating_add` keeps this within the workspace's
        // ban on panicking arithmetic.
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(BodyError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Read a response body as UTF-8 text, capped at `limit` bytes.
pub(crate) async fn read_capped_text(
    response: reqwest::Response,
    limit: usize,
) -> Result<String, BodyError> {
    let body = read_capped_bytes(response, limit).await?;
    String::from_utf8(body).map_err(|_| BodyError::NotUtf8)
}

/// Read a response body as UTF-8 text for a log line, capped and lossy.
///
/// For diagnostic paths that previously used
/// `response.text().await.unwrap_or_default()`: the body is best-effort context
/// for an error that has already been decided, so a read failure yields an
/// empty string rather than displacing the real error. The cap still applies.
pub(crate) async fn read_error_body(response: reqwest::Response) -> String {
    read_capped_text(response, ERROR_BODY_LIMIT)
        .await
        .unwrap_or_default()
}

/// Read and deserialize a JSON response body, capped at `limit` bytes.
pub(crate) async fn read_capped_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T, BodyError> {
    let body = read_capped_bytes(response, limit).await?;
    serde_json::from_slice(&body).map_err(|source| BodyError::Json { source })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Serve `body` once over loopback HTTP/1.1 with an explicit
    /// `Content-Length`, and return the URL to fetch it from.
    ///
    /// The streaming cap itself — chunked framing, aborting mid-body, the
    /// exact-cap boundary — is pinned by the `infra::jwks` tests, which drive
    /// these same readers through `read_jwks_body`. What is exercised here is
    /// the decoding layered on top: JSON, UTF-8, and the lossy error-body read.
    async fn serve_once(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        let _join = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.expect("accept connection");
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if stream.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            let _written = stream.write_all(&body).await;
            let _flushed = stream.shutdown().await;
        });
        format!("http://{addr}/")
    }

    async fn get(body: Vec<u8>) -> reqwest::Response {
        let url = serve_once(body).await;
        reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("loopback request succeeds")
    }

    #[tokio::test]
    async fn read_capped_json_parses_within_the_cap() {
        let response = get(br#"{"kty":"EC","kid":"k1"}"#.to_vec()).await;
        let value: serde_json::Value = read_capped_json(response, 64 * 1024)
            .await
            .expect("a small JSON body parses");
        assert_eq!(value.get("kid").and_then(|v| v.as_str()), Some("k1"));
    }

    #[tokio::test]
    async fn read_capped_json_reports_a_parse_failure_distinctly() {
        let response = get(b"not json at all".to_vec()).await;
        let err = read_capped_json::<serde_json::Value>(response, 64 * 1024)
            .await
            .expect_err("a non-JSON body must not parse");
        assert!(
            matches!(err, BodyError::Json { .. }),
            "a malformed body is a parse failure, not a size or transport one: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_capped_json_rejects_an_oversized_body_before_parsing() {
        let oversized = format!(r#"{{"pad":"{}"}}"#, "A".repeat(4096)).into_bytes();
        let response = get(oversized).await;
        let err = read_capped_json::<serde_json::Value>(response, 1024)
            .await
            .expect_err("a body past the cap must be rejected");
        assert!(
            matches!(err, BodyError::TooLarge { limit: 1024 }),
            "the cap must fire ahead of the JSON parse: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_capped_text_rejects_non_utf8() {
        // A lone 0x80 continuation byte is not valid UTF-8 in any position.
        let response = get(vec![0x80, 0x81, 0x82]).await;
        let err = read_capped_text(response, 64 * 1024)
            .await
            .expect_err("non-UTF-8 must be rejected");
        assert!(
            matches!(err, BodyError::NotUtf8),
            "expected a UTF-8 rejection: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_error_body_returns_the_body_within_the_cap() {
        let response = get(b"upstream said no".to_vec()).await;
        assert_eq!(read_error_body(response).await, "upstream said no");
    }

    /// A diagnostic read must not displace the error it is annotating: past the
    /// cap it yields an empty string rather than surfacing its own failure.
    #[tokio::test]
    async fn read_error_body_yields_empty_past_the_cap() {
        let response = get(vec![b'x'; ERROR_BODY_LIMIT.saturating_add(1)]).await;
        assert!(read_error_body(response).await.is_empty());
    }
}
