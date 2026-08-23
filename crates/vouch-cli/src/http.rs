// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client abstraction for server communication.
//!
//! This module provides a trait-based abstraction over HTTP operations,
//! enabling integration testing by injecting an axum router directly
//! instead of making real network requests.

use crate::{tr, tr_args};
use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use vouch_common::{ApiError, protocol};

/// Total timeout for interactive CLI operations.
const INTERACTIVE_TOTAL: Duration = Duration::from_secs(30);
/// Connection timeout for interactive CLI operations.
const INTERACTIVE_CONNECT: Duration = Duration::from_secs(10);

/// HTTP response from the client.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// WWW-Authenticate header value (if present on 401 responses).
    /// Used for RFC 9470 step-up authentication challenge detection.
    pub www_authenticate: Option<String>,
    /// DPoP-Nonce header value (if present).
    /// Returned by the server to bind the next DPoP proof to a server-issued nonce
    /// (RFC 9449 Section 8).
    pub dpop_nonce: Option<String>,
    /// Signature-Nonce header value (if present).
    /// Server-issued nonce for RFC 9421 HTTP signature replay protection.
    pub sig_nonce: Option<String>,
    /// Retry-After header value in seconds (if present on 429 responses).
    pub retry_after: Option<u64>,
}

impl HttpResponse {
    /// Create a new HTTP response.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            www_authenticate: None,
            dpop_nonce: None,
            sig_nonce: None,
            retry_after: None,
        }
    }

    /// Check if the response indicates success (2xx status).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Parse the response body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).context(tr!("err-failed-parse-json-response"))
    }

    /// Get the body as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid UTF-8.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone()).context(tr!("err-response-body-is-not-valid-utf-8"))
    }
}

/// Skew threshold in seconds — well below the server's 300s max_age (RFC 9421).
pub const CLOCK_SKEW_THRESHOLD_SECS: u64 = 60;

/// Parse the response `Date` header and return the skew in seconds.
///
/// Returns `None` if the header is missing or unparseable. The returned
/// value is the magnitude of the skew (always non-negative); direction is
/// in the second tuple element (`true` if local is behind server).
#[must_use]
pub fn compute_clock_skew(headers: &reqwest::header::HeaderMap) -> Option<(u64, bool)> {
    let date_str = headers.get("date").and_then(|v| v.to_str().ok())?;
    let server_zoned = jiff::fmt::rfc2822::parse(date_str).ok()?;
    let server_secs = server_zoned.timestamp().as_second();
    let local_secs = jiff::Timestamp::now().as_second();
    let skew = server_secs.saturating_sub(local_secs).unsigned_abs();
    let local_behind = local_secs < server_secs;
    Some((skew, local_behind))
}

/// Check the response `Date` header against the local clock and warn the
/// user once per process if the skew exceeds the threshold.
///
/// Clock skew is silent until it crosses the server's signature
/// `max_age` (300s default per RFC 9421), at which point all signed
/// requests fail with an opaque "signature verification failed" 401.
/// Warning at 60s gives the user a clear reason to fix it before that.
fn check_clock_skew(headers: &reqwest::header::HeaderMap) {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if WARNED.get().is_some() {
        return;
    }

    let Some((skew_secs, local_behind)) = compute_clock_skew(headers) else {
        return;
    };

    if skew_secs >= CLOCK_SKEW_THRESHOLD_SECS {
        WARNED.get_or_init(|| {
            crate::tr_eprintln!(
                "http-warn-clock-skew",
                secs = skew_secs,
                local_behind = local_behind.to_string(),
            );
            // Tracing keeps an English direction for operators / logs.
            let direction = if local_behind { "behind" } else { "ahead of" };
            tracing::warn!(
                skew_seconds = skew_secs,
                direction,
                "Clock skew exceeds threshold; signed requests may fail"
            );
        });
    }
}

/// Extract common response headers from a `HeaderMap`.
///
/// Returns `(www_authenticate, dpop_nonce, retry_after)` extracted from
/// the headers based on the HTTP status code. Shared by both the
/// production `ReqwestClient` and the test `TestHttpClient`.
fn extract_response_headers(
    status: u16,
    headers: &reqwest::header::HeaderMap,
) -> (Option<String>, Option<String>, Option<String>, Option<u64>) {
    let www_authenticate = if status == 401 {
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    } else {
        None
    };

    let dpop_nonce = headers
        .get(protocol::HEADER_DPOP_NONCE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let sig_nonce = headers
        .get("signature-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let retry_after = if status == 429 {
        headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    } else {
        None
    };

    (www_authenticate, dpop_nonce, sig_nonce, retry_after)
}

/// Trait for abstracting HTTP client operations.
///
/// This trait enables testing HTTP flows without making real network requests
/// by allowing injection of a test implementation that calls an axum router directly.
pub trait HttpClient: Send + Sync {
    /// Make an HTTP request.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `url` - Full URL to request
    /// * `body` - Optional request body bytes
    /// * `content_type` - Optional Content-Type header
    /// * `auth_header` - Optional Authorization header value
    /// * `extra_headers` - Optional additional headers as `(name, value)` pairs
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        auth_header: Option<&str>,
        extra_headers: Option<&[(&str, &str)]>,
    ) -> impl std::future::Future<Output = Result<HttpResponse>> + Send;
}

/// Production HTTP client using reqwest.
#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
}

impl ReqwestClient {
    /// Create a new reqwest-based HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn new() -> Result<Self> {
        let user_agent = format!("vouch-cli/{}", env!("CARGO_PKG_VERSION"));

        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Ok(v) = reqwest::header::HeaderValue::from_str(env!("CARGO_PKG_VERSION")) {
            default_headers.insert("Vouch-Client-Version", v);
        }
        default_headers.insert(
            "Vouch-Client-OS",
            reqwest::header::HeaderValue::from_static(std::env::consts::OS),
        );
        default_headers.insert(
            "Vouch-Client-Arch",
            reqwest::header::HeaderValue::from_static(std::env::consts::ARCH),
        );
        if let Ok(hostname) = gethostname::gethostname().into_string()
            && let Ok(v) = reqwest::header::HeaderValue::from_str(&hostname)
        {
            default_headers.insert("Vouch-Client-Hostname", v);
        }

        let builder = reqwest::Client::builder()
            .user_agent(&user_agent)
            .default_headers(default_headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(INTERACTIVE_TOTAL)
            .connect_timeout(INTERACTIVE_CONNECT);

        let client = vouch_common::http::with_process_doh(builder)
            .build()
            .context(tr!("err-failed-create-http-client"))?;

        Ok(Self { client })
    }

    /// Get a reference to the underlying reqwest client.
    ///
    /// Used by code that needs the raw client for non-standard requests
    /// (e.g., AWS SigV4 signing).
    pub fn inner(&self) -> &reqwest::Client {
        &self.client
    }
}

impl HttpClient for ReqwestClient {
    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        auth_header: Option<&str>,
        extra_headers: Option<&[(&str, &str)]>,
    ) -> Result<HttpResponse> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .context(tr!("err-invalid-http-method"))?;
        let method_str = method.to_string();

        let mut builder = self.client.request(method, url);

        if let Some(ct) = content_type {
            builder = builder.header("Content-Type", ct);
        }

        if let Some(auth) = auth_header {
            builder = builder.header("Authorization", auth);
        }

        if let Some(headers) = extra_headers {
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
        }

        if let Some(b) = body {
            builder = builder.body(b.to_vec());
        }

        // Trace-level request logging (headers redacted for sensitive values)
        if tracing::enabled!(tracing::Level::TRACE) {
            let redacted = redact_request_headers(auth_header, content_type, extra_headers);
            tracing::trace!(
                http.method = %method_str,
                http.url = %url,
                headers = ?redacted,
                "HTTP request"
            );
        }

        let response = builder
            .send()
            .await
            .context(tr!("err-http-request-failed"))?;

        let status = response.status().as_u16();
        let (www_authenticate, dpop_nonce, sig_nonce, retry_after) =
            extract_response_headers(status, response.headers());
        check_clock_skew(response.headers());

        // Trace-level response logging
        if tracing::enabled!(tracing::Level::TRACE) {
            let redacted = redact_response_headers(response.headers());
            tracing::trace!(
                status = %status,
                headers = ?redacted,
                "HTTP response"
            );
        }

        let body = response
            .bytes()
            .await
            .context(tr!("err-failed-read-response-body"))?;

        Ok(HttpResponse {
            status,
            body: body.to_vec(),
            www_authenticate,
            dpop_nonce,
            sig_nonce,
            retry_after,
        })
    }
}

/// Helper trait for common HTTP operations with JSON.
pub trait HttpClientExt: HttpClient {
    /// POST JSON and receive JSON response.
    fn post_json<Req, Resp>(
        &self,
        url: &str,
        body: &Req,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        async move {
            let json = serde_json::to_vec(body).context(tr!("err-failed-serialize-request"))?;
            let response = self
                .request(
                    "POST",
                    url,
                    Some(&json),
                    Some("application/json"),
                    None,
                    None,
                )
                .await?;
            handle_response(response)
        }
    }

    /// POST JSON with authentication and receive JSON response.
    fn post_json_authenticated<Req, Resp>(
        &self,
        url: &str,
        body: &Req,
        token: &SecretString,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        let auth = format!("{} {}", protocol::AUTH_SCHEME_BEARER, token.expose_secret());
        async move {
            let json = serde_json::to_vec(body).context(tr!("err-failed-serialize-request"))?;
            let response = self
                .request(
                    "POST",
                    url,
                    Some(&json),
                    Some("application/json"),
                    Some(&auth),
                    None,
                )
                .await?;
            handle_response(response)
        }
    }

    /// POST form data and receive JSON response.
    fn post_form<Req, Resp>(
        &self,
        url: &str,
        body: &Req,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        async move {
            let form =
                serde_urlencoded::to_string(body).context(tr!("err-failed-serialize-form-data"))?;
            let response = self
                .request(
                    "POST",
                    url,
                    Some(form.as_bytes()),
                    Some(protocol::CONTENT_TYPE_FORM_URLENCODED),
                    None,
                    None,
                )
                .await?;
            handle_response(response)
        }
    }
}

// Implement HttpClientExt for all HttpClient implementations
impl<T: HttpClient> HttpClientExt for T {}

/// Convert an HTTP error status and body into an actionable error message.
///
/// Shared logic used by both `VouchClient` (reqwest-based) and the
/// trait-based `HttpClient` to ensure consistent error messages.
pub fn format_http_error(status: u16, error_text: &str) -> anyhow::Error {
    // Try to parse as API error for a clean message
    if let Ok(api_error) = serde_json::from_str::<ApiError>(error_text) {
        return anyhow::anyhow!("{}", api_error.message);
    }
    // Non-JSON error body — provide actionable guidance
    match status {
        401 => anyhow::anyhow!(tr!("err-not-authenticated-run-vouch-login-first")),
        403 => anyhow::anyhow!(tr!("err-permission-denied-by-server")),
        404 => anyhow::anyhow!(tr!("err-server-endpoint-not-found-status-404-check-your")),
        429 => anyhow::anyhow!(tr!("err-rate-limited")),
        500..=599 => {
            anyhow::anyhow!(tr_args!(
                "err-server-error-run-vouch-doctor-check-connectivity",
                status = status.to_string()
            ))
        }
        _ => anyhow::anyhow!(tr_args!(
            "err-unexpected-server-response",
            status = status.to_string()
        )),
    }
}

/// Handle HTTP response, parsing JSON or error.
fn handle_response<Resp: DeserializeOwned>(response: HttpResponse) -> Result<Resp> {
    if response.is_success() {
        response.json()
    } else {
        let error_text = response.text().unwrap_or_default();
        Err(format_http_error(response.status, &error_text))
    }
}

/// RFC 9470: Parsed step-up authentication challenge from a `WWW-Authenticate` header.
#[derive(Debug, Clone)]
pub struct StepUpChallenge {
    /// Requested authentication context class references.
    pub acr_values: Option<String>,
    /// Maximum authentication age in seconds.
    pub max_age: Option<u64>,
}

/// Parse a `WWW-Authenticate` header value for an RFC 9470 step-up challenge.
///
/// Returns `Some(challenge)` if the header contains
/// `error="insufficient_user_authentication"`, extracting any `acr_values`
/// and `max_age` parameters.
///
/// Returns `None` for non-step-up Bearer challenges (e.g., `error="invalid_token"`).
pub fn parse_www_authenticate(header: &str) -> Option<StepUpChallenge> {
    // Must be a Bearer challenge
    if header
        .strip_prefix(protocol::AUTH_SCHEME_BEARER)
        .is_none_or(|rest| !rest.starts_with(' '))
    {
        return None;
    }

    // Check for the step-up error code
    if !header.contains("insufficient_user_authentication") {
        return None;
    }

    // Extract quoted parameter values with boundary checking to avoid
    // matching parameter names that appear as substrings of other values.
    let extract_param = |name: &str| -> Option<String> {
        let prefix = format!("{name}=\"");
        let mut search_from = 0;
        loop {
            let start = header
                .get(search_from..)?
                .find(&prefix)?
                .saturating_add(search_from);
            // Verify boundary: the character before the match must be a delimiter
            // (comma, space) or the start of the string.
            if start > 0 {
                let prev = header.as_bytes().get(start.wrapping_sub(1)).copied()?;
                if prev != b',' && prev != b' ' {
                    // Not a real parameter boundary — keep searching
                    search_from = start.saturating_add(1);
                    continue;
                }
            }
            let value_start = start.saturating_add(prefix.len());
            let rest = header.get(value_start..)?;
            let end = rest.find('"')?;
            return rest.get(..end).map(String::from);
        }
    };

    let acr_values = extract_param("acr_values");
    let max_age = extract_param("max_age").and_then(|v| v.parse().ok());

    Some(StepUpChallenge {
        acr_values,
        max_age,
    })
}

/// Build a redacted view of request headers for trace logging.
///
/// Redacts `Authorization` values (shows scheme only), shows signature-related
/// headers in full (`Signature`, `Signature-Input`, `Content-Digest`, `DPoP`).
fn redact_request_headers(
    auth_header: Option<&str>,
    content_type: Option<&str>,
    extra_headers: Option<&[(&str, &str)]>,
) -> Vec<(&'static str, String)> {
    let mut headers = Vec::new();

    if let Some(auth) = auth_header {
        let scheme = auth.split_once(' ').map_or(auth, |(s, _)| s);
        headers.push(("authorization", format!("{scheme} ***")));
    }
    if let Some(ct) = content_type {
        headers.push(("content-type", ct.to_string()));
    }
    if let Some(extras) = extra_headers {
        for (name, value) in extras {
            headers.push((
                // Safety: these header names are all static strings from client.rs
                // The leak is bounded by a small fixed set of header names.
                // This avoids lifetime complexity for trace-only logging.
                string_to_static(name),
                value.to_string(),
            ));
        }
    }

    headers
}

/// Leak a string reference for trace logging header names.
///
/// Only used in the trace logging path (guarded by `tracing::enabled!(TRACE)`).
/// The set of header names is small and fixed (DPoP, Signature, etc.), so the
/// leaked memory is bounded.
fn string_to_static(s: &str) -> &'static str {
    // For known header names, return static strings to avoid leaking
    match s {
        protocol::HEADER_DPOP => protocol::HEADER_DPOP,
        "Signature" => "signature",
        "Signature-Input" => "signature-input",
        "Content-Digest" => "content-digest",
        _ => "other",
    }
}

/// Build a redacted view of response headers for trace logging.
fn redact_response_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (name, value) in headers {
        let name_str = name.as_str();
        let value_str = match name_str {
            "set-cookie" => "***".to_string(),
            _ => value.to_str().unwrap_or("<non-utf8>").to_string(),
        };
        result.push((name_str.to_string(), value_str));
    }
    result
}

#[cfg(feature = "test-utils")]
pub use test_utils::*;

#[cfg(feature = "test-utils")]
mod test_utils {
    use super::*;
    use std::sync::Arc;

    /// Test HTTP client that calls an axum router directly.
    ///
    /// This allows testing the full HTTP request/response flow
    /// without making real network requests.
    #[derive(Clone)]
    pub struct TestHttpClient {
        router: Arc<axum::Router>,
    }

    impl TestHttpClient {
        /// Create a new test HTTP client wrapping an axum router.
        #[must_use]
        pub fn new(router: axum::Router) -> Self {
            Self {
                router: Arc::new(router),
            }
        }
    }

    impl std::fmt::Debug for TestHttpClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestHttpClient").finish_non_exhaustive()
        }
    }

    impl HttpClient for TestHttpClient {
        async fn request(
            &self,
            method: &str,
            url: &str,
            body: Option<&[u8]>,
            content_type: Option<&str>,
            auth_header: Option<&str>,
            extra_headers: Option<&[(&str, &str)]>,
        ) -> Result<HttpResponse> {
            use axum::body::Body;

            // Keep the absolute URI so middleware can derive @scheme/@authority in tests.
            let parsed = url::Url::parse(url).context(tr!("err-invalid-url"))?;
            let uri: http::Uri = parsed
                .as_str()
                .parse()
                .context(tr!("err-invalid-uri-in-test-client-request"))?;

            // Build request
            let method = http::Method::from_bytes(method.as_bytes())
                .context(tr!("err-invalid-http-method"))?;

            let mut builder = http::Request::builder().method(method).uri(uri);

            if let Some(ct) = content_type {
                builder = builder.header("Content-Type", ct);
            }

            if let Some(auth) = auth_header {
                builder = builder.header("Authorization", auth);
            }

            if let Some(headers) = extra_headers {
                for (name, value) in headers {
                    builder = builder.header(*name, *value);
                }
            }

            let body = match body {
                Some(b) => Body::from(b.to_vec()),
                None => Body::empty(),
            };

            let request = builder
                .body(body)
                .context(tr!("err-failed-build-request"))?;
            let (mut parts, body) = request.into_parts();
            parts
                .extensions
                .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    0,
                ))));
            let request = http::Request::from_parts(parts, body);

            // Call the router - clone the inner Router for oneshot
            let router: axum::Router = (*self.router).clone();
            let response = tower::ServiceExt::oneshot(router, request)
                .await
                .context(tr!("err-router-error"))?;

            let status = response.status().as_u16();
            let (www_authenticate, dpop_nonce, sig_nonce, retry_after) =
                extract_response_headers(status, response.headers());

            let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .context(tr!("err-failed-read-response-body"))?;

            Ok(HttpResponse {
                status,
                body: body_bytes.to_vec(),
                www_authenticate,
                dpop_nonce,
                sig_nonce,
                retry_after,
            })
        }
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
    fn test_http_response_success() {
        let response = HttpResponse::new(200, b"{}".to_vec());
        assert!(response.is_success());
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_http_response_error() {
        let response = HttpResponse::new(404, b"not found".to_vec());
        assert!(!response.is_success());
    }

    #[test]
    fn test_http_response_json() {
        let response = HttpResponse::new(200, b"{\"key\": \"value\"}".to_vec());
        let parsed: serde_json::Value = response.json().unwrap();
        assert_eq!(parsed.get("key").and_then(|v| v.as_str()), Some("value"));
    }

    #[test]
    fn test_http_response_text() {
        let response = HttpResponse::new(200, b"hello world".to_vec());
        assert_eq!(response.text().ok(), Some("hello world".to_string()));
    }

    #[test]
    fn test_http_response_boundary_status_codes() {
        assert!(HttpResponse::new(200, vec![]).is_success());
        assert!(HttpResponse::new(201, vec![]).is_success());
        assert!(HttpResponse::new(204, vec![]).is_success());
        assert!(HttpResponse::new(299, vec![]).is_success());
        assert!(!HttpResponse::new(199, vec![]).is_success());
        assert!(!HttpResponse::new(300, vec![]).is_success());
        assert!(!HttpResponse::new(400, vec![]).is_success());
        assert!(!HttpResponse::new(500, vec![]).is_success());
    }

    #[test]
    fn test_http_response_invalid_utf8() {
        let response = HttpResponse::new(200, vec![0xFF, 0xFE]);
        assert!(response.text().is_err());
    }

    #[test]
    fn test_http_response_json_invalid() {
        let response = HttpResponse::new(200, b"not json".to_vec());
        let result: Result<serde_json::Value> = response.json();
        assert!(result.is_err());
    }

    #[test]
    fn test_http_response_dpop_nonce_default_none() {
        let response = HttpResponse::new(200, b"{}".to_vec());
        assert!(response.dpop_nonce.is_none());
    }

    #[test]
    fn test_http_response_401_dpop_nonce_none() {
        let response = HttpResponse {
            status: 401,
            body: b"{}".to_vec(),
            www_authenticate: None,
            dpop_nonce: None,
            sig_nonce: None,
            retry_after: None,
        };
        assert!(response.dpop_nonce.is_none());
    }

    #[test]
    fn test_format_http_error_401() {
        let err = format_http_error(401, "");
        assert!(err.to_string().contains("not authenticated"));
    }

    #[test]
    fn test_format_http_error_403() {
        let err = format_http_error(403, "");
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn test_format_http_error_404() {
        let err = format_http_error(404, "");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_format_http_error_500() {
        let err = format_http_error(500, "");
        assert!(err.to_string().contains("server error"));
    }

    #[test]
    fn test_format_http_error_502() {
        let err = format_http_error(502, "");
        assert!(err.to_string().contains("server error"));
    }

    #[test]
    fn test_format_http_error_unknown_status() {
        let err = format_http_error(418, "");
        assert!(err.to_string().contains("unexpected server response"));
    }

    #[test]
    fn test_format_http_error_with_api_error_json() {
        let body = r#"{"code":"bad_request","message":"Invalid role ARN format"}"#;
        let err = format_http_error(400, body);
        assert_eq!(err.to_string(), "Invalid role ARN format");
    }

    #[test]
    fn test_format_http_error_with_malformed_json() {
        let body = r#"{"not_an_api_error": true}"#;
        // Should fall through to status-based message since it can't parse as ApiError
        let err = format_http_error(400, body);
        assert!(err.to_string().contains("unexpected server response"));
    }

    #[test]
    fn test_handle_response_success() {
        let response = HttpResponse::new(200, br#"{"key":"value"}"#.to_vec());
        let result: Result<serde_json::Value> = handle_response(response);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val.get("key").and_then(|v| v.as_str()), Some("value"));
    }

    #[test]
    fn test_handle_response_success_invalid_json() {
        let response = HttpResponse::new(200, b"not json".to_vec());
        let result: Result<serde_json::Value> = handle_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_response_error_status() {
        let response = HttpResponse::new(401, b"{}".to_vec());
        let result: Result<serde_json::Value> = handle_response(response);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("not authenticated")
        );
    }

    // =========================================================================
    // RFC 9470 WWW-Authenticate Header Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_www_authenticate_step_up_with_all_params() {
        let header = "Bearer error=\"insufficient_user_authentication\", \
                      error_description=\"A recent authentication is required\", \
                      acr_values=\"urn:nist:authentication:assurance-level:aal3\", \
                      max_age=\"300\"";
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(
            challenge.acr_values.as_deref(),
            Some("urn:nist:authentication:assurance-level:aal3")
        );
        assert_eq!(challenge.max_age, Some(300));
    }

    #[test]
    fn test_parse_www_authenticate_step_up_max_age_only() {
        let header = "Bearer error=\"insufficient_user_authentication\", max_age=\"60\"";
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(challenge.acr_values, None);
        assert_eq!(challenge.max_age, Some(60));
    }

    #[test]
    fn test_parse_www_authenticate_step_up_no_params() {
        let header = "Bearer error=\"insufficient_user_authentication\"";
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(challenge.acr_values, None);
        assert_eq!(challenge.max_age, None);
    }

    #[test]
    fn test_parse_www_authenticate_non_step_up_error() {
        let header = "Bearer error=\"invalid_token\"";
        assert!(parse_www_authenticate(header).is_none());
    }

    #[test]
    fn test_parse_www_authenticate_not_bearer() {
        let header = "Basic realm=\"example\"";
        assert!(parse_www_authenticate(header).is_none());
    }

    #[test]
    fn test_parse_www_authenticate_empty() {
        assert!(parse_www_authenticate("").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_param_substring_no_false_match() {
        // "xacr_values" should NOT match when extracting "acr_values"
        let header = "Bearer error=\"insufficient_user_authentication\", \
                      xacr_values=\"fake\", acr_values=\"real_acr\", max_age=\"120\"";
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(challenge.acr_values.as_deref(), Some("real_acr"));
        assert_eq!(challenge.max_age, Some(120));
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_test_http_client_with_router() {
        use axum::{Json, Router, routing::get};

        #[derive(serde::Deserialize, serde::Serialize)]
        struct TestResponse {
            message: String,
        }

        async fn handler() -> Json<TestResponse> {
            Json(TestResponse {
                message: "hello".to_string(),
            })
        }

        let router = Router::new().route("/test", get(handler));
        let client = TestHttpClient::new(router);

        let resp = client
            .request("GET", "http://test.local/test", None, None, None, None)
            .await
            .unwrap();

        assert_eq!(resp.status, 200);

        let parsed: TestResponse = resp.json().unwrap();
        assert_eq!(parsed.message, "hello");
    }
}
