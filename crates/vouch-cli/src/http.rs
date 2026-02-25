// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client abstraction for server communication.
//!
//! This module provides a trait-based abstraction over HTTP operations,
//! enabling integration testing by injecting an axum router directly
//! instead of making real network requests.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use vouch_common::ApiError;

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
        }
    }

    /// Create a new HTTP response with a WWW-Authenticate header.
    #[must_use]
    pub fn with_www_authenticate(
        status: u16,
        body: Vec<u8>,
        www_authenticate: Option<String>,
    ) -> Self {
        Self {
            status,
            body,
            www_authenticate,
            dpop_nonce: None,
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
        serde_json::from_slice(&self.body).context("failed to parse JSON response")
    }

    /// Get the body as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid UTF-8.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone()).context("response body is not valid UTF-8")
    }
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
        let client = vouch_common::http::interactive_client(&format!(
            "vouch-cli/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .context("failed to create HTTP client")?;

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
        let method =
            reqwest::Method::from_bytes(method.as_bytes()).context("invalid HTTP method")?;

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

        let response = builder.send().await.context("HTTP request failed")?;

        let status = response.status().as_u16();

        // Extract WWW-Authenticate header for RFC 9470 step-up detection
        let www_authenticate = if status == 401 {
            response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        } else {
            None
        };

        // Extract DPoP-Nonce header for RFC 9449 nonce binding
        let dpop_nonce = response
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response
            .bytes()
            .await
            .context("failed to read response body")?;

        Ok(HttpResponse {
            status,
            body: body.to_vec(),
            www_authenticate,
            dpop_nonce,
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
            let json = serde_json::to_vec(body).context("failed to serialize request")?;
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
        let auth = format!("Bearer {}", token.expose_secret());
        async move {
            let json = serde_json::to_vec(body).context("failed to serialize request")?;
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

    /// GET with authentication and receive JSON response.
    fn get_json_authenticated<Resp>(
        &self,
        url: &str,
        token: &SecretString,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Resp: DeserializeOwned,
    {
        let auth = format!("Bearer {}", token.expose_secret());
        async move {
            let response = self
                .request("GET", url, None, None, Some(&auth), None)
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
                serde_urlencoded::to_string(body).context("failed to serialize form data")?;
            let response = self
                .request(
                    "POST",
                    url,
                    Some(form.as_bytes()),
                    Some("application/x-www-form-urlencoded"),
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
        401 => anyhow::anyhow!("not authenticated - run 'vouch login' first"),
        403 => anyhow::anyhow!("permission denied by server"),
        404 => anyhow::anyhow!("server endpoint not found (status 404). Check your server URL."),
        500..=599 => {
            anyhow::anyhow!("server error ({status}). Run 'vouch doctor' to check connectivity.")
        }
        _ => anyhow::anyhow!("unexpected server response ({status})"),
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
    if !header.starts_with("Bearer ") {
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
            let start = header.get(search_from..)?.find(&prefix)? + search_from;
            // Verify boundary: the character before the match must be a delimiter
            // (comma, space) or the start of the string.
            if start > 0 {
                let prev = header.as_bytes().get(start.wrapping_sub(1)).copied()?;
                if prev != b',' && prev != b' ' {
                    // Not a real parameter boundary — keep searching
                    search_from = start + 1;
                    continue;
                }
            }
            let value_start = start + prefix.len();
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

            // Parse URL to extract path and query
            let parsed = url::Url::parse(url).context("invalid URL")?;
            let path_and_query = if let Some(query) = parsed.query() {
                format!("{}?{}", parsed.path(), query)
            } else {
                parsed.path().to_string()
            };

            // Build request
            let method =
                http::Method::from_bytes(method.as_bytes()).context("invalid HTTP method")?;

            let mut builder = http::Request::builder().method(method).uri(&path_and_query);

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

            let request = builder.body(body).context("failed to build request")?;

            // Call the router - clone the inner Router for oneshot
            let router: axum::Router = (*self.router).clone();
            let response = tower::ServiceExt::oneshot(router, request)
                .await
                .context("router error")?;

            // Extract status and headers
            let status = response.status().as_u16();
            let www_authenticate = if status == 401 {
                response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            } else {
                None
            };

            // Extract DPoP-Nonce header
            let dpop_nonce = response
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .context("failed to read response body")?;

            Ok(HttpResponse {
                status,
                body: body_bytes.to_vec(),
                www_authenticate,
                dpop_nonce,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn test_http_response_with_www_authenticate_dpop_nonce_none() {
        let response = HttpResponse::with_www_authenticate(401, b"{}".to_vec(), None);
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
