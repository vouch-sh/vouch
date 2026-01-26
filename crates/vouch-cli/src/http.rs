//! HTTP client abstraction for server communication.
//!
//! This module provides a trait-based abstraction over HTTP operations,
//! enabling integration testing by injecting an axum router directly
//! instead of making real network requests.

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use vouch_common::ApiError;

/// HTTP response from the client.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a new HTTP response.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
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
        let client = reqwest::Client::builder()
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self { client })
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            client: reqwest::Client::new(),
        })
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

        if let Some(b) = body {
            builder = builder.body(b.to_vec());
        }

        let response = builder.send().await.context("HTTP request failed")?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .context("failed to read response body")?;

        Ok(HttpResponse::new(status, body.to_vec()))
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
                .request("POST", url, Some(&json), Some("application/json"), None)
                .await?;
            handle_response(response)
        }
    }

    /// POST JSON with authentication and receive JSON response.
    fn post_json_authenticated<Req, Resp>(
        &self,
        url: &str,
        body: &Req,
        token: &str,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        let auth = format!("Bearer {token}");
        async move {
            let json = serde_json::to_vec(body).context("failed to serialize request")?;
            let response = self
                .request(
                    "POST",
                    url,
                    Some(&json),
                    Some("application/json"),
                    Some(&auth),
                )
                .await?;
            handle_response(response)
        }
    }

    /// GET with authentication and receive JSON response.
    fn get_json_authenticated<Resp>(
        &self,
        url: &str,
        token: &str,
    ) -> impl std::future::Future<Output = Result<Resp>> + Send
    where
        Resp: DeserializeOwned,
    {
        let auth = format!("Bearer {token}");
        async move {
            let response = self.request("GET", url, None, None, Some(&auth)).await?;
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
                )
                .await?;
            handle_response(response)
        }
    }
}

// Implement HttpClientExt for all HttpClient implementations
impl<T: HttpClient> HttpClientExt for T {}

/// Handle HTTP response, parsing JSON or error.
fn handle_response<Resp: DeserializeOwned>(response: HttpResponse) -> Result<Resp> {
    if response.is_success() {
        response.json()
    } else {
        // Try to parse as API error
        let error_text = response.text().unwrap_or_default();
        if let Ok(api_error) = serde_json::from_str::<ApiError>(&error_text) {
            bail!("{}: {}", api_error.code, api_error.message);
        }
        bail!("server error ({}): {}", response.status, error_text);
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;

#[cfg(any(test, feature = "test-utils"))]
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

            // Extract status and body
            let status = response.status().as_u16();
            let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .context("failed to read response body")?;

            Ok(HttpResponse::new(status, body_bytes.to_vec()))
        }
    }
}

#[cfg(test)]
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
        let parsed: serde_json::Value = response.json().ok().unwrap_or(serde_json::Value::Null);
        assert_eq!(parsed.get("key").and_then(|v| v.as_str()), Some("value"));
    }

    #[test]
    fn test_http_response_text() {
        let response = HttpResponse::new(200, b"hello world".to_vec());
        assert_eq!(response.text().ok(), Some("hello world".to_string()));
    }

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

        let response = client
            .request("GET", "http://test.local/test", None, None, None)
            .await;

        assert!(response.is_ok());
        let resp = response.ok();
        assert!(resp.is_some());
        let resp = resp.unwrap_or_else(|| HttpResponse::new(500, vec![]));
        assert_eq!(resp.status, 200);

        let parsed: TestResponse = resp.json().ok().unwrap_or(TestResponse {
            message: String::new(),
        });
        assert_eq!(parsed.message, "hello");
    }
}
