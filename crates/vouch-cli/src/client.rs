// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client for communicating with vouch server.
//!
//! [`VouchClient`] is generic over [`HttpClient`](vouch_cli::http::HttpClient),
//! defaulting to [`ReqwestClient`](vouch_cli::http::ReqwestClient) for production use.
//! Tests can inject [`TestHttpClient`](vouch_cli::http::TestHttpClient) for in-process testing.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use vouch_cli::http::{HttpClient, HttpResponse, ReqwestClient, format_http_error};

/// HTTP client wrapper for vouch server API.
///
/// Generic over the HTTP transport to enable testing with mock servers.
/// The default type parameter (`ReqwestClient`) is used by all production code.
pub struct VouchClient<H: HttpClient = ReqwestClient> {
    http: H,
    base_url: String,
    /// Authentication token. Set at construction for authenticated clients,
    /// `None` for unauthenticated clients (login/enroll flows).
    token: Option<SecretString>,
}

impl VouchClient<ReqwestClient> {
    /// Create an authenticated client.
    ///
    /// Resolves the token once from the agent (if running) or config file.
    /// This is the standard constructor for most commands.
    pub async fn new(base_url: &str) -> Result<Self> {
        let mut client = Self::unauthenticated(base_url)?;
        let token = crate::session::resolve_token().await?;
        client.token = Some(token);
        Ok(client)
    }

    /// Create a client without authentication.
    ///
    /// Used only during login/enroll flows where the user doesn't have a
    /// token yet, and for health checks that don't require auth.
    pub fn unauthenticated(base_url: &str) -> Result<Self> {
        let http = ReqwestClient::new()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        })
    }

    /// Create an authenticated client from a resolved session.
    ///
    /// This is the standard pattern for credential commands that have already
    /// called `resolve_session()`.
    pub fn from_session(session: &crate::session::ResolvedSession) -> Result<Self> {
        let mut client = Self::unauthenticated(&session.server_url)?;
        client.token = Some(session.token.clone());
        Ok(client)
    }

    /// Get a reference to the raw reqwest client.
    pub fn raw_client(&self) -> &reqwest::Client {
        self.http.inner()
    }
}

impl<H: HttpClient> VouchClient<H> {
    /// Create a client with a custom HTTP implementation.
    ///
    /// Used for testing with `TestHttpClient`.
    #[allow(dead_code)]
    pub fn with_http(http: H, base_url: &str) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    /// Set an explicit authentication token.
    ///
    /// Used when the caller has already resolved the token (e.g., from
    /// `resolve_session()`) and wants to avoid resolving it again.
    pub fn set_token(&mut self, token: SecretString) {
        self.token = Some(token);
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the stored authentication token, or error if not authenticated.
    fn token(&self) -> Result<&SecretString> {
        self.token
            .as_ref()
            .context("not authenticated - run 'vouch login' first")
    }

    /// Build the full URL for a path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST a JSON request and get a JSON response.
    pub async fn post<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("POST {}", url);

        let json = serde_json::to_vec(body).context("failed to serialize request")?;
        let response = self
            .http
            .request("POST", &url, Some(&json), Some("application/json"), None)
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// POST a form-encoded request and get a JSON response.
    /// Used for OAuth endpoints which require application/x-www-form-urlencoded.
    pub async fn post_form<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("POST {} (form)", url);

        let form = serde_urlencoded::to_string(body).context("failed to serialize form data")?;
        let response = self
            .http
            .request(
                "POST",
                &url,
                Some(form.as_bytes()),
                Some("application/x-www-form-urlencoded"),
                None,
            )
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// GET a JSON response with authentication.
    pub async fn get_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let token = self.token()?;
        let auth = format!("Bearer {}", token.expose_secret());
        let url = self.url(path);
        tracing::debug!("GET {} (authenticated)", url);

        let response = self
            .http
            .request("GET", &url, None, None, Some(&auth))
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// DELETE with authentication.
    pub async fn delete_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let token = self.token()?;
        let auth = format!("Bearer {}", token.expose_secret());
        let url = self.url(path);
        tracing::debug!("DELETE {} (authenticated)", url);

        let response = self
            .http
            .request("DELETE", &url, None, None, Some(&auth))
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// POST a JSON request with authentication and get a JSON response.
    pub async fn post_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let token = self.token()?;
        let auth = format!("Bearer {}", token.expose_secret());
        let url = self.url(path);
        tracing::debug!("POST {} (authenticated)", url);

        let json = serde_json::to_vec(body).context("failed to serialize request")?;
        let response = self
            .http
            .request(
                "POST",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
            )
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// PATCH a JSON request with authentication and get a JSON response.
    pub async fn patch_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let token = self.token()?;
        let auth = format!("Bearer {}", token.expose_secret());
        let url = self.url(path);
        tracing::debug!("PATCH {} (authenticated)", url);

        let json = serde_json::to_vec(body).context("failed to serialize request")?;
        let response = self
            .http
            .request(
                "PATCH",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
            )
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// Handle HTTP response, parsing JSON or error.
    ///
    /// Returns typed [`crate::exit_code::CliError`] for well-known HTTP status codes:
    /// - 401 → `CliError::NotAuthenticated`
    /// - 403 → `CliError::PermissionDenied`
    /// - Other errors → generic message from [`format_http_error`]
    fn handle_response<Resp: DeserializeOwned>(response: HttpResponse) -> Result<Resp> {
        if response.is_success() {
            return response.json();
        }

        let status_code = response.status;
        let error_text = response.text().unwrap_or_default();

        match status_code {
            401 => Err(crate::exit_code::CliError::NotAuthenticated.into()),
            403 => Err(crate::exit_code::CliError::PermissionDenied.into()),
            _ => Err(format_http_error(status_code, &error_text)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthenticated_trims_trailing_slash() {
        let client = VouchClient::unauthenticated("https://example.com/").unwrap();
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn test_unauthenticated_trims_multiple_trailing_slashes() {
        let client = VouchClient::unauthenticated("https://example.com///").unwrap();
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn test_unauthenticated_no_trailing_slash() {
        let client = VouchClient::unauthenticated("https://example.com").unwrap();
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn test_token_returns_error_when_not_set() {
        let client = VouchClient::unauthenticated("https://example.com").unwrap();
        assert!(client.token().is_err());
    }

    #[test]
    fn test_set_token_makes_token_available() {
        let mut client = VouchClient::unauthenticated("https://example.com").unwrap();
        client.set_token(SecretString::from("test-token".to_string()));
        assert!(client.token().is_ok());
    }

    #[test]
    fn test_base_url_returns_stored_url() {
        let client = VouchClient::unauthenticated("https://example.com").unwrap();
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn test_handle_response_401_returns_not_authenticated() {
        let response = HttpResponse::new(401, b"{}".to_vec());
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.downcast_ref::<crate::exit_code::CliError>().is_some());
    }

    #[test]
    fn test_handle_response_403_returns_permission_denied() {
        let response = HttpResponse::new(403, b"{}".to_vec());
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.downcast_ref::<crate::exit_code::CliError>().is_some());
    }

    #[test]
    fn test_handle_response_success() {
        let response = HttpResponse::new(200, br#"{"ok":true}"#.to_vec());
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_ok());
    }
}
