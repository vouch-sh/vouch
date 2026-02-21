// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client for communicating with vouch server.

use anyhow::{Context, Result};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};

/// HTTP client wrapper for vouch server API.
pub struct VouchClient {
    client: Client,
    base_url: String,
    /// Authentication token. Set at construction for authenticated clients,
    /// `None` for unauthenticated clients (login/enroll flows).
    token: Option<SecretString>,
}

impl VouchClient {
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
        let client = vouch_common::http::interactive_client(&format!(
            "vouch-cli/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        })
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

    /// Get a reference to the raw reqwest client.
    pub fn raw_client(&self) -> &Client {
        &self.client
    }

    /// Get the stored authentication token, or error if not authenticated.
    fn token(&self) -> Result<&SecretString> {
        self.token
            .as_ref()
            .context("not authenticated - run 'vouch login' first")
    }

    /// POST a JSON request and get a JSON response.
    pub async fn post<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("POST {}", url);

        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// POST a form-encoded request and get a JSON response.
    /// Used for OAuth endpoints which require application/x-www-form-urlencoded.
    pub async fn post_form<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("POST {} (form)", url);

        let response = self
            .client
            .post(&url)
            .form(body)
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// GET a JSON response with authentication.
    pub async fn get_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let token = self.token()?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("GET {} (authenticated)", url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// DELETE with authentication.
    pub async fn delete_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let token = self.token()?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("DELETE {} (authenticated)", url);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// POST a JSON request with authentication and get a JSON response.
    pub async fn post_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let token = self.token()?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("POST {} (authenticated)", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .json(body)
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// PATCH a JSON request with authentication and get a JSON response.
    pub async fn patch_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let token = self.token()?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("PATCH {} (authenticated)", url);

        let response = self
            .client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .json(body)
            .send()
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        self.handle_response(response).await
    }

    /// Handle HTTP response, parsing JSON or error.
    async fn handle_response<Resp>(&self, response: reqwest::Response) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let status = response.status();

        if status.is_success() {
            response
                .json()
                .await
                .context("failed to parse server response")
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(vouch_cli::http::format_http_error(
                status.as_u16(),
                &error_text,
            ))
        }
    }
}
