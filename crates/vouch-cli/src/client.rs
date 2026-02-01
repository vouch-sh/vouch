// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client for communicating with vouch server.

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use vouch_common::ApiError;

use crate::config::Config;

/// HTTP client wrapper for vouch server API.
pub struct VouchClient {
    client: Client,
    base_url: String,
}

impl VouchClient {
    /// Create a new client for the given server URL.
    pub fn new(base_url: &str) -> Result<Self> {
        let client =
            vouch_common::http::interactive_client().context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get a reference to the raw reqwest client.
    pub fn raw_client(&self) -> &Client {
        &self.client
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
        let config = Config::load()?;
        let token = config
            .token()
            .context("not authenticated - run 'vouch login' first")?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("GET {} (authenticated)", url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
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
        let config = Config::load()?;
        let token = config
            .token()
            .context("not authenticated - run 'vouch login' first")?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("DELETE {} (authenticated)", url);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {token}"))
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
        let config = Config::load()?;
        let token = config
            .token()
            .context("not authenticated - run 'vouch login' first")?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("POST {} (authenticated)", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
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
        let config = Config::load()?;
        let token = config
            .token()
            .context("not authenticated - run 'vouch login' first")?;

        let url = format!("{}{}", self.base_url, path);
        tracing::debug!("PATCH {} (authenticated)", url);

        let response = self
            .client
            .patch(&url)
            .header("Authorization", format!("Bearer {token}"))
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
            // Try to parse as API error
            let error_text = response.text().await.unwrap_or_default();
            if let Ok(api_error) = serde_json::from_str::<ApiError>(&error_text) {
                bail!("{}: {}", api_error.code, api_error.message);
            }
            bail!("server error ({status}): {error_text}");
        }
    }
}
