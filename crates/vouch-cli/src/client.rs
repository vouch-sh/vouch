//! HTTP client for vouch server API

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use vouch_common::ApiError;

/// Client for vouch server API
pub struct VouchClient {
    http: Client,
    base_url: String,
}

impl VouchClient {
    /// Create a new client
    pub fn new(base_url: &str) -> Result<Self> {
        let http = Client::builder()
            .user_agent(format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// POST request
    pub async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        token: Option<&str>,
    ) -> Result<R> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut req = self.http.post(&url).json(body);
        
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.context("request failed")?;
        self.handle_response(resp).await
    }

    /// GET request
    pub async fn get<R: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<R> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut req = self.http.get(&url);
        
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.context("request failed")?;
        self.handle_response(resp).await
    }

    /// DELETE request
    pub async fn delete<R: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<R> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut req = self.http.delete(&url);
        
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.context("request failed")?;
        self.handle_response(resp).await
    }

    /// Handle response, extracting errors
    async fn handle_response<R: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<R> {
        let status = resp.status();
        
        if status.is_success() {
            let body = resp.json().await.context("failed to parse response")?;
            Ok(body)
        } else {
            // Try to parse as API error
            let error: ApiError = resp
                .json()
                .await
                .unwrap_or_else(|_| ApiError::new("unknown", format!("HTTP {}", status)));
            
            anyhow::bail!("{}: {}", error.code, error.error)
        }
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
