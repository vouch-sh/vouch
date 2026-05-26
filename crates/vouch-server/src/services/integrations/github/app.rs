// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App API client.
//!
//! This module provides the low-level GitHub API client functionality:
//! - Authenticate as a GitHub App using RS256 JWTs
//! - Exchange App JWTs for installation access tokens
//! - Scope tokens to specific repositories and permissions
//! - User OAuth token management (exchange, refresh)
//! - GitHub API calls (user info, installations)

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::config::ServerConfig;

/// GitHub App ID (assigned when creating the app on github.com).
#[derive(Debug, Clone, Copy)]
pub struct GitHubAppId(pub u64);

/// GitHub App installation ID (unique per org/user that installs the app).
#[derive(Debug, Clone, Copy)]
pub struct GitHubInstallationId(pub u64);

/// RSA private key in PKCS#1 DER format, zeroized on drop.
///
/// `jsonwebtoken::EncodingKey::from_rsa_der()` with the `aws_lc_rs` feature
/// expects PKCS#1 DER format (RFC 8017), which is what GitHub provides for
/// App private keys (`BEGIN RSA PRIVATE KEY`).
#[derive(Clone)]
pub(crate) struct RsaPrivateKeyDer(Zeroizing<Vec<u8>>);

impl RsaPrivateKeyDer {
    /// Parse RSA private key from PKCS#1 PEM or base64-encoded PKCS#1 PEM.
    ///
    /// Supports:
    /// - PKCS#1 PEM format (`BEGIN RSA PRIVATE KEY`) - as provided by GitHub
    /// - Base64-encoded PKCS#1 PEM (entire PEM base64 encoded for env vars)
    ///
    /// For environment variables, base64 encode the entire PEM file:
    /// ```bash
    /// cat your-key.pem | base64 | tr -d '\n'
    /// ```
    pub(crate) fn from_pem(pem_or_base64: &str) -> Result<Self> {
        let pem =
            crate::crypto::pem::decode_base64_pem(pem_or_base64).context("Invalid key format")?;
        Self::parse_pem(&pem)
    }

    /// Parse a PEM-formatted PKCS#1 key.
    fn parse_pem(content: &str) -> Result<Self> {
        if !content.contains("RSA PRIVATE KEY") {
            anyhow::bail!(
                "Invalid key format: expected PKCS#1 PEM ('BEGIN RSA PRIVATE KEY'), \
                 not PKCS#8. GitHub App keys should be in PKCS#1 format."
            );
        }

        let der_bytes = Self::pem_to_der(content)?;
        tracing::debug!("Parsed PKCS#1 RSA key: {} DER bytes", der_bytes.len());
        Ok(Self(Zeroizing::new(der_bytes)))
    }

    /// Get the PKCS#1 DER bytes.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert PEM to DER bytes.
    pub(crate) fn pem_to_der(pem_content: &str) -> Result<Vec<u8>> {
        let lines: Vec<&str> = pem_content.lines().collect();
        let mut base64_content = String::new();
        let mut in_content = false;

        for line in lines {
            let line = line.trim();
            if line.starts_with("-----BEGIN") {
                in_content = true;
                continue;
            }
            if line.starts_with("-----END") {
                break;
            }
            if in_content {
                base64_content.push_str(line);
            }
        }

        STANDARD
            .decode(&base64_content)
            .context("Failed to decode PEM base64 content")
    }
}

/// JWT claims for authenticating as the GitHub App.
#[derive(Debug, Serialize)]
struct GitHubAppJwtClaims {
    /// Issued at (Unix timestamp).
    iat: i64,
    /// Expiration (Unix timestamp, max 10 minutes).
    exp: i64,
    /// Issuer (GitHub App ID).
    iss: String,
}

/// Installation access token from GitHub.
pub struct GitHubInstallationToken {
    /// The access token (use as password with username "x-access-token").
    pub token: SecretString,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// Granted permissions (scope -> level).
    pub permissions: HashMap<String, String>,
    /// Repositories the token can access (if scoped).
    pub repositories: Option<Vec<GitHubRepository>>,
}

/// GitHub repository reference.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRepository {
    /// Repository ID.
    pub id: u64,
    /// Repository name (without owner).
    pub name: String,
    /// Full name (owner/repo).
    pub full_name: String,
}

/// Response from GitHub's installation token endpoint.
#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
    permissions: HashMap<String, String>,
    repositories: Option<Vec<GitHubRepository>>,
}

// Custom Debug that redacts token to prevent accidental log exposure.
impl std::fmt::Debug for InstallationTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationTokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("permissions", &self.permissions)
            .field("repositories", &self.repositories)
            .finish()
    }
}

/// Response from GitHub's installation details endpoint.
#[derive(Debug, Deserialize)]
pub struct InstallationDetails {
    /// Installation ID.
    pub id: u64,
    /// Account that installed the app.
    pub account: InstallationAccount,
    /// Repository selection mode.
    pub repository_selection: String,
    /// Granted permissions.
    pub permissions: HashMap<String, String>,
    /// When the app was installed.
    pub created_at: String,
    /// Whether the installation is suspended.
    pub suspended_at: Option<String>,
}

/// Account that installed the GitHub App.
#[derive(Debug, Deserialize)]
pub struct InstallationAccount {
    /// Account login (username or org name).
    pub login: String,
    /// Account ID.
    pub id: u64,
    /// Account type ("Organization" or "User").
    #[serde(rename = "type")]
    pub account_type: String,
}

/// Request body for creating an installation token.
#[derive(Debug, Serialize)]
struct CreateInstallationTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<HashMap<String, String>>,
}

/// GitHub App configuration and token generation.
pub struct GitHubApp {
    app_id: GitHubAppId,
    private_key: RsaPrivateKeyDer,
    http_client: reqwest::Client,
}

impl GitHubApp {
    /// Load GitHub App from configuration if all required values are present.
    ///
    /// # Arguments
    /// * `config` - Server configuration
    /// * `http_client` - Shared HTTP client (configured with appropriate local address)
    pub fn load(config: &ServerConfig, http_client: reqwest::Client) -> Result<Option<Self>> {
        let app_id = match config.github_app_id {
            Some(id) => GitHubAppId(id),
            None => {
                tracing::info!("GitHub App not configured (no app ID)");
                return Ok(None);
            }
        };

        let private_key_pem = match config.github_app_key_exposed() {
            Some(key) if !key.trim().is_empty() => key,
            _ => {
                tracing::info!("GitHub App not configured (no private key)");
                return Ok(None);
            }
        };

        let private_key = RsaPrivateKeyDer::from_pem(private_key_pem)
            .context("Failed to parse GitHub App private key")?;

        // Verify the key can be used for signing
        match aws_lc_rs::signature::RsaKeyPair::from_der(private_key.as_bytes()) {
            Ok(key_pair) => {
                tracing::info!(
                    "GitHub App private key validated: {} bytes, modulus {} bits",
                    private_key.as_bytes().len(),
                    key_pair.public_modulus_len().saturating_mul(8)
                );
            }
            Err(e) => {
                tracing::error!(
                    "GitHub App private key INVALID: {} bytes, error: {:?}",
                    private_key.as_bytes().len(),
                    e
                );
                anyhow::bail!("GitHub App private key failed validation: {e:?}");
            }
        }

        tracing::info!("GitHub App loaded: app_id={}", app_id.0);

        Ok(Some(Self {
            app_id,
            private_key,
            http_client,
        }))
    }

    /// Generate a JWT for authenticating as the GitHub App (RS256, 10-min validity).
    ///
    /// RS256 signing is offloaded to a blocking thread to avoid starving
    /// the tokio runtime on 1-vCPU instances.
    pub async fn generate_app_jwt(&self) -> Result<String> {
        let now = jiff::Timestamp::now();
        // GitHub recommends setting iat to 60 seconds in the past to account for clock drift
        let iat = now.as_second().saturating_sub(60);
        // JWT expires in 10 minutes (GitHub maximum)
        let exp = now.as_second().saturating_add(600);

        let claims = GitHubAppJwtClaims {
            iat,
            exp,
            iss: self.app_id.0.to_string(),
        };

        let private_key_bytes = self.private_key.as_bytes().to_vec();

        tokio::task::spawn_blocking(move || {
            let encoding_key = EncodingKey::from_rsa_der(&private_key_bytes);
            let header = Header::new(Algorithm::RS256);

            jsonwebtoken::encode(&header, &claims, &encoding_key)
                .map_err(|e| anyhow::anyhow!("Failed to generate GitHub App JWT: {e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("GitHub App JWT signing task failed: {e}"))?
    }

    /// Get installation details from GitHub.
    pub async fn get_installation_details(
        &self,
        installation_id: GitHubInstallationId,
    ) -> Result<InstallationDetails> {
        let jwt = self.generate_app_jwt().await?;

        let url = format!(
            "https://api.github.com/app/installations/{}",
            installation_id.0
        );

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("Failed to request installation details from GitHub")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!(
                "GitHub API error ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }

        response
            .json::<InstallationDetails>()
            .await
            .context("Failed to parse installation details response")
    }

    /// Get a scoped installation access token from GitHub.
    ///
    /// # Arguments
    /// * `installation_id` - The installation to get a token for
    /// * `repositories` - Optional list of repository names (without owner) to scope the token to
    /// * `permissions` - Optional permissions to request (defaults to contents:write, metadata:read)
    pub async fn get_installation_token(
        &self,
        installation_id: GitHubInstallationId,
        repositories: Option<&[String]>,
        permissions: Option<&HashMap<String, String>>,
    ) -> Result<GitHubInstallationToken> {
        let jwt = self.generate_app_jwt().await?;

        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            installation_id.0
        );

        let request_body = CreateInstallationTokenRequest {
            repositories: repositories.map(|r| r.to_vec()),
            permissions: permissions.cloned(),
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&request_body)
            .send()
            .await
            .context("Failed to request installation token from GitHub")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!(
                "GitHub API error ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }

        let token_response: InstallationTokenResponse = response
            .json()
            .await
            .context("Failed to parse installation token response")?;

        Ok(GitHubInstallationToken {
            token: SecretString::from(token_response.token),
            expires_at: token_response.expires_at,
            permissions: token_response.permissions,
            repositories: token_response.repositories,
        })
    }

    /// Get the App ID.
    #[must_use]
    pub fn app_id(&self) -> GitHubAppId {
        self.app_id
    }

    /// Get a reference to the HTTP client.
    ///
    /// This client is configured with `vouch_common::http::server_client()`
    /// timeouts (15s total, 5s connect).
    #[must_use]
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

/// Minimal permissions for Git operations.
#[must_use]
pub(crate) fn minimal_git_permissions() -> HashMap<String, String> {
    [("contents", "write"), ("metadata", "read")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ============================================================================
// User OAuth Token APIs
// ============================================================================

/// Response from GET /user/installations (paginated).
#[derive(Debug, Deserialize)]
pub(crate) struct UserInstallationsResponse {
    /// Total count of installations the user has access to.
    #[allow(dead_code, reason = "GitHub API field; deserialized but not consumed")]
    pub total_count: u32,
    /// List of installations.
    pub installations: Vec<InstallationDetails>,
}

/// List installations accessible to a user (requires user OAuth access token).
///
/// This uses the user's OAuth token, not the App JWT. The API returns only
/// installations the authenticated user has explicit permission to access.
///
/// # Arguments
/// * `http_client` - HTTP client to use
/// * `user_token` - GitHub user OAuth access token
pub(crate) async fn list_user_accessible_installations(
    http_client: &reqwest::Client,
    user_token: &str,
) -> Result<Vec<InstallationDetails>> {
    let mut all_installations = Vec::new();
    let mut page: u32 = 1;

    loop {
        let response = http_client
            .get(format!(
                "https://api.github.com/user/installations?per_page=100&page={page}"
            ))
            .header("Authorization", format!("Bearer {user_token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("Failed to request user installations from GitHub")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!(
                "GitHub API error ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }

        let body: UserInstallationsResponse = response
            .json()
            .await
            .context("Failed to parse user installations response")?;

        let count = body.installations.len();
        all_installations.extend(body.installations);

        if count < 100 {
            break;
        }
        page = page.saturating_add(1);
    }

    Ok(all_installations)
}

/// GitHub user info from /user endpoint.
#[derive(Debug, Deserialize)]
#[allow(dead_code, reason = "GitHub API fields; deserialized for completeness")]
pub(crate) struct GitHubUser {
    /// GitHub user ID.
    pub id: u64,
    /// GitHub username (login).
    pub login: String,
    /// User's name.
    pub name: Option<String>,
    /// User's email (may be null if private).
    pub email: Option<String>,
}

/// Get the authenticated user's info from GitHub.
///
/// # Arguments
/// * `http_client` - HTTP client to use
/// * `user_token` - GitHub user OAuth access token
pub(crate) async fn get_github_user(
    http_client: &reqwest::Client,
    user_token: &str,
) -> Result<GitHubUser> {
    let response = http_client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {user_token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("Failed to request user info from GitHub")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "GitHub API error ({}): {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    response
        .json::<GitHubUser>()
        .await
        .context("Failed to parse GitHub user response")
}

/// Response from GitHub OAuth token endpoint.
#[derive(Deserialize)]
pub(crate) struct GitHubOAuthTokenResponse {
    /// Access token for API calls.
    pub access_token: String,
    /// Token type (usually "bearer").
    pub token_type: String,
    /// Granted scopes (space-separated).
    pub scope: Option<String>,
    /// Refresh token for getting new access tokens.
    pub refresh_token: Option<String>,
    /// Access token expiration in seconds (8 hours for GitHub Apps).
    pub expires_in: Option<u64>,
    /// Refresh token expiration in seconds (6 months for GitHub Apps).
    pub refresh_token_expires_in: Option<u64>,
}

// Custom Debug that redacts tokens to prevent accidental log exposure.
impl std::fmt::Debug for GitHubOAuthTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubOAuthTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .finish()
    }
}

/// Exchange an OAuth authorization code for access and refresh tokens.
///
/// Per RFC 6749 Section 4.1.3, `redirect_uri` MUST be included in the token
/// request when it was included in the authorization request.
///
/// # Arguments
/// * `http_client` - HTTP client to use
/// * `client_id` - GitHub App Client ID
/// * `client_secret` - GitHub App Client Secret
/// * `code` - Authorization code from OAuth callback
/// * `redirect_uri` - The same redirect URI used in the authorization request
pub(crate) async fn exchange_oauth_code(
    http_client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<GitHubOAuthTokenResponse> {
    let response = http_client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .context("Failed to exchange OAuth code with GitHub")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "GitHub OAuth error ({}): {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    // GitHub may return 200 with an error in the body
    let body: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse OAuth token response")?;

    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        let description = body
            .get("error_description")
            .and_then(|d| d.as_str())
            .unwrap_or("Unknown error");
        bail!("GitHub OAuth error: {} - {}", error, description);
    }

    serde_json::from_value(body).context("Failed to parse OAuth token response")
}

/// Refresh an access token using a refresh token.
///
/// # Arguments
/// * `http_client` - HTTP client to use
/// * `client_id` - GitHub App Client ID
/// * `client_secret` - GitHub App Client Secret
/// * `refresh_token` - Refresh token from previous OAuth flow
pub(crate) async fn refresh_oauth_token(
    http_client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<GitHubOAuthTokenResponse> {
    let response = http_client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("Failed to refresh OAuth token with GitHub")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "GitHub OAuth refresh error ({}): {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    // GitHub may return 200 with an error in the body
    let body: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse OAuth refresh response")?;

    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        let description = body
            .get("error_description")
            .and_then(|d| d.as_str())
            .unwrap_or("Unknown error");
        bail!("GitHub OAuth refresh error: {} - {}", error, description);
    }

    serde_json::from_value(body).context("Failed to parse OAuth refresh response")
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // Test RSA key in PKCS#1 PEM format (as provided by GitHub App)
    const TEST_RSA_KEY_PKCS1_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAq+Yjk+Vhue6aIzehO/jfoxzc9shrMLZ0T2+Xx5ohsMZJYULo
DRHUpgWuLaQeXL9pF3vmwG3yZkHAN1bFs7uWpwNcvzIO6Oz7Yym6dRb3cmBCiC5N
PIPR0nwgH/ZcmPx0KpDmhNeqx2iWl035J0rGQpAK9CfeM4GdzXporoBct9AJxoFH
34tZ4Ja6R2cLPxH6c/IAp82fMl9k6ji01p5DBwoY6DW0vZk+3q/t0muJHutmXCNO
rZrH+u+h8lz4ridD3+tuvsjOOmMUX107AKl5zXfFaP5dAsrTqZ2qne09CNrMP0M9
F/36VkJurwxR0y15umwikM6xnf02xFOCa+6PawIDAQABAoIBAFSmBTIQvFGTmiqq
e8btFK+diIAsDIDV8Cun372mfF2xHzR6fovlEmrZFD8ceOkiRu2OEYEEA2Bwk2eM
3tlVkGfZA4SRcX8pJ9falhuPvjWACnNGHbmljh8RCb7DkjCx7MCDT0jubQY6TiHe
/0jmjP/9L6+wrD5/3wXu9/qqcj3/LxNxXfNI+0JaY0GKo24vZHGYj5mCBUvQHC+4
rElwlFygaZfnnSchPSCWssFdgMDblkbGpkylje2wSvxvoTTAfkrTsNsr7wZYnKuK
6Pza3/78OP0w5gS93YDOWNG1WTrxsxR2bMH6MZHH3h/w/EPCFXdztYumcafyYFBC
SgZjeSUCgYEA8Wy1K8iH+nbVJIy1qTyd/a3t+MvsT1vBYkOxkLXSU2O7zFp68NtX
FGkrxtEw+r4XEee3UBrLNQF2vmqrNxrYNEncRp5hLUHqnDmHQvC/OlyutPL2FSgN
+rR7/QTMF9MSGsZYtuNAaOVW3maX7ioj1vRY2+zUDQxtUS2FyIW0c60CgYEAtkbk
COuAEQaknV1kayEcA/fkF9WVs4jiSPL/cdFQhUgt/g0000ZZ2aD1rMXufrNrXNkw
OAafLn4Cgu5KsE6zEaNcr+M5NeNikljyqxl0c72FrqumDzYwF5c/i/jZWWc+S6yF
R9eEy5MCp90eqmdn3x6bpIi7L03WqwfZIHbpMncCgYEA58bbsCsXEMhhHHPSO6Ws
cE049/Ce8BlA8VvX7vv/7nsDYs9C1FVfpoLJulg/U5qHf3McNFVk3YCIRYsW0RJ+
msSGK24GEXMFD/LS/tsuW5N7TtEqm2kW8qevmVuvrPfAm9/sb7iAr7Pt0Bpipg3i
1o1DefBGLDjQAm1X0Qk8EwkCgYAAjmbTwCQ76RFHialsykUTngYMLJKwYZKPNm6h
IkpknbvGMrQekPBlQaB+TnxT1qhVODR1d0+1DJ1lWOTRdOwG+cCmqMLb7z21xJ+4
9fLtB38I8W0oTroG2GdRPgkrxKzj/jrJ5VZ6aJBxgrM9QeOHQsimz+QCWPJ2wyde
ef5sMQKBgQDgdb3fIhYhwL4pqD16vDxWrEmKW4UTufkTSHeuXaQvELlMaE01Xcvn
4E6YbvnQ536ej8Y75DAxPheNxwSORCpg9ZnFZF3HifT5G5h45OvPkZNrR0KVCB0u
eyYRskrWOAtu0DuWJARLn74r5B4ze8s4DvUdPe781neRB1hMbXte6g==
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn test_rsa_key_from_pkcs1_pem() {
        // PKCS#1 format is what GitHub provides for App private keys
        let key =
            RsaPrivateKeyDer::from_pem(TEST_RSA_KEY_PKCS1_PEM).expect("Should parse PKCS#1 PEM");
        assert!(!key.as_bytes().is_empty());

        // The key should be usable with jsonwebtoken for signing
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(key.as_bytes());

        // Actually try to sign something
        #[derive(serde::Serialize)]
        struct TestClaims {
            sub: String,
            iat: i64,
            exp: i64,
        }
        let claims = TestClaims {
            sub: "test".to_string(),
            iat: 1000000000,
            exp: 1000000600,
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .expect("Should be able to sign JWT with PKCS#1 key");
        assert!(!token.is_empty());
    }

    #[test]
    fn test_rsa_key_from_base64_encoded_pem() {
        // This is the common format for environment variables - the entire PEM
        // (including headers) is base64 encoded to avoid newline issues
        let base64_pem = STANDARD.encode(TEST_RSA_KEY_PKCS1_PEM.as_bytes());

        let key = RsaPrivateKeyDer::from_pem(&base64_pem).expect("Should parse base64-encoded PEM");
        assert!(!key.as_bytes().is_empty());

        // Verify it can sign
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(key.as_bytes());
        #[derive(serde::Serialize)]
        struct TestClaims {
            sub: String,
        }
        let claims = TestClaims {
            sub: "test".to_string(),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .expect("Should be able to sign with base64-encoded PEM key");
        assert!(!token.is_empty());
    }

    #[test]
    #[expect(
        clippy::unreachable,
        reason = "test code: unreachable! after let-else-Err proof"
    )]
    fn test_rsa_key_rejects_pkcs8_pem() {
        // Verify that PKCS#8 PEM format is rejected with a helpful error
        let pkcs8_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----";
        let result = RsaPrivateKeyDer::from_pem(pkcs8_pem);
        let Err(e) = result else {
            unreachable!("Expected PKCS#8 PEM to be rejected");
        };
        let err = e.to_string();
        assert!(
            err.contains("PKCS#1") && err.contains("RSA PRIVATE KEY"),
            "Error should mention PKCS#1 format: {err}"
        );
    }

    #[test]
    fn test_minimal_git_permissions() {
        let perms = minimal_git_permissions();
        assert_eq!(perms.get("contents"), Some(&"write".to_string()));
        assert_eq!(perms.get("metadata"), Some(&"read".to_string()));
        assert_eq!(perms.len(), 2);
    }
}
