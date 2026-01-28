// SPDX-License-Identifier: BUSL-1.1
//! GitHub App integration for credential issuance.
//!
//! This module provides functionality to:
//! - Authenticate as a GitHub App using RS256 JWTs
//! - Exchange App JWTs for installation access tokens
//! - Scope tokens to specific repositories and permissions

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

/// RSA private key in DER format, zeroized on drop.
#[derive(Clone)]
pub struct RsaPrivateKeyDer(Zeroizing<Vec<u8>>);

impl RsaPrivateKeyDer {
    /// Parse PEM-encoded RSA private key and extract DER bytes.
    ///
    /// Handles both multi-line PEM and single-line with literal `\n` characters
    /// (common when passing via environment variables).
    pub fn from_pem(pem: &str) -> Result<Self> {
        // Handle single-line keys with literal \n (common in env vars)
        let pem = pem.replace("\\n", "\n");
        let pem = pem.trim();

        // Validate it looks like a PEM key
        if !pem.starts_with("-----BEGIN") {
            anyhow::bail!("Invalid PEM format: missing BEGIN header");
        }
        if !pem.contains("PRIVATE KEY") {
            anyhow::bail!("Invalid PEM format: not a private key");
        }

        // Extract base64 content between headers
        let der_bytes = Self::pem_to_der(pem)?;

        Ok(Self(Zeroizing::new(der_bytes)))
    }

    /// Get the DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert PEM to DER bytes.
    fn pem_to_der(pem_content: &str) -> Result<Vec<u8>> {
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
#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
    permissions: HashMap<String, String>,
    repositories: Option<Vec<GitHubRepository>>,
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
    pub fn load(config: &ServerConfig) -> Result<Option<Self>> {
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

        let http_client = reqwest::Client::builder()
            .user_agent("vouch-server")
            .build()
            .context("Failed to create HTTP client for GitHub App")?;

        tracing::info!("GitHub App loaded: app_id={}", app_id.0);

        Ok(Some(Self {
            app_id,
            private_key,
            http_client,
        }))
    }

    /// Generate a JWT for authenticating as the GitHub App (RS256, 10-min validity).
    pub fn generate_app_jwt(&self) -> Result<String> {
        let now = jiff::Timestamp::now();
        // GitHub recommends setting iat to 60 seconds in the past to account for clock drift
        let iat = now.as_second() - 60;
        // JWT expires in 10 minutes (GitHub maximum)
        let exp = now.as_second() + 600;

        let claims = GitHubAppJwtClaims {
            iat,
            exp,
            iss: self.app_id.0.to_string(),
        };

        let encoding_key = EncodingKey::from_rsa_der(self.private_key.as_bytes());
        let header = Header::new(Algorithm::RS256);

        jsonwebtoken::encode(&header, &claims, &encoding_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate GitHub App JWT: {e}"))
    }

    /// Get installation details from GitHub.
    pub async fn get_installation_details(
        &self,
        installation_id: GitHubInstallationId,
    ) -> Result<InstallationDetails> {
        let jwt = self.generate_app_jwt()?;

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
        let jwt = self.generate_app_jwt()?;

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
}

/// Minimal permissions for Git operations.
#[must_use]
pub fn minimal_git_permissions() -> HashMap<String, String> {
    [("contents", "write"), ("metadata", "read")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // Test RSA key in PKCS#8 PEM format (for testing only - not a real key)
    const TEST_RSA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCr5iOT5WG57poj
N6E7+N+jHNz2yGswtnRPb5fHmiGwxklhQugNEdSmBa4tpB5cv2kXe+bAbfJmQcA3
VsWzu5anA1y/Mg7o7PtjKbp1FvdyYEKILk08g9HSfCAf9lyY/HQqkOaE16rHaJaX
TfknSsZCkAr0J94zgZ3NemiugFy30AnGgUffi1nglrpHZws/Efpz8gCnzZ8yX2Tq
OLTWnkMHChjoNbS9mT7er+3Sa4ke62ZcI06tmsf676HyXPiuJ0Pf626+yM46YxRf
XTsAqXnNd8Vo/l0CytOpnaqd7T0I2sw/Qz0X/fpWQm6vDFHTLXm6bCKQzrGd/TbE
U4Jr7o9rAgMBAAECggEAVKYFMhC8UZOaKqp7xu0Ur52IgCwMgNXwK6ffvaZ8XbEf
NHp+i+USatkUPxx46SJG7Y4RgQQDYHCTZ4ze2VWQZ9kDhJFxfykn19qWG4++NYAK
c0YduaWOHxEJvsOSMLHswINPSO5tBjpOId7/SOaM//0vr7CsPn/fBe73+qpyPf8v
E3Fd80j7QlpjQYqjbi9kcZiPmYIFS9AcL7isSXCUXKBpl+edJyE9IJaywV2AwNuW
RsamTKWN7bBK/G+hNMB+StOw2yvvBlicq4ro/Nrf/vw4/TDmBL3dgM5Y0bVZOvGz
FHZswfoxkcfeH/D8Q8IVd3O1i6Zxp/JgUEJKBmN5JQKBgQDxbLUryIf6dtUkjLWp
PJ39re34y+xPW8FiQ7GQtdJTY7vMWnrw21cUaSvG0TD6vhcR57dQGss1AXa+aqs3
Gtg0SdxGnmEtQeqcOYdC8L86XK608vYVKA36tHv9BMwX0xIaxli240Bo5VbeZpfu
KiPW9Fjb7NQNDG1RLYXIhbRzrQKBgQC2RuQI64ARBqSdXWRrIRwD9+QX1ZWziOJI
8v9x0VCFSC3+DTTTRlnZoPWsxe5+s2tc2TA4Bp8ufgKC7kqwTrMRo1yv4zk142KS
WPKrGXRzvYWuq6YPNjAXlz+L+NlZZz5LrIVH14TLkwKn3R6qZ2ffHpukiLsvTdar
B9kgdukydwKBgQDnxtuwKxcQyGEcc9I7paxwTTj38J7wGUDxW9fu+//uewNiz0LU
VV+mgsm6WD9Tmod/cxw0VWTdgIhFixbREn6axIYrbgYRcwUP8tL+2y5bk3tO0Sqb
aRbyp6+ZW6+s98Cb3+xvuICvs+3QGmKmDeLWjUN58EYsONACbVfRCTwTCQKBgACO
ZtPAJDvpEUeJqWzKRROeBgwskrBhko82bqEiSmSdu8YytB6Q8GVBoH5OfFPWqFU4
NHV3T7UMnWVY5NF07Ab5wKaowtvvPbXEn7j18u0HfwjxbShOugbYZ1E+CSvErOP+
OsnlVnpokHGCsz1B44dCyKbP5AJY8nbDJ155/mwxAoGBAOB1vd8iFiHAvimoPXq8
PFasSYpbhRO5+RNId65dpC8QuUxoTTVdy+fgTphu+dDnfp6PxjvkMDE+F43HBI5E
KmD1mcVkXceJ9PkbmHjk68+Rk2tHQpUIHS57JhGyStY4C27QO5YkBEufvivkHjN7
yzgO9R097vzWd5EHWExte17q
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_rsa_key_from_pem() {
        let key = RsaPrivateKeyDer::from_pem(TEST_RSA_KEY_PEM).expect("Should parse PEM");
        assert!(!key.as_bytes().is_empty());
    }

    #[test]
    fn test_rsa_key_from_single_line_pem() {
        // Test that single-line PEM with literal \n is handled
        let single_line = TEST_RSA_KEY_PEM.replace('\n', "\\n");
        let key = RsaPrivateKeyDer::from_pem(&single_line).expect("Should parse single-line PEM");
        assert!(!key.as_bytes().is_empty());
    }

    #[test]
    fn test_minimal_git_permissions() {
        let perms = minimal_git_permissions();
        assert_eq!(perms.get("contents"), Some(&"write".to_string()));
        assert_eq!(perms.get("metadata"), Some(&"read".to_string()));
        assert_eq!(perms.len(), 2);
    }
}
