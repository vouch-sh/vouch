// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client for communicating with vouch server.
//!
//! [`VouchClient`] is generic over [`HttpClient`](vouch_cli::http::HttpClient),
//! defaulting to [`ReqwestClient`](vouch_cli::http::ReqwestClient) for production use.
//! Tests can inject [`TestHttpClient`](vouch_cli::http::TestHttpClient) for in-process testing.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use vouch_cli::fapi::{ClientKey, DpopProofBuilder};
use vouch_cli::http::{
    HttpClient, HttpResponse, ReqwestClient, format_http_error, parse_www_authenticate,
};

/// HTTP client wrapper for vouch server API.
///
/// Generic over the HTTP transport to enable testing with mock servers.
/// The default type parameter (`ReqwestClient`) is used by all production code.
///
/// When a `fapi_key` is present, authenticated requests use
/// `Authorization: DPoP <token>` with a `DPoP: <proof>` header bound
/// to the access token hash (`ath` claim, RFC 9449 Section 4.2).
/// If DPoP proof generation fails, the client falls back to
/// `Authorization: Bearer <token>` transparently.
pub struct VouchClient<H: HttpClient = ReqwestClient> {
    http: H,
    base_url: String,
    /// Authentication token. Set at construction for authenticated clients,
    /// `None` for unauthenticated clients (login/enroll flows).
    token: Option<SecretString>,
    /// FAPI 2.0 client key for DPoP proof generation on resource requests.
    /// `None` when FAPI infrastructure is not available.
    fapi_key: Option<ClientKey>,
}

impl VouchClient<ReqwestClient> {
    /// Create an authenticated client.
    ///
    /// Resolves the token once from the agent (if running) or config file.
    /// Also loads the FAPI client key from the OS keychain (or disk fallback)
    /// for DPoP proof generation on resource requests.
    ///
    /// This is the standard constructor for most commands.
    pub async fn new(base_url: &str) -> Result<Self> {
        let mut client = Self::unauthenticated(base_url)?;
        let token = crate::session::resolve_token().await?;
        client.token = Some(token);
        // Load the FAPI key for DPoP on resource endpoints (non-fatal).
        client.fapi_key = load_fapi_key();
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
            fapi_key: None,
        })
    }

    /// Create an authenticated client from a resolved session.
    ///
    /// This is the standard pattern for credential commands that have already
    /// called `resolve_session()`.
    pub fn from_session(session: &crate::session::ResolvedSession) -> Result<Self> {
        let mut client = Self::unauthenticated(&session.server_url)?;
        client.token = Some(session.token.clone());
        // Load the FAPI key for DPoP on resource endpoints (non-fatal).
        client.fapi_key = load_fapi_key();
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
            fapi_key: None,
        }
    }

    /// Set an explicit authentication token.
    ///
    /// Used when the caller has already resolved the token (e.g., from
    /// `resolve_session()`) and wants to avoid resolving it again.
    pub fn set_token(&mut self, token: SecretString) {
        self.token = Some(token);
    }

    /// Set the FAPI client key for DPoP proof generation.
    ///
    /// Used when the caller already has the key in memory (e.g., from
    /// the login flow) and wants to avoid reloading from the keychain.
    pub fn set_fapi_key(&mut self, key: ClientKey) {
        self.fapi_key = Some(key);
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

    /// Build the `Authorization` header value and an optional `DPoP` proof.
    ///
    /// When a FAPI key is present, generates a DPoP proof bound to the access
    /// token hash and returns `("DPoP <token>", Some("<proof>"))`.
    /// If proof generation fails, falls back to `("Bearer <token>", None)`.
    ///
    /// When no FAPI key is present, returns `("Bearer <token>", None)`.
    fn build_auth(&self, method: &str, url: &str) -> Result<(String, Option<String>)> {
        let token = self.token()?;
        let token_str = token.expose_secret();

        if let Some(ref key) = self.fapi_key {
            match DpopProofBuilder::new(method, url)
                .access_token(token_str)
                .build(key)
            {
                Ok(proof) => {
                    tracing::debug!("Using DPoP auth for {method} {url} (kid={})", key.kid());
                    return Ok((format!("DPoP {token_str}"), Some(proof)));
                }
                Err(e) => {
                    // Non-fatal: fall through to Bearer auth.
                    // Warn rather than debug — Bearer fallback for a DPoP-bound
                    // token causes 401, so this is worth surfacing.
                    tracing::warn!(
                        "DPoP proof failed for {method} {url}, \
                         falling back to Bearer: {e}"
                    );
                }
            }
        } else {
            tracing::debug!("Using Bearer auth for {method} {url} (no FAPI key)");
        }

        Ok((format!("Bearer {token_str}"), None))
    }

    /// Build the full URL for a path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
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
                None,
            )
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// GET a JSON response with authentication.
    ///
    /// Uses `Authorization: DPoP <token>` with a bound `DPoP:` proof header
    /// when a FAPI client key is available; falls back to `Bearer` otherwise.
    pub async fn get_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("GET {} (authenticated)", url);

        let (auth, dpop_proof) = self.build_auth("GET", &url)?;

        let extra: Option<Vec<(&str, &str)>> = dpop_proof.as_deref().map(|p| vec![("DPoP", p)]);
        let extra_ref: Option<&[(&str, &str)]> = extra.as_deref();

        let response = self
            .http
            .request("GET", &url, None, None, Some(&auth), extra_ref)
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// DELETE with authentication.
    ///
    /// Uses `Authorization: DPoP <token>` with a bound `DPoP:` proof header
    /// when a FAPI client key is available; falls back to `Bearer` otherwise.
    pub async fn delete_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("DELETE {} (authenticated)", url);

        let (auth, dpop_proof) = self.build_auth("DELETE", &url)?;

        let extra: Option<Vec<(&str, &str)>> = dpop_proof.as_deref().map(|p| vec![("DPoP", p)]);
        let extra_ref: Option<&[(&str, &str)]> = extra.as_deref();

        let response = self
            .http
            .request("DELETE", &url, None, None, Some(&auth), extra_ref)
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// POST a JSON request with authentication and get a JSON response.
    ///
    /// Uses `Authorization: DPoP <token>` with a bound `DPoP:` proof header
    /// when a FAPI client key is available; falls back to `Bearer` otherwise.
    pub async fn post_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("POST {} (authenticated)", url);

        let (auth, dpop_proof) = self.build_auth("POST", &url)?;

        let json = serde_json::to_vec(body).context("failed to serialize request")?;

        let extra: Option<Vec<(&str, &str)>> = dpop_proof.as_deref().map(|p| vec![("DPoP", p)]);
        let extra_ref: Option<&[(&str, &str)]> = extra.as_deref();

        let response = self
            .http
            .request(
                "POST",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
                extra_ref,
            )
            .await
            .with_context(|| format!("failed to connect to {url}"))?;

        Self::handle_response(response)
    }

    /// PATCH a JSON request with authentication and get a JSON response.
    ///
    /// Uses `Authorization: DPoP <token>` with a bound `DPoP:` proof header
    /// when a FAPI client key is available; falls back to `Bearer` otherwise.
    pub async fn patch_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let url = self.url(path);
        tracing::debug!("PATCH {} (authenticated)", url);

        let (auth, dpop_proof) = self.build_auth("PATCH", &url)?;

        let json = serde_json::to_vec(body).context("failed to serialize request")?;

        let extra: Option<Vec<(&str, &str)>> = dpop_proof.as_deref().map(|p| vec![("DPoP", p)]);
        let extra_ref: Option<&[(&str, &str)]> = extra.as_deref();

        let response = self
            .http
            .request(
                "PATCH",
                &url,
                Some(&json),
                Some("application/json"),
                Some(&auth),
                extra_ref,
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
            401 => {
                // RFC 9470: Check for step-up authentication challenge
                if let Some(ref www_auth) = response.www_authenticate
                    && let Some(challenge) = parse_www_authenticate(www_auth)
                {
                    return Err(crate::exit_code::CliError::StepUpRequired {
                        acr_values: challenge.acr_values,
                        max_age: challenge.max_age,
                    }
                    .into());
                }
                // Log the server's reason — the error body often explains
                // why the token was rejected (e.g., DPoP binding mismatch).
                if !error_text.is_empty() {
                    tracing::warn!("Server rejected token (401): {error_text}");
                }
                Err(crate::exit_code::CliError::NotAuthenticated.into())
            }
            403 => Err(crate::exit_code::CliError::PermissionDenied.into()),
            _ => Err(format_http_error(status_code, &error_text)),
        }
    }
}

/// Load the FAPI client key for DPoP proof generation.
///
/// Checks sources in order:
/// 1. OS keychain (preferred — encrypted at rest)
/// 2. `~/.vouch/client_key.json` (legacy/fallback)
///
/// Returns `None` if no key is found. Never generates a new key — that
/// happens only in the enroll/login flows. This is intentionally non-fatal:
/// resource requests fall back to `Bearer` auth when no key is available.
fn load_fapi_key() -> Option<ClientKey> {
    // 1. Try the OS keychain first.
    match vouch_cli::fapi::key_store::load_from_keychain() {
        Ok(Some(key_file)) => match ClientKey::from_key_file(&key_file) {
            Ok(key) => {
                tracing::debug!("Loaded FAPI key from keychain: kid={}", key.kid());
                return Some(key);
            }
            Err(e) => {
                tracing::warn!("Keychain has FAPI key but it failed to parse: {e}");
            }
        },
        Ok(None) => {
            tracing::debug!("No FAPI key in keychain");
        }
        Err(e) => {
            tracing::warn!("Cannot access keychain for FAPI key: {e}");
        }
    }

    // 2. Fall back to disk.
    let home = dirs::home_dir()?;
    let key_path = home.join(".vouch").join("client_key.json");

    if !key_path.exists() {
        tracing::debug!("No FAPI key on disk at {}", key_path.display());
        return None;
    }

    match ClientKey::load(&key_path) {
        Ok(key) => {
            tracing::debug!("Loaded FAPI key from disk: kid={}", key.kid());
            Some(key)
        }
        Err(e) => {
            tracing::warn!("FAPI key exists on disk but failed to load: {e}");
            None
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::string_slice
)]
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

    #[test]
    fn test_handle_response_401_step_up_challenge() {
        let response = HttpResponse::with_www_authenticate(
            401,
            b"{}".to_vec(),
            Some("Bearer error=\"insufficient_user_authentication\", max_age=\"300\"".to_string()),
        );
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let cli_err = err.downcast_ref::<crate::exit_code::CliError>().unwrap();
        assert!(matches!(
            cli_err,
            crate::exit_code::CliError::StepUpRequired {
                max_age: Some(300),
                ..
            }
        ));
    }

    #[test]
    fn test_handle_response_401_without_step_up() {
        // Regular 401 without WWW-Authenticate → NotAuthenticated
        let response = HttpResponse::new(401, b"{}".to_vec());
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let cli_err = err.downcast_ref::<crate::exit_code::CliError>().unwrap();
        assert!(matches!(
            cli_err,
            crate::exit_code::CliError::NotAuthenticated
        ));
    }

    #[test]
    fn test_build_auth_without_fapi_key_returns_bearer() {
        let mut client = VouchClient::unauthenticated("https://example.com").unwrap();
        client.set_token(SecretString::from("my-token".to_string()));
        // No fapi_key set → always Bearer
        let (auth, proof) = client
            .build_auth("GET", "https://example.com/v1/keys")
            .unwrap();
        assert_eq!(auth, "Bearer my-token");
        assert!(proof.is_none());
    }

    #[test]
    fn test_build_auth_with_fapi_key_returns_dpop() {
        use vouch_cli::fapi::ClientKey;

        let mut client = VouchClient::unauthenticated("https://example.com").unwrap();
        client.set_token(SecretString::from("my-dpop-token".to_string()));
        client.fapi_key = Some(ClientKey::generate().unwrap());

        let (auth, proof) = client
            .build_auth("POST", "https://example.com/v1/keys")
            .unwrap();

        assert!(
            auth.starts_with("DPoP "),
            "auth should be DPoP scheme: {auth}"
        );
        assert_eq!(&auth["DPoP ".len()..], "my-dpop-token");
        assert!(proof.is_some(), "DPoP proof should be present");

        // The proof must be a valid 3-part JWT
        let proof_str = proof.unwrap();
        assert_eq!(proof_str.split('.').count(), 3, "DPoP proof must be a JWT");
    }

    #[test]
    fn test_build_auth_dpop_proof_contains_ath() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use vouch_cli::fapi::ClientKey;

        let mut client = VouchClient::unauthenticated("https://example.com").unwrap();
        client.set_token(SecretString::from("access-token-abc".to_string()));
        client.fapi_key = Some(ClientKey::generate().unwrap());

        let (_, proof) = client
            .build_auth("GET", "https://example.com/v1/keys")
            .unwrap();

        let proof_str = proof.unwrap();
        let parts: Vec<&str> = proof_str.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();

        // `ath` should be present (access token hash)
        assert!(claims.get("ath").is_some(), "DPoP claims must include ath");

        // Verify the ath value
        let expected_digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"access-token-abc");
        let expected_ath = URL_SAFE_NO_PAD.encode(expected_digest.as_ref());
        assert_eq!(claims["ath"].as_str().unwrap(), expected_ath);
    }
}
