// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP client for communicating with vouch server.
//!
//! [`VouchClient`] is generic over [`HttpClient`](vouch_cli::http::HttpClient),
//! defaulting to [`ReqwestClient`](vouch_cli::http::ReqwestClient) for production use.
//! Tests can inject [`TestHttpClient`](vouch_cli::http::TestHttpClient) for in-process testing.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use vouch_cli::fapi::httpsig::ClientKeySigner;
use vouch_cli::fapi::{ClientKey, DpopProofBuilder};
use vouch_cli::http::{
    HttpClient, HttpResponse, ReqwestClient, format_http_error, parse_www_authenticate,
};
use vouch_cli::{tr, tr_args};

/// Parameters for building RFC 9421 HTTP signature headers.
struct SignRequestParams<'a> {
    method: &'a str,
    url: &'a str,
    auth_header: &'a str,
    dpop_proof: Option<&'a str>,
    content_type: Option<&'a str>,
    body: Option<&'a [u8]>,
    nonce: Option<&'a str>,
    key: &'a ClientKey,
}

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
pub(crate) struct VouchClient<H: HttpClient = ReqwestClient> {
    http: H,
    base_url: String,
    /// Authentication token. Set at construction for authenticated clients,
    /// `None` for unauthenticated clients (login/enroll flows).
    token: Option<SecretString>,
    /// FAPI 2.0 client key for DPoP proof generation on resource requests.
    /// `None` when FAPI infrastructure is not available.
    fapi_key: Option<ClientKey>,
    /// Server-issued nonce for RFC 9421 HTTP signature replay protection.
    /// Updated from the `Signature-Nonce` response header after each request.
    /// Uses `Mutex` for interior mutability (updated through `&self`).
    sig_nonce: std::sync::Mutex<Option<String>>,
    /// Optional source identifier embedded in DPoP proofs (custom claim).
    /// When set, the server uses this for credential attribution (e.g., AI tags).
    dpop_source: Option<String>,
}

impl VouchClient<ReqwestClient> {
    /// Create an authenticated client.
    ///
    /// Resolves the token once from the agent (if running) or config file.
    /// Also loads the FAPI client key from the OS keychain (or disk fallback)
    /// for DPoP proof generation on resource requests.
    ///
    /// This is the standard constructor for most commands.
    pub(crate) async fn new(base_url: &str) -> Result<Self> {
        let mut client = Self::unauthenticated(base_url)?;
        let token = crate::session::resolve_token().await?;
        client.token = Some(token);
        // Load the FAPI key for DPoP on resource endpoints (non-fatal).
        client.fapi_key = vouch_cli::fapi::key_store::load_client_key();
        Ok(client)
    }

    /// Create an authenticated client from an existing token.
    ///
    /// Used when a token is already available (e.g. after enrollment)
    /// without resolving from the agent or config file.
    pub(crate) fn with_token(base_url: &str, token: SecretString) -> Result<Self> {
        let http = ReqwestClient::new()?;
        let mut client = Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: Some(token),
            fapi_key: None,
            sig_nonce: std::sync::Mutex::new(None),
            dpop_source: None,
        };
        client.fapi_key = vouch_cli::fapi::key_store::load_client_key();
        Ok(client)
    }

    /// Create a client without authentication.
    ///
    /// Used only during login/enroll flows where the user doesn't have a
    /// token yet, and for health checks that don't require auth.
    pub(crate) fn unauthenticated(base_url: &str) -> Result<Self> {
        let http = ReqwestClient::new()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
            fapi_key: None,
            sig_nonce: std::sync::Mutex::new(None),
            dpop_source: None,
        })
    }

    /// Create an authenticated client from a resolved session.
    ///
    /// This is the standard pattern for credential commands that have already
    /// called `resolve_session()`.
    pub(crate) fn from_session(session: &crate::session::ResolvedSession) -> Result<Self> {
        let mut client = Self::unauthenticated(&session.server_url)?;
        client.token = Some(session.token.clone());
        // Load the FAPI key for DPoP on resource endpoints (non-fatal).
        client.fapi_key = vouch_cli::fapi::key_store::load_client_key();
        Ok(client)
    }

    /// Get a reference to the raw reqwest client.
    pub(crate) fn raw_client(&self) -> &reqwest::Client {
        self.http.inner()
    }
}

impl<H: HttpClient> VouchClient<H> {
    /// Set an explicit authentication token.
    ///
    /// Used when the caller has already resolved the token (e.g., from
    /// `resolve_session()`) and wants to avoid resolving it again.
    pub(crate) fn set_token(&mut self, token: SecretString) {
        self.token = Some(token);
    }

    /// Set the FAPI client key for DPoP proof generation.
    ///
    /// Used when the caller already has the key in memory (e.g., from
    /// the login flow) and wants to avoid reloading from the keychain.
    pub(crate) fn set_fapi_key(&mut self, key: ClientKey) {
        self.fapi_key = Some(key);
    }

    /// Set the credential source identifier for DPoP proofs.
    ///
    /// When set, this value is included as a `source` custom claim in
    /// DPoP proof JWTs (RFC 9449 §4.2 allows additional claims). The
    /// server extracts this to determine credential attribution (e.g.,
    /// adding AI session tags when an agent is detected).
    pub(crate) fn set_dpop_source(&mut self, source: &str) {
        self.dpop_source = Some(source.to_string());
    }

    /// Get the base URL.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the stored authentication token, or error if not authenticated.
    fn token(&self) -> Result<&SecretString> {
        self.token.as_ref().ok_or_else(|| {
            // Typed error so `exit_code::classify` maps it by type, not by
            // matching the (translatable) message string.
            crate::exit_code::CliError::NotAuthenticated {
                reason: tr!("client-err-not-authenticated"),
            }
            .into()
        })
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
            let mut builder = DpopProofBuilder::new(method, url).access_token(token_str);
            if let Some(ref source) = self.dpop_source {
                builder = builder.source(source);
            }
            match builder.build(key) {
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
                    eprintln!(
                        "Warning: DPoP proof generation failed ({e}). \
                         Authentication may fail if the server \
                         requires DPoP."
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

    /// Build RFC 9421 HTTP signature headers for a request.
    ///
    /// Signs the request using `ecdsa-p256-sha256` (RFC 9421 Section 3.3.4)
    /// covering `@method`, `@authority`, `@path`, `@query`, `authorization`,
    /// and `dpop` (when present). When a body is present, also covers
    /// `content-type` and `content-digest`.
    ///
    /// Returns the extra headers to add (Signature, Signature-Input, and
    /// optionally Content-Digest). Returns an empty vec if signing fails
    /// (non-fatal, similar to DPoP fallback).
    fn sign_request_headers(params: &SignRequestParams<'_>) -> Vec<(String, String)> {
        let signer = match ClientKeySigner::from_client_key(params.key) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("HTTP signature signer creation failed: {e}");
                crate::tr_eprintln!("httpsig-warn-create-failed", error = e.to_string());
                return Vec::new();
            }
        };

        // Build a temporary http::Request to sign
        let mut builder = http::Request::builder()
            .method(params.method)
            .uri(params.url)
            .header("authorization", params.auth_header);

        if let Some(proof) = params.dpop_proof {
            builder = builder.header("dpop", proof);
        }

        if let Some(ct) = params.content_type {
            builder = builder.header("content-type", ct);
        }

        let body_bytes = params.body.unwrap_or_default();
        let mut req = match builder.body(body_bytes.to_vec()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("HTTP signature request build failed: {e}");
                crate::tr_eprintln!("httpsig-warn-create-failed", error = e.to_string());
                return Vec::new();
            }
        };

        // Add Content-Digest for requests with a body (RFC 9530)
        if params.body.is_some()
            && let Err(e) = vouch_httpsig::digest::set_content_digest(
                req.headers_mut(),
                body_bytes,
                vouch_httpsig::DigestAlgorithm::Sha256,
            )
        {
            tracing::warn!("Content-Digest computation failed: {e}");
            crate::tr_eprintln!("httpsig-warn-create-failed", error = e.to_string());
            return Vec::new();
        }

        // Build the signature covering relevant components.
        // Includes @query to protect query parameters on GET requests
        // (e.g., /v1/credentials/aws/token?role_arn=...).
        let mut sig_builder = vouch_httpsig::SignatureBuilder::new("sig1")
            .method()
            .authority()
            .path()
            .query()
            .field("authorization")
            .created_now();

        // Include DPoP proof in signed components to cryptographically
        // link the HTTP signature and DPoP proof.
        if params.dpop_proof.is_some() {
            sig_builder = sig_builder.field("dpop");
        }

        if params.body.is_some() {
            sig_builder = sig_builder.field("content-type").field("content-digest");
        }

        // Include server-issued nonce for replay protection
        if let Some(n) = params.nonce {
            sig_builder = sig_builder.nonce(n);
        }

        if let Err(e) = sig_builder.sign_request(&mut req, &signer) {
            tracing::warn!("HTTP message signing failed: {e}");
            crate::tr_eprintln!("httpsig-warn-create-failed", error = e.to_string());
            return Vec::new();
        }

        // Extract the generated headers
        let mut headers = Vec::new();

        if let Some(v) = req.headers().get("signature-input")
            && let Ok(s) = v.to_str()
        {
            headers.push(("Signature-Input".to_string(), s.to_string()));
        }
        if let Some(v) = req.headers().get("signature")
            && let Ok(s) = v.to_str()
        {
            headers.push(("Signature".to_string(), s.to_string()));
        }
        if let Some(v) = req.headers().get("content-digest")
            && let Ok(s) = v.to_str()
        {
            headers.push(("Content-Digest".to_string(), s.to_string()));
        }

        if !headers.is_empty() {
            tracing::debug!(
                "Signed request with HTTP message signature (kid={})",
                params.key.kid()
            );
        }

        headers
    }

    /// Send an HTTP request with automatic retry on transient errors.
    ///
    /// Retries up to [`MAX_RETRIES`] times on 429 (using `Retry-After`)
    /// and 5xx (using exponential backoff with jitter). DPoP proofs are
    /// regenerated on each attempt when `auth` is `Auth::Authenticated`.
    async fn request_with_retry<Resp: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        auth: Auth,
    ) -> Result<Resp> {
        let url = self.url(path);
        tracing::debug!("{method} {url} ({auth})");

        // Consult the shared source-of-truth predicate for which vouch-server
        // `/v1` paths require an RFC 9421 HTTP signature.  This keeps the CLI
        // and the server middleware in sync — changing PUBLIC_V1_PATHS in
        // vouch-httpsig automatically updates both sides.  This predicate is
        // scoped to vouch-server traffic only; AWS/CodeArtifact/CodeCommit calls
        // that happen to start with "/v1" go through separate SigV4 paths and
        // never reach this code.
        let signature_required = vouch_httpsig::requires_signature(path);

        let mut attempt = 0;
        loop {
            let response = match auth {
                Auth::Authenticated => {
                    let (hdr, dpop_proof) = self.build_auth(method, &url)?;

                    // Collect all extra headers (DPoP proof + HTTP signature)
                    let mut extra_headers: Vec<(String, String)> = Vec::new();
                    if let Some(ref proof) = dpop_proof {
                        extra_headers.push(("DPoP".to_string(), proof.clone()));
                    }

                    // Sign with RFC 9421 HTTP message signatures when FAPI key is present
                    if let Some(ref key) = self.fapi_key {
                        let nonce = self.sig_nonce.lock().ok().and_then(|g| g.clone());
                        let sig_headers = Self::sign_request_headers(&SignRequestParams {
                            method,
                            url: &url,
                            auth_header: &hdr,
                            dpop_proof: dpop_proof.as_deref(),
                            content_type,
                            body,
                            nonce: nonce.as_deref(),
                            key,
                        });
                        if signature_required && !sig_headers.iter().any(|(k, _)| k == "Signature")
                        {
                            return Err(crate::exit_code::CliError::NotAuthenticated {
                                reason: tr_args!("httpsig-err-no-signature", path = path),
                            }
                            .into());
                        }
                        extra_headers.extend(sig_headers);
                    } else if signature_required {
                        return Err(crate::exit_code::CliError::NotAuthenticated {
                            reason: tr_args!("httpsig-err-key-unavailable", path = path),
                        }
                        .into());
                    }

                    let extra_refs: Vec<(&str, &str)> = extra_headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    let extra_slice = if extra_refs.is_empty() {
                        None
                    } else {
                        Some(extra_refs.as_slice())
                    };

                    self.http
                        .request(method, &url, body, content_type, Some(&hdr), extra_slice)
                        .await
                }
                Auth::None => {
                    self.http
                        .request(method, &url, body, content_type, None, None)
                        .await
                }
            }
            .with_context(|| format!("failed to connect to {url}"))?;

            // Capture server-issued nonce for the next request's HTTP signature
            if let Some(ref nonce) = response.sig_nonce
                && let Ok(mut guard) = self.sig_nonce.lock()
            {
                *guard = Some(nonce.clone());
            }

            match retry_delay(&response, attempt) {
                Some(wait) => {
                    tokio::time::sleep(wait).await;
                    attempt = attempt.saturating_add(1);
                }
                None => return Self::handle_response(response),
            }
        }
    }

    /// POST a form-encoded request and get a JSON response.
    /// Used for OAuth endpoints which require application/x-www-form-urlencoded.
    pub(crate) async fn post_form<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let form = serde_urlencoded::to_string(body).context("failed to serialize form data")?;
        self.request_with_retry(
            "POST",
            path,
            Some(form.as_bytes()),
            Some("application/x-www-form-urlencoded"),
            Auth::None,
        )
        .await
    }

    /// GET a JSON response with authentication.
    ///
    /// Uses DPoP when a FAPI client key is available; falls back to Bearer.
    pub(crate) async fn get_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        self.request_with_retry("GET", path, None, None, Auth::Authenticated)
            .await
    }

    /// DELETE with authentication.
    ///
    /// Uses DPoP when a FAPI client key is available; falls back to Bearer.
    pub(crate) async fn delete_authenticated<Resp>(&self, path: &str) -> Result<Resp>
    where
        Resp: DeserializeOwned,
    {
        self.request_with_retry("DELETE", path, None, None, Auth::Authenticated)
            .await
    }

    /// POST a JSON request with authentication and get a JSON response.
    ///
    /// Uses DPoP when a FAPI client key is available; falls back to Bearer.
    pub(crate) async fn post_authenticated<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let json = serde_json::to_vec(body).context("failed to serialize request")?;
        self.request_with_retry(
            "POST",
            path,
            Some(&json),
            Some("application/json"),
            Auth::Authenticated,
        )
        .await
    }

    /// PATCH a JSON request with authentication and get a JSON response.
    ///
    /// Uses DPoP when a FAPI client key is available; falls back to Bearer.
    pub(crate) async fn patch_authenticated<Req, Resp>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let json = serde_json::to_vec(body).context("failed to serialize request")?;
        self.request_with_retry(
            "PATCH",
            path,
            Some(&json),
            Some("application/json"),
            Auth::Authenticated,
        )
        .await
    }

    /// Handle HTTP response, parsing JSON or error.
    ///
    /// Classifies the HTTP status into a [`ServerErrorKind`] and
    /// converts to the appropriate [`CliError`](crate::exit_code::CliError).
    fn handle_response<Resp: DeserializeOwned>(response: HttpResponse) -> Result<Resp> {
        if response.is_success() {
            return response.json();
        }

        let kind = ServerErrorKind::from_response(&response);
        let error_text = response.text().unwrap_or_default();

        Err(kind.into_cli_error(&error_text))
    }
}

/// Whether a request carries authentication headers.
#[derive(Debug, Clone, Copy)]
enum Auth {
    Authenticated,
    None,
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated => f.write_str("authenticated"),
            Self::None => f.write_str("unauthenticated"),
        }
    }
}

/// Maximum number of retries for transient errors.
const MAX_RETRIES: u32 = 3;

/// Return the delay before the next retry attempt, or `None` if the
/// response is not retryable or retries are exhausted.
///
/// - **429**: waits for the `Retry-After` header (default 2s, cap 30s).
/// - **5xx**: exponential backoff with jitter (equal-jitter strategy).
/// - **Everything else**: not retryable.
fn retry_delay(response: &HttpResponse, attempt: u32) -> Option<std::time::Duration> {
    if attempt >= MAX_RETRIES {
        return None;
    }

    match response.status {
        429 => {
            let secs = response.retry_after.unwrap_or(2).min(30);
            eprintln!(
                "Rate limited by server, retrying in {secs}s \
                 (attempt {}/{MAX_RETRIES})...",
                attempt.saturating_add(1),
            );
            Some(std::time::Duration::from_secs(secs))
        }
        500..=599 => {
            let delay = backoff_with_jitter(attempt);
            eprintln!(
                "Server error ({}), retrying in {:.1}s \
                 (attempt {}/{MAX_RETRIES})...",
                response.status,
                delay.as_secs_f64(),
                attempt.saturating_add(1),
            );
            Some(delay)
        }
        _ => None,
    }
}

/// Compute an exponential backoff delay with equal jitter.
///
/// Uses the "equal jitter" strategy: `half + random(0, half)` where
/// `half = min(cap, base * 2^attempt) / 2`. This guarantees a minimum
/// wait of half the computed backoff while adding randomness to prevent
/// thundering-herd effects.
fn backoff_with_jitter(attempt: u32) -> std::time::Duration {
    const BASE_MS: u64 = 1_000;
    const CAP_MS: u64 = 30_000;

    let exp_ms = BASE_MS.saturating_mul(1_u64.checked_shl(attempt).unwrap_or(u64::MAX));
    let capped_ms = exp_ms.min(CAP_MS);
    // 2 is non-zero; unwrap_or arm is unreachable.
    let half_ms = capped_ms.checked_div(2).unwrap_or(0);

    let jitter_ms = random_u64_in_range(half_ms);

    std::time::Duration::from_millis(half_ms.saturating_add(jitter_ms))
}

/// Return a random `u64` in `0..=max` using `aws-lc-rs` CSPRNG.
fn random_u64_in_range(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut buf).is_err() {
        // 2 is non-zero; unwrap_or arm is unreachable.
        return max.checked_div(2).unwrap_or(0); // deterministic fallback
    }
    let value = u64::from_le_bytes(buf);
    match max.checked_add(1) {
        // checked_rem returns None only if modulus is 0; checked_add(1) is non-zero.
        Some(modulus) => value.checked_rem(modulus).unwrap_or(0),
        None => value, // max == u64::MAX: full range
    }
}

/// Classification of HTTP error responses from the server.
///
/// Maps HTTP status codes (and headers) into semantic categories
/// that convert to [`CliError`](crate::exit_code::CliError).
enum ServerErrorKind {
    /// 401 with RFC 9470 step-up challenge in `WWW-Authenticate`.
    StepUp {
        acr_values: Option<String>,
        max_age: Option<u64>,
    },
    /// 401 without step-up — token rejected or missing.
    Unauthorized,
    /// 403 — server denied the request.
    Forbidden,
    /// 429 — rate limited by server.
    RateLimited { retry_after: Option<u64> },
    /// Any other non-success status code.
    Other(u16),
}

impl ServerErrorKind {
    /// Classify an HTTP response into a `ServerErrorKind`.
    fn from_response(response: &HttpResponse) -> Self {
        match response.status {
            401 => {
                // RFC 9470: Check for step-up auth challenge.
                if let Some(ref www_auth) = response.www_authenticate
                    && let Some(challenge) = parse_www_authenticate(www_auth)
                {
                    return Self::StepUp {
                        acr_values: challenge.acr_values,
                        max_age: challenge.max_age,
                    };
                }
                Self::Unauthorized
            }
            403 => Self::Forbidden,
            429 => Self::RateLimited {
                retry_after: response.retry_after,
            },
            status => Self::Other(status),
        }
    }

    /// Convert into a `CliError` wrapped in `anyhow::Error`.
    ///
    /// Parses the response body as [`ApiError`](vouch_common::ApiError)
    /// to extract the server's reason when available.
    fn into_cli_error(self, error_text: &str) -> anyhow::Error {
        use crate::exit_code::CliError;

        match self {
            Self::StepUp {
                acr_values,
                max_age,
            } => CliError::StepUpRequired {
                acr_values,
                max_age,
            }
            .into(),
            Self::Unauthorized => {
                if !error_text.is_empty() {
                    tracing::warn!("Server rejected token (401): {error_text}");
                }
                let reason = if let Ok(api_err) =
                    serde_json::from_str::<vouch_common::ApiError>(error_text)
                {
                    format!("{} — run 'vouch login' to re-authenticate", api_err.message)
                } else if error_text.to_lowercase().contains("expired") {
                    "session expired — run 'vouch login' to \
                     re-authenticate"
                        .to_string()
                } else {
                    "not authenticated — run 'vouch login' first".to_string()
                };
                CliError::NotAuthenticated { reason }.into()
            }
            Self::Forbidden => {
                let reason = if let Ok(api_err) =
                    serde_json::from_str::<vouch_common::ApiError>(error_text)
                {
                    api_err.message
                } else if error_text.is_empty() {
                    "access denied by server".to_string()
                } else {
                    error_text.to_string()
                };
                CliError::PermissionDenied(reason).into()
            }
            Self::RateLimited { retry_after } => CliError::RateLimited { retry_after }.into(),
            Self::Other(status) => format_http_error(status, error_text),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "test code: panic on assertion failure is acceptable"
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
        let response = HttpResponse {
            status: 401,
            body: b"{}".to_vec(),
            www_authenticate: Some(
                "Bearer error=\"insufficient_user_authentication\", \
                 max_age=\"300\""
                    .to_string(),
            ),
            dpop_nonce: None,
            sig_nonce: None,
            retry_after: None,
        };
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
            crate::exit_code::CliError::NotAuthenticated { .. }
        ));
    }

    #[test]
    fn test_handle_response_429_returns_rate_limited() {
        let mut response = HttpResponse::new(429, b"{}".to_vec());
        response.retry_after = Some(5);
        let result: Result<serde_json::Value> =
            VouchClient::<ReqwestClient>::handle_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let cli_err = err.downcast_ref::<crate::exit_code::CliError>().unwrap();
        assert!(matches!(
            cli_err,
            crate::exit_code::CliError::RateLimited {
                retry_after: Some(5)
            }
        ));
    }

    #[test]
    fn test_retry_delay_returns_none_for_200() {
        let response = HttpResponse::new(200, b"{}".to_vec());
        assert!(retry_delay(&response, 0).is_none());
    }

    #[test]
    fn test_retry_delay_returns_none_for_401() {
        let response = HttpResponse::new(401, b"{}".to_vec());
        assert!(retry_delay(&response, 0).is_none());
    }

    #[test]
    fn test_retry_delay_429_uses_retry_after() {
        let mut response = HttpResponse::new(429, b"{}".to_vec());
        response.retry_after = Some(10);
        let duration = retry_delay(&response, 0).unwrap();
        assert_eq!(duration, std::time::Duration::from_secs(10));
    }

    #[test]
    fn test_retry_delay_429_caps_at_30_seconds() {
        let mut response = HttpResponse::new(429, b"{}".to_vec());
        response.retry_after = Some(120);
        let duration = retry_delay(&response, 0).unwrap();
        assert_eq!(duration, std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_retry_delay_429_defaults_to_2_seconds() {
        let response = HttpResponse::new(429, b"{}".to_vec());
        let duration = retry_delay(&response, 0).unwrap();
        assert_eq!(duration, std::time::Duration::from_secs(2));
    }

    #[test]
    fn test_retry_delay_5xx_uses_backoff() {
        let response = HttpResponse::new(502, b"{}".to_vec());
        let d0 = retry_delay(&response, 0).unwrap();
        // Attempt 0: base=1s, half=500ms, jitter 0..500ms → 500..1000ms
        assert!(d0 >= std::time::Duration::from_millis(500));
        assert!(d0 <= std::time::Duration::from_millis(1000));
    }

    #[test]
    fn test_retry_delay_5xx_increases_with_attempt() {
        let response = HttpResponse::new(500, b"{}".to_vec());
        // Run multiple times to account for jitter; minimum always increases
        // Attempt 0: min 500ms, Attempt 1: min 1000ms
        let d0_min = std::time::Duration::from_millis(500);
        let d1_min = std::time::Duration::from_millis(1000);
        assert!(retry_delay(&response, 0).unwrap() >= d0_min);
        assert!(retry_delay(&response, 1).unwrap() >= d1_min);
    }

    #[test]
    fn test_retry_delay_returns_none_when_retries_exhausted() {
        let response_429 = HttpResponse::new(429, b"{}".to_vec());
        assert!(retry_delay(&response_429, MAX_RETRIES).is_none());

        let response_500 = HttpResponse::new(500, b"{}".to_vec());
        assert!(retry_delay(&response_500, MAX_RETRIES).is_none());
    }

    #[test]
    fn test_retry_delay_allows_up_to_max_retries() {
        let response = HttpResponse::new(429, b"{}".to_vec());
        assert!(retry_delay(&response, 0).is_some());
        assert!(retry_delay(&response, 1).is_some());
        assert!(retry_delay(&response, 2).is_some());
        assert!(retry_delay(&response, 3).is_none());
    }

    #[test]
    fn test_backoff_with_jitter_bounded() {
        for attempt in 0..5 {
            let delay = backoff_with_jitter(attempt);
            assert!(delay <= std::time::Duration::from_secs(30));
        }
    }

    #[test]
    fn test_random_u64_in_range_zero() {
        assert_eq!(random_u64_in_range(0), 0);
    }

    #[test]
    fn test_random_u64_in_range_bounded() {
        for _ in 0..100 {
            assert!(random_u64_in_range(10) <= 10);
        }
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

    // =========================================================================
    // RFC 9421 HTTP Message Signature Tests
    // =========================================================================

    #[test]
    fn test_sign_request_headers_produces_signature_for_get() {
        let key = vouch_cli::fapi::ClientKey::generate().unwrap();
        let headers = VouchClient::<ReqwestClient>::sign_request_headers(&SignRequestParams {
            method: "GET",
            url: "https://example.com/v1/keys",
            auth_header: "DPoP my-token",
            dpop_proof: None,
            content_type: None,
            body: None,
            nonce: None,
            key: &key,
        });

        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            names.contains(&"Signature-Input"),
            "should have Signature-Input: {names:?}"
        );
        assert!(
            names.contains(&"Signature"),
            "should have Signature: {names:?}"
        );
        // No body → no Content-Digest
        assert!(
            !names.contains(&"Content-Digest"),
            "GET should not have Content-Digest"
        );
    }

    #[test]
    fn test_sign_request_headers_includes_content_digest_for_body() {
        let key = vouch_cli::fapi::ClientKey::generate().unwrap();
        let body = br#"{"key":"value"}"#;
        let headers = VouchClient::<ReqwestClient>::sign_request_headers(&SignRequestParams {
            method: "POST",
            url: "https://example.com/v1/credentials/ssh",
            auth_header: "DPoP my-token",
            dpop_proof: None,
            content_type: Some("application/json"),
            body: Some(body.as_slice()),
            nonce: None,
            key: &key,
        });

        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Signature-Input"));
        assert!(names.contains(&"Signature"));
        assert!(
            names.contains(&"Content-Digest"),
            "POST with body should have Content-Digest"
        );

        // Verify Content-Digest format
        let digest = headers
            .iter()
            .find(|(k, _)| k == "Content-Digest")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(
            digest.starts_with("sha-256=:"),
            "should be sha-256 digest: {digest}"
        );

        // Verify Signature-Input covers content-digest and content-type
        let sig_input = headers
            .iter()
            .find(|(k, _)| k == "Signature-Input")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(
            sig_input.contains("\"content-digest\""),
            "should cover content-digest: {sig_input}"
        );
        assert!(
            sig_input.contains("\"content-type\""),
            "should cover content-type: {sig_input}"
        );
    }

    #[test]
    fn test_sign_request_headers_covers_required_components() {
        let key = vouch_cli::fapi::ClientKey::generate().unwrap();
        let headers = VouchClient::<ReqwestClient>::sign_request_headers(&SignRequestParams {
            method: "GET",
            url: "https://example.com/v1/keys",
            auth_header: "Bearer my-token",
            dpop_proof: None,
            content_type: None,
            body: None,
            nonce: None,
            key: &key,
        });

        let sig_input = headers
            .iter()
            .find(|(k, _)| k == "Signature-Input")
            .map(|(_, v)| v.as_str())
            .unwrap();

        assert!(sig_input.contains("\"@method\""), "should cover @method");
        assert!(
            sig_input.contains("\"@authority\""),
            "should cover @authority"
        );
        assert!(sig_input.contains("\"@path\""), "should cover @path");
        assert!(
            sig_input.contains("\"authorization\""),
            "should cover authorization"
        );
        assert!(
            sig_input.contains("alg=\"ecdsa-p256-sha256\""),
            "should use ecdsa-p256-sha256: {sig_input}"
        );
        assert!(
            sig_input.contains(&format!("keyid=\"{}\"", key.kid())),
            "should include keyid"
        );
    }
}
