// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center (SSO) OIDC device authorization flow.
//!
//! Implements the OAuth 2.0 Device Authorization Grant against AWS SSO OIDC
//! endpoints for obtaining SSO access tokens. Cached files are botocore-compatible
//! so existing AWS CLI sessions are reused.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vouch_common::aws::Partition;

/// SSO OIDC configuration for the device authorization flow.
pub(crate) struct SsoConfig {
    /// SSO start URL (e.g., "https://my-sso.awsapps.com/start").
    pub start_url: String,
    /// SSO region (e.g., "us-east-1").
    pub region: String,
    /// OAuth scopes (default: ["sso:account:access"]).
    pub scopes: Vec<String>,
    /// SSO session name from `[sso-session <name>]` in `~/.aws/config`.
    ///
    /// When present, the token cache key is `SHA1(session_name)` (modern AWS CLI behavior).
    /// When absent, falls back to `SHA1(start_url)` (legacy behavior).
    pub session_name: Option<String>,
}

impl SsoConfig {
    /// Create from an `SsoSession` parsed from `~/.aws/config`.
    pub(crate) fn from_session(session: &crate::integrations::aws::config::SsoSession) -> Self {
        Self {
            start_url: session.start_url.clone(),
            region: session.region.clone(),
            scopes: session.scopes.clone(),
            session_name: Some(session.name.clone()),
        }
    }
}

/// Cached SSO OIDC client registration (~90 day lifetime).
///
/// Stored in `~/.aws/sso/cache/{sha1}.json` with botocore-compatible format.
/// Note: `region` and `tool` are only used for the cache key hash — they are
/// NOT stored in the file itself.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoClientRegistration {
    pub client_id: String,
    pub client_secret: String,
    /// ISO 8601 expiry timestamp (e.g. `"2026-07-09T01:54:45Z"`).
    pub expires_at: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
}

impl SsoClientRegistration {
    /// Check whether this registration has expired.
    #[must_use]
    pub(crate) fn is_expired(&self) -> bool {
        match parse_sso_timestamp(&self.expires_at) {
            Ok(ts) => ts <= jiff::Timestamp::now(),
            Err(_) => true,
        }
    }
}

impl std::fmt::Debug for SsoClientRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoClientRegistration")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Serialize a `SecretString` as a plain string (required for on-disk cache format).
fn serialize_secret<S: Serializer>(s: &SecretString, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(s.expose_secret())
}

/// Deserialize a plain string into a `SecretString`.
fn deserialize_secret<'de, D: Deserializer<'de>>(de: D) -> Result<SecretString, D::Error> {
    let s = String::deserialize(de)?;
    Ok(SecretString::from(s))
}

/// Cached SSO access token (~8 hour lifetime).
///
/// Stored in `~/.aws/sso/cache/{sha1}.json` with botocore-compatible format.
/// Cache key is `SHA1(session_name)` for `[sso-session]` configs, or
/// `SHA1(start_url)` for legacy configs without a named session.
/// Unknown fields are silently ignored so future botocore additions round-trip safely.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SsoAccessToken {
    pub start_url: String,
    pub region: String,
    /// Access token — stored as plain string on disk but held as `SecretString` in memory.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub access_token: SecretString,
    /// ISO 8601 expiry of the access token (e.g. `"2026-04-10T02:54:49Z"`).
    pub expires_at: String,
    pub client_id: String,
    pub client_secret: String,
    /// ISO 8601 expiry of the client registration.
    pub registration_expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for SsoAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoAccessToken")
            .field("start_url", &self.start_url)
            .field("region", &self.region)
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("registration_expires_at", &self.registration_expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl SsoAccessToken {
    /// Check whether the access token has expired.
    ///
    /// Handles three botocore timestamp variants:
    /// - `"2024-01-15T18:30:45Z"` (standard ISO 8601)
    /// - `"2024-01-15T18:30:45UTC"` (botocore legacy)
    /// - `"2024-01-15T18:30:45+00:00"` (AWS CLI v2.15+)
    #[must_use]
    pub(crate) fn is_expired(&self) -> bool {
        match parse_sso_timestamp(&self.expires_at) {
            Ok(ts) => ts <= jiff::Timestamp::now(),
            Err(_) => true,
        }
    }

    /// Return the access token as a `SecretString`.
    pub(crate) fn token(&self) -> SecretString {
        self.access_token.clone()
    }
}

/// Parse an SSO timestamp, handling three format variants:
/// `"...Z"`, `"...UTC"`, and `"...+00:00"`.
///
/// Also handles microseconds: `"2024-01-15T18:30:45.123456UTC"`.
pub(crate) fn parse_sso_timestamp(s: &str) -> Result<jiff::Timestamp> {
    // Try standard ISO 8601 first (handles Z and +00:00)
    if let Ok(ts) = s.parse::<jiff::Timestamp>() {
        return Ok(ts);
    }

    // Strip trailing "UTC" suffix and retry
    if let Some(stripped) = s.strip_suffix("UTC") {
        // Handle optional microseconds: strip them and parse without
        let normalized = if let Some(dot_pos) = stripped.rfind('.') {
            // Check if the fractional part is all digits
            let frac = stripped.get(dot_pos + 1..).unwrap_or("");
            if frac.chars().all(|c| c.is_ascii_digit()) {
                // Remove fractional seconds — jiff handles "...T18:30:45" directly
                stripped.get(..dot_pos).unwrap_or(stripped).to_string()
            } else {
                stripped.to_string()
            }
        } else {
            stripped.to_string()
        };

        let with_z = format!("{normalized}Z");
        return with_z
            .parse::<jiff::Timestamp>()
            .with_context(|| format!("failed to parse SSO timestamp: {s}"));
    }

    Err(anyhow::anyhow!("unrecognized SSO timestamp format: {s}"))
}

/// Format a timestamp as ISO 8601 with `Z` suffix (botocore-compatible).
fn format_sso_timestamp(ts: jiff::Timestamp) -> String {
    let dt = ts.to_zoned(jiff::tz::TimeZone::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// SSO OIDC device authorization response.
pub(crate) struct DeviceAuth {
    /// Code to display to the user.
    pub user_code: String,
    /// URL for the user to open (without code, for display or fallback).
    #[allow(dead_code)]
    pub verification_uri: String,
    /// URL with code pre-filled (for `open::that()`).
    pub verification_uri_complete: String,
    /// Device code for polling.
    device_code: String,
    /// Polling interval in seconds.
    interval: u64,
    /// How long this auth is valid (seconds).
    expires_in: u64,
}

/// Error response from SSO OIDC endpoints.
#[derive(Deserialize)]
struct SsoOidcError {
    error: String,
    #[serde(rename = "error_description")]
    _description: Option<String>,
}

/// Serialize a JSON value using Python-compatible separators, recursively.
///
/// Python's `json.dumps(obj, sort_keys=True)` uses `(', ', ': ')` as separators
/// at every level. This produces `{"key": "value"}` and `["a", "b"]` rather than
/// `{"key":"value"}` and `["a","b"]`. The difference produces different SHA-1 hashes.
fn python_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            // Use serde_json's string escaping rather than reimplementing it.
            serde_json::to_string(v).unwrap_or_else(|_| format!("\"{s}\""))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(python_json_value).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(obj) => {
            // Sort keys to match Python's sort_keys=True.
            let mut pairs: Vec<String> = obj
                .iter()
                .map(|(k, val)| format!("\"{k}\": {}", python_json_value(val)))
                .collect();
            pairs.sort();
            format!("{{{}}}", pairs.join(", "))
        }
    }
}

/// Serialize a sorted `BTreeMap<&str, Value>` using Python-compatible separators.
///
/// Matches `json.dumps(obj, sort_keys=True)` exactly, including spaces inside arrays.
fn python_json_dumps(map: &BTreeMap<&str, serde_json::Value>) -> String {
    let pairs: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("\"{k}\": {}", python_json_value(v)))
        .collect();
    format!("{{{}}}", pairs.join(", "))
}

/// Compute the botocore-compatible SHA-1 hex cache key for client registration.
///
/// Matches `hashlib.sha1(json.dumps(obj, sort_keys=True).encode()).hexdigest()` in Python.
/// The JSON uses Python's default separators `(', ', ': ')`.
/// The `session_name` field is `null` for legacy configs or the session name string
/// for `[sso-session]` configs.
pub(crate) fn registration_cache_key(config: &SsoConfig) -> String {
    let mut obj: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    obj.insert("region", serde_json::json!(config.region));
    obj.insert("scopes", serde_json::json!(config.scopes));
    obj.insert(
        "session_name",
        match &config.session_name {
            Some(name) => serde_json::json!(name),
            None => serde_json::Value::Null,
        },
    );
    obj.insert("startUrl", serde_json::json!(config.start_url));
    obj.insert("tool", serde_json::json!("botocore"));

    let json_str = python_json_dumps(&obj);
    sha1_hex(json_str.as_bytes())
}

/// Compute the SHA-1 hex cache key for access tokens.
///
/// - With `[sso-session]`: `SHA1(session_name)` — e.g. `SHA1("smoketurner")`
/// - Legacy: `SHA1(start_url)`
fn token_cache_key(config: &SsoConfig) -> String {
    let input = config.session_name.as_deref().unwrap_or(&config.start_url);
    sha1_hex(input.as_bytes())
}

/// Compute SHA-1 hex digest of bytes.
fn sha1_hex(data: &[u8]) -> String {
    use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
    hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
}

/// Return the path to the SSO cache directory (`~/.aws/sso/cache/`).
fn sso_cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws").join("sso").join("cache"))
}

/// Load a cached SSO access token if present and not expired.
pub(crate) fn load_cached_token(config: &SsoConfig) -> Option<SsoAccessToken> {
    let cache_dir = sso_cache_dir().ok()?;
    let key = token_cache_key(config);
    let path = cache_dir.join(format!("{key}.json"));

    let content = std::fs::read_to_string(&path).ok()?;
    let token: SsoAccessToken = serde_json::from_str(&content).ok()?;

    if token.is_expired() {
        return None;
    }

    // Verify this token matches our SSO config
    if token.start_url != config.start_url {
        return None;
    }

    Some(token)
}

/// Load a cached SSO client registration if present and not expired.
fn load_cached_registration(
    cache_dir: &std::path::Path,
    key: &str,
) -> Option<SsoClientRegistration> {
    let path = cache_dir.join(format!("{key}.json"));
    let content = std::fs::read_to_string(&path).ok()?;
    let reg: SsoClientRegistration = serde_json::from_str(&content).ok()?;
    if reg.is_expired() {
        return None;
    }
    Some(reg)
}

/// Save an SSO client registration to cache with 0600 permissions.
fn save_registration(
    cache_dir: &std::path::Path,
    key: &str,
    reg: &SsoClientRegistration,
) -> Result<()> {
    crate::utils::ensure_secure_dir(cache_dir)?;
    let path = cache_dir.join(format!("{key}.json"));
    let content = serialize_python_compat(reg).context("failed to serialize registration")?;
    crate::utils::atomic_write_secure(&path, content.as_bytes())
        .context("failed to write SSO client registration cache")
}

/// Save an SSO access token to cache with 0600 permissions.
pub(crate) fn save_access_token(config: &SsoConfig, token: &SsoAccessToken) -> Result<()> {
    let cache_dir = sso_cache_dir()?;
    crate::utils::ensure_secure_dir(&cache_dir)?;
    let key = token_cache_key(config);
    let path = cache_dir.join(format!("{key}.json"));
    let content = serialize_python_compat(token).context("failed to serialize access token")?;
    crate::utils::atomic_write_secure(&path, content.as_bytes())
        .context("failed to write SSO access token cache")
}

/// Serialize a value to JSON with Python-compatible separators.
///
/// Python's `json.dumps()` uses `(', ', ': ')` as default separators,
/// producing `{"key": "value", ...}`. Rust's `serde_json::to_string()`
/// uses compact `{"key":"value",...}`. This function matches Python's
/// format while preserving struct field order (serde serializes fields
/// in declaration order).
fn serialize_python_compat<T: Serialize>(value: &T) -> Result<String> {
    // Serialize to compact JSON first (preserves struct field order),
    // then add spaces to match Python's default separators.
    let compact = serde_json::to_string(value).context("failed to serialize to JSON")?;
    // Post-process: add space after every `:` and `,` that's part of
    // JSON structure (not inside string values).
    Ok(add_python_json_spacing(&compact))
}

/// Add Python-compatible spacing to compact JSON.
///
/// Inserts a space after `:` and `,` that appear at the JSON structure
/// level (not inside quoted strings).
fn add_python_json_spacing(compact: &str) -> String {
    let mut result = String::with_capacity(compact.len() * 2);
    let mut in_string = false;
    let mut escape_next = false;

    for ch in compact.chars() {
        if escape_next {
            result.push(ch);
            escape_next = false;
            continue;
        }
        if ch == '\\' && in_string {
            result.push(ch);
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
        }
        result.push(ch);
        if !in_string && (ch == ':' || ch == ',') {
            result.push(' ');
        }
    }
    result
}

/// Register a new SSO OIDC client (or return cached registration).
pub(crate) async fn register_client(
    http_client: &reqwest::Client,
    config: &SsoConfig,
) -> Result<SsoClientRegistration> {
    let cache_dir = sso_cache_dir()?;
    let cache_key = registration_cache_key(config);

    if let Some(cached) = load_cached_registration(&cache_dir, &cache_key) {
        tracing::debug!("reusing cached SSO client registration");
        return Ok(cached);
    }

    let partition = Partition::from_region(&config.region);
    let oidc_endpoint = partition.sso_oidc_endpoint(&config.region);
    let url = format!("{oidc_endpoint}/client/register");

    let body = serde_json::json!({
        "clientName": "vouch-cli",
        "clientType": "public",
        "scopes": config.scopes,
    });

    let response = http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("failed to register SSO OIDC client")?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "SSO OIDC client registration failed {status}: {text}"
        ))
        .into());
    }

    // The AWS SSO OIDC RegisterClient API returns `clientSecretExpiresAt` as
    // an integer (Unix epoch seconds). We convert it to an ISO 8601 string
    // for the cache file (botocore-compatible format).
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RegisterResponse {
        client_id: String,
        client_secret: String,
        /// Epoch seconds from the API; converted to ISO 8601 for the cache file.
        client_secret_expires_at: i64,
    }

    let resp: RegisterResponse = response
        .json()
        .await
        .context("failed to parse SSO client registration response")?;

    let expires_at = jiff::Timestamp::from_second(resp.client_secret_expires_at)
        .context("invalid clientSecretExpiresAt from SSO OIDC RegisterClient")?;

    // scopes and grantTypes are not returned by the API — botocore
    // populates them from the request parameters before caching.
    let reg = SsoClientRegistration {
        client_id: resp.client_id,
        client_secret: resp.client_secret,
        expires_at: format_sso_timestamp(expires_at),
        scopes: config.scopes.clone(),
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
    };

    save_registration(&cache_dir, &cache_key, &reg)?;
    Ok(reg)
}

/// Start the device authorization flow.
pub(crate) async fn start_device_authorization(
    http_client: &reqwest::Client,
    config: &SsoConfig,
    registration: &SsoClientRegistration,
) -> Result<DeviceAuth> {
    let partition = Partition::from_region(&config.region);
    let oidc_endpoint = partition.sso_oidc_endpoint(&config.region);
    let url = format!("{oidc_endpoint}/device_authorization");

    let body = serde_json::json!({
        "clientId": registration.client_id,
        "clientSecret": registration.client_secret,
        "startUrl": config.start_url,
    });

    let response = http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("failed to start SSO device authorization")?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "SSO device authorization failed {status}: {text}"
        ))
        .into());
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DeviceAuthResponse {
        device_code: String,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: String,
        #[serde(default = "default_interval")]
        interval: u64,
        expires_in: u64,
    }

    fn default_interval() -> u64 {
        5
    }

    let resp: DeviceAuthResponse = response
        .json()
        .await
        .context("failed to parse SSO device authorization response")?;

    Ok(DeviceAuth {
        user_code: resp.user_code,
        verification_uri: resp.verification_uri,
        verification_uri_complete: resp.verification_uri_complete,
        device_code: resp.device_code,
        interval: resp.interval,
        expires_in: resp.expires_in,
    })
}

/// Poll for an SSO access token after the user completes authorization.
///
/// Returns the token when the user has authorized, or an error if:
/// - The user declined (`access_denied`)
/// - The authorization expired (`expired_token`)
/// - The device code expired
pub(crate) async fn poll_for_token(
    http_client: &reqwest::Client,
    config: &SsoConfig,
    registration: &SsoClientRegistration,
    device_auth: &DeviceAuth,
) -> Result<SsoAccessToken> {
    let partition = Partition::from_region(&config.region);
    let oidc_endpoint = partition.sso_oidc_endpoint(&config.region);
    let url = format!("{oidc_endpoint}/token");

    let mut interval_secs = device_auth.interval;
    let deadline = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            i64::try_from(device_auth.expires_in).unwrap_or(i64::MAX),
        ))
        .context("SSO device auth expiry overflow")?;

    // Safety cap: never loop more than 100 times regardless of expires_in
    let max_iterations: u32 = 100;
    let mut iteration: u32 = 0;

    loop {
        if jiff::Timestamp::now() >= deadline {
            return Err(crate::exit_code::CliError::NetworkError(
                "SSO device authorization timed out. Run 'vouch aws login' again.".to_string(),
            )
            .into());
        }

        if iteration >= max_iterations {
            return Err(crate::exit_code::CliError::NetworkError(
                "SSO device authorization polling limit reached.".to_string(),
            )
            .into());
        }
        iteration += 1;

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let body = serde_json::json!({
            "clientId": registration.client_id,
            "clientSecret": registration.client_secret,
            "deviceCode": device_auth.device_code,
            "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        });

        let response = http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("failed to poll SSO token endpoint")?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct TokenResponse {
                access_token: String,
                expires_in: u64,
                #[serde(default)]
                refresh_token: Option<String>,
            }

            let resp: TokenResponse = response
                .json()
                .await
                .context("failed to parse SSO token response")?;

            let expires_at = jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_secs(
                    i64::try_from(resp.expires_in).unwrap_or(i64::MAX),
                ))
                .context("SSO token expiry overflow")?;

            return Ok(SsoAccessToken {
                start_url: config.start_url.clone(),
                region: config.region.clone(),
                access_token: SecretString::from(resp.access_token),
                expires_at: format_sso_timestamp(expires_at),
                client_id: registration.client_id.clone(),
                client_secret: registration.client_secret.clone(),
                registration_expires_at: registration.expires_at.clone(),
                refresh_token: resp.refresh_token,
            });
        }

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();

        // Parse the error to decide whether to retry or fail
        let oidc_err: Option<SsoOidcError> = serde_json::from_str(&body_text).ok();
        let error_code = oidc_err.as_ref().map(|e| e.error.as_str()).unwrap_or("");

        match error_code {
            "authorization_pending" => {
                // Normal: user hasn't authorized yet — keep polling
                tracing::debug!("SSO authorization pending, polling again in {interval_secs}s");
            }
            "slow_down" => {
                // Server requesting slower polling
                interval_secs += 5;
                tracing::debug!("SSO slow_down: increasing interval to {interval_secs}s");
            }
            "access_denied" => {
                return Err(crate::exit_code::CliError::PermissionDenied(
                    "SSO authorization was denied.".to_string(),
                )
                .into());
            }
            "expired_token" => {
                return Err(crate::exit_code::CliError::NetworkError(
                    "SSO device code expired. Run 'vouch aws login' again.".to_string(),
                )
                .into());
            }
            _ => {
                return Err(crate::exit_code::CliError::NetworkError(format!(
                    "SSO token request failed {status}: {body_text}"
                ))
                .into());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::integrations::aws::config::SsoSession;

    fn make_session(name: &str, start_url: &str, region: &str) -> SsoSession {
        SsoSession {
            name: name.to_string(),
            start_url: start_url.to_string(),
            region: region.to_string(),
            scopes: vec!["sso:account:access".to_string()],
        }
    }

    #[test]
    fn test_registration_cache_key_deterministic() {
        let session = make_session(
            "my-session",
            "https://my-sso.awsapps.com/start",
            "us-east-1",
        );
        let config = SsoConfig::from_session(&session);

        // Key must be stable across calls
        let key1 = registration_cache_key(&config);
        let key2 = registration_cache_key(&config);
        assert_eq!(key1, key2);

        // Key is a 40-char hex string (SHA-1)
        assert_eq!(key1.len(), 40);
        assert!(key1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_registration_cache_key_differs_with_different_session_names() {
        let session_a = make_session("session-a", "https://my-sso.awsapps.com/start", "us-east-1");
        let session_b = make_session("session-b", "https://my-sso.awsapps.com/start", "us-east-1");
        let config_a = SsoConfig::from_session(&session_a);
        let config_b = SsoConfig::from_session(&session_b);
        // Different session names → different keys
        assert_ne!(
            registration_cache_key(&config_a),
            registration_cache_key(&config_b)
        );
    }

    #[test]
    fn test_token_cache_key_uses_session_name() {
        let session = make_session(
            "my-session",
            "https://my-sso.awsapps.com/start",
            "us-east-1",
        );
        let config = SsoConfig::from_session(&session);
        let key = token_cache_key(&config);
        assert_eq!(key, sha1_hex("my-session".as_bytes()));
        assert_eq!(key.len(), 40);
    }

    #[test]
    fn test_token_cache_key_smoketurner() {
        // Verified: SHA1("smoketurner") = c31a222de1424e1a089c046fba783f6e4fb5954c
        // This matches the user's real cache filename.
        let session = make_session(
            "smoketurner",
            "https://smoketurner.awsapps.com/start",
            "us-east-1",
        );
        let config = SsoConfig::from_session(&session);
        let key = token_cache_key(&config);
        assert_eq!(key, "c31a222de1424e1a089c046fba783f6e4fb5954c");
    }

    #[test]
    fn test_token_cache_key_legacy_uses_start_url() {
        // Legacy configs without a named [sso-session] use SHA1(start_url).
        // Verified: SHA1("https://my-sso.awsapps.com/start") matches botocore.
        let config = SsoConfig {
            start_url: "https://my-sso.awsapps.com/start".to_string(),
            region: "us-east-1".to_string(),
            scopes: vec!["sso:account:access".to_string()],
            session_name: None,
        };
        let key = token_cache_key(&config);
        // Key must be SHA1 of the start URL, not the session name
        assert_eq!(key, sha1_hex("https://my-sso.awsapps.com/start".as_bytes()));
        assert_eq!(key.len(), 40);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_token_cache_key_session_name_differs_from_start_url() {
        // The key with a session name must differ from the key computed from the start_url.
        let session = make_session(
            "my-session",
            "https://my-sso.awsapps.com/start",
            "us-east-1",
        );
        let named_config = SsoConfig::from_session(&session);
        let legacy_config = SsoConfig {
            start_url: "https://my-sso.awsapps.com/start".to_string(),
            region: "us-east-1".to_string(),
            scopes: vec!["sso:account:access".to_string()],
            session_name: None,
        };
        assert_ne!(
            token_cache_key(&named_config),
            token_cache_key(&legacy_config)
        );
    }

    #[test]
    fn test_python_json_dumps_single_scope() {
        // Verify exact string output matches Python's json.dumps(obj, sort_keys=True)
        let mut map = BTreeMap::new();
        map.insert("region", serde_json::json!("us-east-1"));
        map.insert("scopes", serde_json::json!(["sso:account:access"]));
        map.insert("session_name", serde_json::json!("test"));
        map.insert("startUrl", serde_json::json!("https://example.com/start"));
        map.insert("tool", serde_json::json!("botocore"));

        let out = python_json_dumps(&map);
        assert_eq!(
            out,
            r#"{"region": "us-east-1", "scopes": ["sso:account:access"], "session_name": "test", "startUrl": "https://example.com/start", "tool": "botocore"}"#
        );
    }

    #[test]
    fn test_python_json_dumps_multi_scope() {
        // Array items must also be separated with ", " to match Python
        let mut map = BTreeMap::new();
        map.insert("region", serde_json::json!("us-east-1"));
        map.insert(
            "scopes",
            serde_json::json!(["sso:account:access", "sso:other:scope"]),
        );
        map.insert("session_name", serde_json::json!("multi"));
        map.insert(
            "startUrl",
            serde_json::json!("https://example.awsapps.com/start"),
        );
        map.insert("tool", serde_json::json!("botocore"));

        let out = python_json_dumps(&map);
        assert_eq!(
            out,
            r#"{"region": "us-east-1", "scopes": ["sso:account:access", "sso:other:scope"], "session_name": "multi", "startUrl": "https://example.awsapps.com/start", "tool": "botocore"}"#
        );
    }

    #[test]
    fn test_registration_cache_key_multi_scope_golden() {
        // Golden hash for multi-scope config — verified with Python:
        // => "fffb192c213db6b8fee8752d8e12719f96a5f063"
        let session = SsoSession {
            name: "multi".to_string(),
            start_url: "https://example.awsapps.com/start".to_string(),
            region: "us-east-1".to_string(),
            scopes: vec![
                "sso:account:access".to_string(),
                "sso:other:scope".to_string(),
            ],
        };
        let config = SsoConfig::from_session(&session);
        assert_eq!(
            registration_cache_key(&config),
            "fffb192c213db6b8fee8752d8e12719f96a5f063"
        );
    }

    #[test]
    fn test_registration_cache_key_smoketurner_golden() {
        // Golden hash — verified with Python:
        // import json, hashlib
        // obj = {"region": "us-east-1", "scopes": ["sso:account:access"],
        //        "session_name": "smoketurner",
        //        "startUrl": "https://smoketurner.awsapps.com/start", "tool": "botocore"}
        // hashlib.sha1(json.dumps(obj, sort_keys=True).encode()).hexdigest()
        // => "a43c9cf4c32647e1c549c23ec7ac0ec48676a793"
        let session = make_session(
            "smoketurner",
            "https://smoketurner.awsapps.com/start",
            "us-east-1",
        );
        let config = SsoConfig::from_session(&session);
        assert_eq!(
            registration_cache_key(&config),
            "a43c9cf4c32647e1c549c23ec7ac0ec48676a793"
        );
    }

    #[test]
    fn test_registration_cache_key_null_session_name_golden() {
        // Golden hash for legacy configs (no [sso-session]) — verified with Python:
        // obj = {"region": "us-east-1", "scopes": ["sso:account:access"],
        //        "session_name": null,
        //        "startUrl": "https://my-sso.awsapps.com/start", "tool": "botocore"}
        // hashlib.sha1(json.dumps(obj, sort_keys=True).encode()).hexdigest()
        // => "86c5f58554531cd1231f5471537186f468344753"
        let config = SsoConfig {
            start_url: "https://my-sso.awsapps.com/start".to_string(),
            region: "us-east-1".to_string(),
            scopes: vec!["sso:account:access".to_string()],
            session_name: None,
        };
        assert_eq!(
            registration_cache_key(&config),
            "86c5f58554531cd1231f5471537186f468344753"
        );
    }

    #[test]
    fn test_client_registration_deserialization_real_format() {
        // Real botocore cache file format (verified against ~/.aws/sso/cache/*.json)
        let json = r#"{
            "clientId": "cBP-1Sc6dal96A6SKmYmoHVzLWVhc3QtMQ",
            "clientSecret": "eyJraWQi...(JWT)...",
            "expiresAt": "2026-07-09T01:54:45Z",
            "scopes": ["sso:account:access"],
            "grantTypes": ["authorization_code", "refresh_token"]
        }"#;
        let reg: SsoClientRegistration = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(reg.client_id, "cBP-1Sc6dal96A6SKmYmoHVzLWVhc3QtMQ");
        assert_eq!(reg.expires_at, "2026-07-09T01:54:45Z");
        assert_eq!(reg.scopes, vec!["sso:account:access"]);
        assert_eq!(reg.grant_types, vec!["authorization_code", "refresh_token"]);
        assert!(!reg.is_expired());
    }

    #[test]
    fn test_client_registration_deserialization_missing_optional_fields() {
        // Older botocore versions may omit grantTypes
        let json = r#"{
            "clientId": "abc123",
            "clientSecret": "secret",
            "expiresAt": "2024-01-01T00:00:00Z"
        }"#;
        let reg: SsoClientRegistration = serde_json::from_str(json).expect("valid JSON");
        assert!(reg.scopes.is_empty());
        assert!(reg.grant_types.is_empty());
        assert!(reg.is_expired());
    }

    #[test]
    fn test_parse_sso_timestamp_utc_suffix() {
        let ts = parse_sso_timestamp("2024-01-15T18:30:45UTC").unwrap();
        let expected = "2024-01-15T18:30:45Z".parse::<jiff::Timestamp>().unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_parse_sso_timestamp_z_suffix() {
        let ts = parse_sso_timestamp("2024-01-15T18:30:45Z").unwrap();
        let expected = "2024-01-15T18:30:45Z".parse::<jiff::Timestamp>().unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_parse_sso_timestamp_plus_offset() {
        let ts = parse_sso_timestamp("2024-01-15T18:30:45+00:00").unwrap();
        let expected = "2024-01-15T18:30:45Z".parse::<jiff::Timestamp>().unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_parse_sso_timestamp_microseconds_utc() {
        // botocore may write microseconds before UTC suffix
        let ts = parse_sso_timestamp("2024-01-15T18:30:45.123456UTC").unwrap();
        // Should parse to the second (microseconds stripped)
        let expected = "2024-01-15T18:30:45Z".parse::<jiff::Timestamp>().unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_parse_sso_timestamp_invalid() {
        assert!(parse_sso_timestamp("not-a-timestamp").is_err());
        assert!(parse_sso_timestamp("").is_err());
    }

    #[test]
    fn test_format_sso_timestamp_z_suffix() {
        let ts = "2024-01-15T18:30:45Z".parse::<jiff::Timestamp>().unwrap();
        let formatted = format_sso_timestamp(ts);
        assert_eq!(formatted, "2024-01-15T18:30:45Z");
    }

    #[test]
    fn test_format_sso_timestamp_round_trip() {
        let ts = "2024-06-20T12:00:00Z".parse::<jiff::Timestamp>().unwrap();
        let formatted = format_sso_timestamp(ts);
        let reparsed = parse_sso_timestamp(&formatted).unwrap();
        assert_eq!(ts, reparsed);
    }

    fn make_token(expires_at: String) -> SsoAccessToken {
        SsoAccessToken {
            start_url: "https://example.com/start".to_string(),
            region: "us-east-1".to_string(),
            access_token: SecretString::from("tok".to_string()),
            expires_at,
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            registration_expires_at: "2026-07-09T01:54:45Z".to_string(),
            refresh_token: None,
        }
    }

    #[test]
    fn test_access_token_is_expired() {
        let past = format_sso_timestamp(
            jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(3600))
                .unwrap(),
        );
        assert!(make_token(past).is_expired());
    }

    #[test]
    fn test_access_token_not_expired() {
        let future = format_sso_timestamp(
            jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_secs(3600))
                .unwrap(),
        );
        assert!(!make_token(future).is_expired());
    }

    #[test]
    fn test_access_token_invalid_expires_at_treated_as_expired() {
        assert!(make_token("invalid".to_string()).is_expired());
    }

    #[test]
    fn test_access_token_deserialization_real_format() {
        // Real botocore cache file format (verified against ~/.aws/sso/cache/*.json).
        // Uses a clearly-past expiresAt to avoid time-sensitivity in CI.
        let json = r#"{
            "startUrl": "https://smoketurner.awsapps.com/start",
            "region": "us-east-1",
            "accessToken": "aoaAAAAA...(long token)...",
            "expiresAt": "2024-01-01T00:00:00Z",
            "clientId": "cBP-1Sc6dal96A6SKmYmoHVzLWVhc3QtMQ",
            "clientSecret": "eyJraWQi...(JWT)...",
            "registrationExpiresAt": "2026-07-09T01:54:45Z",
            "refreshToken": "aorAAAAA...(long token)..."
        }"#;
        let token: SsoAccessToken = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(token.start_url, "https://smoketurner.awsapps.com/start");
        assert_eq!(token.region, "us-east-1");
        assert_eq!(
            token.access_token.expose_secret(),
            "aoaAAAAA...(long token)..."
        );
        assert_eq!(token.expires_at, "2024-01-01T00:00:00Z");
        assert_eq!(token.client_id, "cBP-1Sc6dal96A6SKmYmoHVzLWVhc3QtMQ");
        assert_eq!(token.registration_expires_at, "2026-07-09T01:54:45Z");
        assert!(token.refresh_token.is_some());
        assert!(token.is_expired());
    }

    #[test]
    fn test_add_python_json_spacing_with_colons_in_strings() {
        let input = r#"{"url":"https://a.com/b","note":"a,b:c"}"#;
        let expected = r#"{"url": "https://a.com/b", "note": "a,b:c"}"#;
        assert_eq!(add_python_json_spacing(input), expected);
    }

    #[test]
    fn test_add_python_json_spacing_nested_array() {
        let input = r#"{"scopes":["sso:account:access"]}"#;
        let expected = r#"{"scopes": ["sso:account:access"]}"#;
        assert_eq!(add_python_json_spacing(input), expected);
    }

    #[test]
    fn test_add_python_json_spacing_escaped_quotes() {
        let input = r#"{"key":"value with \"quotes\""}"#;
        let expected = r#"{"key": "value with \"quotes\""}"#;
        assert_eq!(add_python_json_spacing(input), expected);
    }

    #[test]
    fn test_access_token_deserialization_without_refresh_token() {
        // Older botocore versions may omit refreshToken
        let json = r#"{
            "startUrl": "https://example.awsapps.com/start",
            "region": "us-east-1",
            "accessToken": "tok",
            "expiresAt": "2099-01-01T00:00:00Z",
            "clientId": "client-id",
            "clientSecret": "secret",
            "registrationExpiresAt": "2099-06-01T00:00:00Z"
        }"#;
        let token: SsoAccessToken = serde_json::from_str(json).expect("valid JSON");
        assert!(token.refresh_token.is_none());
        assert!(!token.is_expired());
    }
}
