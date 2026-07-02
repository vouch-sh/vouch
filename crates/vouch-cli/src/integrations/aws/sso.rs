// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center (SSO) token cache.
//!
//! Provides read access to botocore-compatible SSO access token cache files
//! stored in `~/.aws/sso/cache/`. Retained for use by `setup aws --discover`
//! and future IdC credential flows (PR2+).

use std::path::PathBuf;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// SSO OIDC configuration for token cache lookups.
pub(crate) struct SsoConfig {
    /// SSO start URL (e.g., "https://my-sso.awsapps.com/start").
    pub start_url: String,
    /// SSO region (e.g., "us-east-1").
    #[expect(dead_code, reason = "retained for PR2 IdC credential flow")]
    pub region: String,
    /// OAuth scopes (default: ["sso:account:access"]).
    #[expect(dead_code, reason = "retained for PR2 IdC credential flow")]
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
            let frac = stripped.get(dot_pos.saturating_add(1)..).unwrap_or("");
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

/// Return the path to the SSO cache directory (`~/.aws/sso/cache/`).
fn sso_cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws").join("sso").join("cache"))
}

/// Compute SHA-1 hex digest of bytes.
fn sha1_hex(data: &[u8]) -> String {
    use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
    hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
}

/// Compute the SHA-1 hex cache key for access tokens.
///
/// - With `[sso-session]`: `SHA1(session_name)` — e.g. `SHA1("smoketurner")`
/// - Legacy: `SHA1(start_url)`
fn token_cache_key(config: &SsoConfig) -> String {
    let input = config.session_name.as_deref().unwrap_or(&config.start_url);
    sha1_hex(input.as_bytes())
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

    fn format_sso_timestamp_test(ts: jiff::Timestamp) -> String {
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

    #[test]
    fn test_access_token_is_expired() {
        let past = format_sso_timestamp_test(
            jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(3600))
                .unwrap(),
        );
        assert!(make_token(past).is_expired());
    }

    #[test]
    fn test_access_token_not_expired() {
        let future = format_sso_timestamp_test(
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
