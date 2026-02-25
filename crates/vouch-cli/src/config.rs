// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration and token storage for vouch CLI.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// CLI configuration stored in ~/.vouch/config.json
///
/// Note: The token is stored as a plain string in the file for serialization purposes.
/// The config file is protected with 0600 permissions on Unix systems.
/// In memory, the token is wrapped in `SecretString` for protection and automatic
/// zeroing on drop.
#[derive(Default)]
pub struct Config {
    /// Vouch server URL.
    server_url: Option<String>,
    /// Current session token (JWT), protected in memory.
    token: Option<SecretString>,
    /// CodeArtifact profile configuration.
    codeartifact: Option<CodeArtifactConfig>,
    /// OAuth 2.0 client ID from dynamic registration (RFC 7591).
    client_id: Option<String>,
    /// OAuth 2.0 registration access token for managing the registration (RFC 7592).
    registration_access_token: Option<SecretString>,
    /// URI to manage the dynamic registration (RFC 7592).
    registration_client_uri: Option<String>,
    /// Key ID of the DPoP keypair stored in ~/.vouch/dpop_key.json.
    dpop_key_id: Option<String>,
}

/// CodeArtifact configuration with named profiles (similar to AWS CLI profiles).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CodeArtifactConfig {
    /// Name of the default profile (used when `--profile` is omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Named profiles, keyed by user-chosen name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, CodeArtifactProfile>,
}

/// A single CodeArtifact domain profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeArtifactProfile {
    /// CodeArtifact domain name.
    pub domain: String,
    /// AWS account ID that owns the domain.
    pub domain_owner: String,
    /// AWS region (e.g., "us-east-1").
    pub region: String,
}

/// Intermediate type for serialization/deserialization.
/// `SecretString` doesn't implement Serialize/Deserialize, so we use this.
/// This is a short-lived bridge between JSON on disk and the `Config` type
/// (which wraps the token in `SecretString`).
#[derive(Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codeartifact: Option<CodeArtifactConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_client_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dpop_key_id: Option<String>,
}

impl std::fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigFile")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("codeartifact", &self.codeartifact)
            .field("client_id", &self.client_id)
            .field(
                "registration_access_token",
                &self
                    .registration_access_token
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("registration_client_uri", &self.registration_client_uri)
            .field("dpop_key_id", &self.dpop_key_id)
            .finish()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("codeartifact", &self.codeartifact)
            .field("client_id", &self.client_id)
            .field(
                "registration_access_token",
                &self
                    .registration_access_token
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("registration_client_uri", &self.registration_client_uri)
            .field("dpop_key_id", &self.dpop_key_id)
            .finish()
    }
}

impl Config {
    /// Load configuration from disk, or return defaults if not found.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config from {}", path.display()))?;
            let config_file: ConfigFile = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse config from {}", path.display()))?;
            Ok(Self::from(config_file))
        } else {
            Ok(Self::default())
        }
    }

    /// Save configuration to disk.
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption
    /// if the process is interrupted mid-write.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        let config_file = ConfigFile::from(self);
        let content =
            serde_json::to_string_pretty(&config_file).context("failed to serialize config")?;

        crate::utils::atomic_write_secure(path.as_path(), content.as_bytes())
            .with_context(|| format!("failed to write config to {}", path.display()))?;

        Ok(())
    }

    /// Atomically load, modify, and save the config file under an advisory lock.
    ///
    /// This prevents concurrent processes from clobbering each other's changes.
    /// The lock is held for the entire load-modify-save cycle.
    #[cfg(unix)]
    pub fn modify(f: impl FnOnce(&mut Config)) -> Result<()> {
        let path = Self::config_path()?;
        let lock_path = path.with_extension("lock");

        // Ensure the directory exists before creating the lock file
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;

        // Restrict lock file permissions to owner-only (match config file)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
        }

        // Acquire exclusive advisory lock (blocks until available)
        crate::utils::flock_exclusive(&lock_file).context("failed to acquire config file lock")?;

        // Load, modify, save under the lock
        let mut config = Self::load()?;
        f(&mut config);
        config.save()?;

        // Lock is released when lock_file is dropped
        drop(lock_file);

        Ok(())
    }

    /// Atomically load, modify, and save the config file.
    ///
    /// Non-Unix fallback without advisory locking.
    #[cfg(not(unix))]
    pub fn modify(f: impl FnOnce(&mut Config)) -> Result<()> {
        let mut config = Self::load()?;
        f(&mut config);
        config.save()
    }

    /// Get the configured server URL.
    #[must_use]
    pub fn server_url(&self) -> Option<&str> {
        self.server_url.as_deref()
    }

    /// Get the current session token.
    ///
    /// Returns a reference to the `SecretString`. Use `.expose_secret()` to access
    /// the underlying string only when necessary (e.g., building HTTP headers).
    #[must_use]
    pub fn token(&self) -> Option<&SecretString> {
        self.token.as_ref()
    }

    /// Set the server URL (in memory only, call `save()` to persist).
    pub fn set_server_url(&mut self, url: &str) {
        self.server_url = Some(url.to_string());
    }

    /// Set a new session token (in memory only, call `save()` to persist).
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(SecretString::from(token.to_string()));
    }

    /// Clear the session token in memory (call `save()` to persist).
    pub fn clear_token(&mut self) {
        self.token = None;
    }

    /// Get the CodeArtifact configuration.
    #[must_use]
    pub fn codeartifact(&self) -> Option<&CodeArtifactConfig> {
        self.codeartifact.as_ref()
    }

    /// Add a CodeArtifact profile (in memory only, call `save()` to persist).
    /// If this is the first profile, it becomes the default.
    pub fn set_codeartifact_profile(&mut self, name: &str, profile: CodeArtifactProfile) {
        let ca = self
            .codeartifact
            .get_or_insert_with(CodeArtifactConfig::default);
        if ca.profiles.is_empty() && ca.default.is_none() {
            ca.default = Some(name.to_string());
        }
        ca.profiles.insert(name.to_string(), profile);
    }

    /// Get the path to the config file.
    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".vouch").join("config.json"))
    }
}

/// FAPI 2.0 dynamic registration fields.
///
/// These methods will be called by Phase 2 of the FAPI implementation.
/// The `dead_code` allow is needed until the registration command is implemented.
#[allow(dead_code)]
impl Config {
    // =========================================================================
    // FAPI 2.0 fields
    // =========================================================================

    /// Get the OAuth 2.0 client ID from dynamic registration (RFC 7591).
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Get the registration access token (RFC 7592).
    ///
    /// Used to update or delete the dynamic client registration.
    #[must_use]
    pub fn registration_access_token(&self) -> Option<&SecretString> {
        self.registration_access_token.as_ref()
    }

    /// Get the registration client URI (RFC 7592).
    #[must_use]
    pub fn registration_client_uri(&self) -> Option<&str> {
        self.registration_client_uri.as_deref()
    }

    /// Get the DPoP key ID for the stored client keypair.
    #[must_use]
    pub fn dpop_key_id(&self) -> Option<&str> {
        self.dpop_key_id.as_deref()
    }

    /// Set the OAuth 2.0 client ID (in memory only, call `save()` to persist).
    pub fn set_client_id(&mut self, client_id: &str) {
        self.client_id = Some(client_id.to_string());
    }

    /// Set the registration access token (in memory only, call `save()` to persist).
    pub fn set_registration_access_token(&mut self, token: &str) {
        self.registration_access_token = Some(SecretString::from(token.to_string()));
    }

    /// Set the registration client URI (in memory only, call `save()` to persist).
    pub fn set_registration_client_uri(&mut self, uri: &str) {
        self.registration_client_uri = Some(uri.to_string());
    }

    /// Set the DPoP key ID (in memory only, call `save()` to persist).
    pub fn set_dpop_key_id(&mut self, kid: &str) {
        self.dpop_key_id = Some(kid.to_string());
    }

    /// Clear all FAPI 2.0 dynamic registration fields.
    ///
    /// Clears `client_id`, `registration_access_token`, `registration_client_uri`,
    /// and `dpop_key_id`. Call `save()` to persist.
    pub fn clear_fapi(&mut self) {
        self.client_id = None;
        self.registration_access_token = None;
        self.registration_client_uri = None;
        self.dpop_key_id = None;
    }
}

impl From<ConfigFile> for Config {
    fn from(mut file: ConfigFile) -> Self {
        Self {
            server_url: std::mem::take(&mut file.server_url),
            token: std::mem::take(&mut file.token).map(SecretString::from),
            codeartifact: file.codeartifact.take(),
            client_id: std::mem::take(&mut file.client_id),
            registration_access_token: std::mem::take(&mut file.registration_access_token)
                .map(SecretString::from),
            registration_client_uri: std::mem::take(&mut file.registration_client_uri),
            dpop_key_id: std::mem::take(&mut file.dpop_key_id),
        }
    }
}

impl From<&Config> for ConfigFile {
    fn from(config: &Config) -> Self {
        Self {
            server_url: config.server_url.clone(),
            token: config.token.as_ref().map(|s| s.expose_secret().to_string()),
            codeartifact: config.codeartifact.clone(),
            client_id: config.client_id.clone(),
            registration_access_token: config
                .registration_access_token
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            registration_client_uri: config.registration_client_uri.clone(),
            dpop_key_id: config.dpop_key_id.clone(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_codeartifact_config_round_trip() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token",
            "codeartifact": {
                "default": "prod",
                "profiles": {
                    "prod": {
                        "domain": "my-domain",
                        "domain_owner": "123456789012",
                        "region": "us-east-1"
                    },
                    "staging": {
                        "domain": "staging-domain",
                        "domain_owner": "987654321098",
                        "region": "eu-west-1"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.server_url(), Some("https://vouch.example.com"));

        let ca = config
            .codeartifact()
            .expect("codeartifact config should exist");
        assert_eq!(ca.default.as_deref(), Some("prod"));
        assert_eq!(ca.profiles.len(), 2);

        let prod = ca.profiles.get("prod").expect("prod profile should exist");
        assert_eq!(prod.domain, "my-domain");
        assert_eq!(prod.domain_owner, "123456789012");
        assert_eq!(prod.region, "us-east-1");

        let staging = ca
            .profiles
            .get("staging")
            .expect("staging profile should exist");
        assert_eq!(staging.domain, "staging-domain");
        assert_eq!(staging.domain_owner, "987654321098");
        assert_eq!(staging.region, "eu-west-1");

        // Round-trip back to ConfigFile
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
        let config2 = Config::from(file3);

        assert_eq!(config2.server_url(), config.server_url());
        let ca2 = config2
            .codeartifact()
            .expect("round-tripped codeartifact config");
        assert_eq!(ca2.default, ca.default);
        assert_eq!(ca2.profiles.len(), ca.profiles.len());
    }

    #[test]
    fn test_config_without_codeartifact() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert!(config.codeartifact().is_none());

        // Round-trip should not add codeartifact field
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(!json2.contains("codeartifact"));
        assert!(!json2.contains("null"));
    }

    #[test]
    fn test_none_fields_omitted_from_serialization() {
        // A completely empty config should serialize to just "{}"
        let config = Config::default();
        let file = ConfigFile::from(&config);
        let json = serde_json::to_string(&file).unwrap();
        assert_eq!(json, "{}");
        assert!(!json.contains("null"));

        // Deserializing "{}" back should produce valid defaults
        let file2: ConfigFile = serde_json::from_str(&json).unwrap();
        let config2 = Config::from(file2);
        assert!(config2.server_url().is_none());
        assert!(config2.token().is_none());
        assert!(config2.codeartifact().is_none());
    }

    #[test]
    fn test_explicit_null_values_deserialize_as_none() {
        // Existing config files with explicit null values should still work
        let json = r#"{
            "server_url": null,
            "token": null,
            "codeartifact": null
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.codeartifact().is_none());
    }

    #[test]
    fn test_legacy_email_field_ignored() {
        // Old config files may still contain the email field; it should be silently ignored
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token",
            "email": "alice@example.com"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));

        // Round-trip should not include the email field
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(!json2.contains("email"));
    }

    #[test]
    fn test_empty_codeartifact_not_serialized() {
        let ca = CodeArtifactConfig::default();
        let json = serde_json::to_string(&ca).unwrap();
        // Empty profiles map should be omitted via skip_serializing_if
        assert!(!json.contains("profiles"));
    }

    #[test]
    fn test_set_codeartifact_profile_sets_default_for_first() {
        let mut config = Config::default();

        config.set_codeartifact_profile(
            "myteam",
            CodeArtifactProfile {
                domain: "team-domain".into(),
                domain_owner: "111111111111".into(),
                region: "us-west-2".into(),
            },
        );

        let ca = config
            .codeartifact()
            .expect("should have codeartifact config");
        assert_eq!(ca.default.as_deref(), Some("myteam"));
        assert_eq!(ca.profiles.len(), 1);
    }

    // =========================================================================
    // FAPI 2.0 field tests
    // =========================================================================

    #[test]
    fn test_fapi_fields_round_trip() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "client_id": "my-client-123",
            "registration_access_token": "reg-token-abc",
            "registration_client_uri": "https://vouch.example.com/register/my-client-123",
            "dpop_key_id": "abc123thumbprint"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.client_id(), Some("my-client-123"));
        assert_eq!(
            config.registration_client_uri(),
            Some("https://vouch.example.com/register/my-client-123")
        );
        assert_eq!(config.dpop_key_id(), Some("abc123thumbprint"));
        assert!(config.registration_access_token().is_some());

        // Round-trip
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(json2.contains("my-client-123"));
        assert!(json2.contains("abc123thumbprint"));
    }

    #[test]
    fn test_fapi_fields_absent_when_none() {
        let config = Config::default();
        let file = ConfigFile::from(&config);
        let json = serde_json::to_string(&file).unwrap();
        assert!(!json.contains("client_id"));
        assert!(!json.contains("registration_access_token"));
        assert!(!json.contains("registration_client_uri"));
        assert!(!json.contains("dpop_key_id"));
    }

    #[test]
    fn test_set_client_id() {
        let mut config = Config::default();
        assert!(config.client_id().is_none());
        config.set_client_id("test-client");
        assert_eq!(config.client_id(), Some("test-client"));
    }

    #[test]
    fn test_set_dpop_key_id() {
        let mut config = Config::default();
        config.set_dpop_key_id("my-kid");
        assert_eq!(config.dpop_key_id(), Some("my-kid"));
    }

    #[test]
    fn test_set_registration_access_token() {
        let mut config = Config::default();
        config.set_registration_access_token("secret-reg-token");
        assert!(config.registration_access_token().is_some());
    }

    #[test]
    fn test_set_registration_client_uri() {
        let mut config = Config::default();
        config.set_registration_client_uri("https://example.com/reg/123");
        assert_eq!(
            config.registration_client_uri(),
            Some("https://example.com/reg/123")
        );
    }

    #[test]
    fn test_clear_fapi() {
        let mut config = Config::default();
        config.set_client_id("c1");
        config.set_dpop_key_id("k1");
        config.set_registration_access_token("t1");
        config.set_registration_client_uri("https://example.com/reg");

        config.clear_fapi();

        assert!(config.client_id().is_none());
        assert!(config.dpop_key_id().is_none());
        assert!(config.registration_access_token().is_none());
        assert!(config.registration_client_uri().is_none());
    }

    #[test]
    fn test_clear_fapi_does_not_clear_token() {
        let mut config = Config::default();
        config.set_token("session-token");
        config.set_client_id("c1");

        config.clear_fapi();

        // Session token should be unaffected
        assert!(config.token().is_some());
        assert!(config.client_id().is_none());
    }

    #[test]
    fn test_registration_access_token_redacted_in_debug() {
        let mut config = Config::default();
        config.set_registration_access_token("super-secret-reg-token");
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret-reg-token"));
    }
}
