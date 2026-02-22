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
/// Implements `ZeroizeOnDrop` to clear sensitive data from memory.
#[derive(Debug, Default, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
struct ConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codeartifact: Option<CodeArtifactConfig>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("codeartifact", &self.codeartifact)
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

impl From<ConfigFile> for Config {
    fn from(mut file: ConfigFile) -> Self {
        // Use std::mem::take to move values out while leaving defaults behind.
        // This works with ZeroizeOnDrop because the struct will still be dropped
        // but with default (empty) values that will be zeroed.
        Self {
            server_url: std::mem::take(&mut file.server_url),
            token: std::mem::take(&mut file.token).map(SecretString::from),
            codeartifact: file.codeartifact.take(),
        }
    }
}

impl From<&Config> for ConfigFile {
    fn from(config: &Config) -> Self {
        Self {
            server_url: config.server_url.clone(),
            token: config.token.as_ref().map(|s| s.expose_secret().to_string()),
            codeartifact: config.codeartifact.clone(),
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
}
