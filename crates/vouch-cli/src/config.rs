// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration and token storage for vouch CLI.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
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
    /// User's email address (for session naming).
    email: Option<String>,
}

/// Intermediate type for serialization/deserialization.
/// `SecretString` doesn't implement Serialize/Deserialize, so we use this.
/// Implements `ZeroizeOnDrop` to clear sensitive data from memory.
#[derive(Debug, Default, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
struct ConfigFile {
    server_url: Option<String>,
    token: Option<String>,
    email: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("email", &self.email)
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
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory {}", parent.display())
            })?;
        }

        let config_file = ConfigFile::from(self);
        let content =
            serde_json::to_string_pretty(&config_file).context("failed to serialize config")?;

        // Write with restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            let mut file = options
                .open(&path)
                .with_context(|| format!("failed to create config file {}", path.display()))?;
            file.write_all(content.as_bytes())
                .with_context(|| format!("failed to write config to {}", path.display()))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, &content)
                .with_context(|| format!("failed to write config to {}", path.display()))?;
        }

        Ok(())
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

    /// Save the server URL.
    pub fn save_server_url(&mut self, url: &str) -> Result<()> {
        self.server_url = Some(url.to_string());
        self.save()
    }

    /// Save a new session token.
    pub fn save_token(&mut self, token: &str) -> Result<()> {
        self.token = Some(SecretString::from(token.to_string()));
        self.save()
    }

    /// Clear the session token (logout).
    pub fn clear_token(&mut self) -> Result<()> {
        self.token = None;
        self.save()
    }

    /// Get the user's email address.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Save the user's email address.
    pub fn save_email(&mut self, email: &str) -> Result<()> {
        self.email = Some(email.to_string());
        self.save()
    }

    /// Clear the user's email address.
    pub fn clear_email(&mut self) -> Result<()> {
        self.email = None;
        self.save()
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
            email: std::mem::take(&mut file.email),
        }
    }
}

impl From<&Config> for ConfigFile {
    fn from(config: &Config) -> Self {
        Self {
            server_url: config.server_url.clone(),
            token: config.token.as_ref().map(|s| s.expose_secret().to_string()),
            email: config.email.clone(),
        }
    }
}
