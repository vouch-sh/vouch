// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Read-only configuration reader for `~/.vouch/config.json`.
//!
//! This module provides read-only access to the Vouch config file.
//! The agent uses this to recover session state on startup.
//! Only the CLI should write to this file.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Read-only view of the Vouch CLI configuration.
///
/// Deserialize-only — the agent must never write to `config.json`.
/// Supports both the multi-server format (with `current_server` +
/// `servers` map) and the legacy flat format (top-level `server_url`
/// + `token`).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct VouchConfig {
    /// Hostname of the currently active server (multi-server format).
    current_server: Option<String>,
    /// Per-server state, keyed by hostname (multi-server format).
    #[serde(default)]
    servers: BTreeMap<String, ServerEntry>,
    /// Legacy flat server URL.
    server_url: Option<String>,
    /// Legacy flat session token.
    token: Option<String>,
}

/// Read-only per-server entry within the config file.
#[derive(Debug, Default, Deserialize)]
struct ServerEntry {
    server_url: Option<String>,
    token: Option<String>,
}

impl VouchConfig {
    /// Resolve the active server URL.
    ///
    /// Checks the multi-server `servers` map first (via
    /// `current_server`), then falls back to the legacy flat
    /// `server_url` field.
    pub(crate) fn server_url(&self) -> Option<&str> {
        if let Some(host) = &self.current_server
            && let Some(entry) = self.servers.get(host)
            && let Some(url) = &entry.server_url
        {
            return Some(url.as_str());
        }
        self.server_url.as_deref()
    }

    /// Resolve the active session token.
    ///
    /// Checks the multi-server `servers` map first (via
    /// `current_server`), then falls back to the legacy flat
    /// `token` field.
    pub(crate) fn token(&self) -> Option<&str> {
        if let Some(host) = &self.current_server
            && let Some(entry) = self.servers.get(host)
            && let Some(tok) = &entry.token
        {
            return Some(tok.as_str());
        }
        self.token.as_deref()
    }
}

/// Get the path to the config file (`~/.vouch/config.json`).
fn config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".vouch").join("config.json"))
}

/// Read the config file from disk.
///
/// Returns `Ok(None)` if the file does not exist.
/// Returns an error if the file exists but cannot be read or parsed.
///
/// On Unix, rejects files that are group/other-readable (mode & 0o077 != 0).
pub(crate) fn read_config() -> Result<Option<VouchConfig>> {
    let path = config_path()?;

    if !path.exists() {
        return Ok(None);
    }

    // Reject files with overly permissive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to stat config file {}", path.display()))?;
        let mode = metadata.mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "config file {} has insecure permissions {:o} (expected 0600)",
                path.display(),
                mode & 0o777,
            );
        }
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config from {}", path.display()))?;

    let config: VouchConfig = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config from {}", path.display()))?;

    Ok(Some(config))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_config_path() {
        let path = config_path();
        assert!(path.is_ok());
        let path = path.expect("config_path should succeed");
        assert!(path.ends_with(".vouch/config.json"));
    }

    #[test]
    fn test_deserialize_legacy_flat_config() {
        let json = r#"{"server_url": "https://vouch.example.com", "token": "jwt-token"}"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
        assert_eq!(config.token(), Some("jwt-token"));
    }

    #[test]
    fn test_deserialize_multi_server_config() {
        let json = r#"{
            "current_server": "vouch.example.com",
            "servers": {
                "vouch.example.com": {
                    "server_url": "https://vouch.example.com",
                    "token": "jwt-token"
                }
            }
        }"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
        assert_eq!(config.token(), Some("jwt-token"));
    }

    #[test]
    fn test_deserialize_multi_server_with_port() {
        let json = r#"{
            "current_server": "localhost:3000",
            "servers": {
                "localhost:3000": {
                    "server_url": "http://localhost:3000",
                    "token": "dev-token"
                }
            }
        }"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.server_url(), Some("http://localhost:3000"));
        assert_eq!(config.token(), Some("dev-token"));
    }

    #[test]
    fn test_deserialize_empty_config() {
        let json = "{}";
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
    }

    #[test]
    fn test_deserialize_partial_config() {
        let json = r#"{"server_url": "https://vouch.example.com"}"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
        assert!(config.token().is_none());
    }

    #[test]
    fn test_multi_server_missing_current() {
        let json = r#"{
            "current_server": "missing.example.com",
            "servers": {
                "vouch.example.com": {
                    "server_url": "https://vouch.example.com",
                    "token": "jwt-token"
                }
            }
        }"#;
        let config: VouchConfig = serde_json::from_str(json).expect("should parse");
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
    }
}
