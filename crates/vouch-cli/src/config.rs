// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration and token storage for vouch CLI.
//!
//! Config is scoped per server hostname so multiple servers
//! (us.vouch.sh, dev.vouch.sh, localhost:3000) coexist without
//! stale registrations causing `invalid_client` errors.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use vouch_common::dns::DohConfigSerde;

/// AWS multi-account configuration in ~/.vouch/config.json.
///
/// Keyed by SSO session name (matching `[sso-session <name>]` in `~/.aws/config`).
/// SSO connection details (start URL, region, scopes) are read from `~/.aws/config`
/// — only role chaining config lives here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct AwsMultiAccountConfig {
    /// Per-SSO-session role chaining configuration, keyed by session name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sso_sessions: BTreeMap<String, SsoSessionConfig>,
}

/// Per-SSO-session configuration for role chaining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SsoSessionConfig {
    /// Management account role ARN (Vouch OIDC trust deployed here).
    pub management_role: String,
    /// Role name to assume in member accounts.
    #[serde(default = "default_member_role_name")]
    pub member_role_name: String,
    /// IAM Path of the member-account role, always canonical (starts and
    /// ends with `/`, e.g. `/teams/sec/`; `/` means no path). User input is
    /// normalized at deserialization via [`normalize_member_role_path`].
    #[serde(
        default = "default_member_role_path",
        deserialize_with = "deserialize_member_role_path"
    )]
    pub member_role_path: String,
}

impl Default for SsoSessionConfig {
    fn default() -> Self {
        Self {
            management_role: String::new(),
            member_role_name: default_member_role_name(),
            member_role_path: default_member_role_path(),
        }
    }
}

impl SsoSessionConfig {
    /// Build the assumable member-account role ARN for the given account.
    pub(crate) fn role_arn_in(&self, partition: &str, account_id: &str) -> String {
        format!(
            "arn:{partition}:iam::{account_id}:role{path}{name}",
            path = self.member_role_path,
            name = self.member_role_name,
        )
    }
}

fn default_member_role_name() -> String {
    "VouchAccess".to_string()
}

fn default_member_role_path() -> String {
    "/".to_string()
}

fn deserialize_member_role_path<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    normalize_member_role_path(&raw).map_err(serde::de::Error::custom)
}

/// Normalize an IAM Path string so it starts and ends with `/`.
///
/// Accepts forms like `""`, `"/"`, `"teams/sec"`, `"/teams/sec"`,
/// `"teams/sec/"`, `"/teams/sec/"` and returns `/teams/sec/` (or `/` for
/// the empty/root case). Rejects whitespace and embedded ARN fragments.
pub(crate) fn normalize_member_role_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok("/".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        anyhow::bail!("member_role_path must not contain whitespace: {raw:?}");
    }
    if trimmed.contains("//") {
        anyhow::bail!("member_role_path must not contain empty segments: {raw:?}");
    }
    if trimmed.contains(':') || trimmed.contains("arn:") {
        anyhow::bail!("member_role_path must be a path, not an ARN: {raw:?}");
    }
    let with_leading = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    let canonical = if with_leading.ends_with('/') {
        with_leading
    } else {
        format!("{with_leading}/")
    };
    Ok(canonical)
}

/// CLI configuration stored in ~/.vouch/config.json
///
/// Per-server state (token, client_id, registration, DPoP key) is
/// stored under `servers`, keyed by hostname. Global state (CodeArtifact
/// profiles) lives at the top level.
///
/// The config file is protected with 0600 permissions on Unix systems.
#[derive(Default)]
pub(crate) struct Config {
    /// Hostname of the currently active server.
    current_server: Option<String>,
    /// Per-server state, keyed by hostname (e.g. "us.vouch.sh").
    servers: BTreeMap<String, ServerConfig>,
    /// Global CodeArtifact profile configuration.
    codeartifact: Option<CodeArtifactConfig>,
    /// AWS multi-account configuration (role chaining + SSO discovery).
    aws: Option<AwsMultiAccountConfig>,
    /// Global network configuration (DoH, …).
    network: Option<NetworkConfig>,
}

/// Global network options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct NetworkConfig {
    /// DNS-over-HTTPS provider. Accepts a boolean (`true` = Google, `false`
    /// = off), a keyword (`off`, `google`, `cloudflare`, `quad9`), or a
    /// custom `https://…/dns-query` URL. Overridden at runtime by the
    /// `VOUCH_DOH` env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_over_https: Option<DohConfigSerde>,
}

/// Per-server configuration state.
#[derive(Default, Clone)]
pub(crate) struct ServerConfig {
    /// Full server URL (e.g. "https://us.vouch.sh").
    server_url: String,
    /// Current session token (JWT), protected in memory.
    token: Option<SecretString>,
    /// OAuth 2.0 client ID from dynamic registration (RFC 7591).
    client_id: Option<String>,
    /// OAuth 2.0 registration access token (RFC 7592).
    registration_access_token: Option<SecretString>,
    /// URI to manage the dynamic registration (RFC 7592).
    registration_client_uri: Option<String>,
    /// Key ID of the DPoP keypair stored in ~/.vouch/dpop_key.json.
    dpop_key_id: Option<String>,
    /// ISO 8601 timestamp of last successful registration verification.
    registration_verified_at: Option<String>,
}

/// CodeArtifact configuration with named profiles (similar to AWS CLI profiles).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct CodeArtifactConfig {
    /// Name of the default profile (used when `--profile` is omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Named profiles, keyed by user-chosen name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, CodeArtifactProfile>,
}

/// A single CodeArtifact domain profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CodeArtifactProfile {
    /// CodeArtifact domain name.
    pub domain: String,
    /// AWS account ID that owns the domain.
    pub domain_owner: String,
    /// AWS region (e.g., "us-east-1").
    pub region: String,
}

// =========================================================================
// On-disk format (ConfigFile)
// =========================================================================

/// On-disk representation with per-server scoping.
///
/// Supports reading legacy flat configs (pre-scoping) via the
/// `#[serde(default)]` fields. Legacy fields are read but never
/// written back — the first save migrates to the new format.
#[derive(Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_server: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    servers: BTreeMap<String, ServerConfigFile>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    codeartifact: Option<CodeArtifactConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws: Option<AwsMultiAccountConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<NetworkConfig>,

    // Legacy flat fields — read for migration, never written back.
    #[serde(default, skip_serializing)]
    server_url: Option<String>,
    #[serde(default, skip_serializing)]
    token: Option<String>,
    #[serde(default, skip_serializing)]
    client_id: Option<String>,
    #[serde(default, skip_serializing)]
    registration_access_token: Option<String>,
    #[serde(default, skip_serializing)]
    registration_client_uri: Option<String>,
    #[serde(default, skip_serializing)]
    dpop_key_id: Option<String>,
}

/// On-disk per-server config entry.
#[derive(Default, Serialize, Deserialize)]
struct ServerConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_client_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dpop_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_verified_at: Option<String>,
}

// =========================================================================
// Debug impls (redact secrets)
// =========================================================================

impl std::fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigFile")
            .field("current_server", &self.current_server)
            .field("servers", &"[...]")
            .field("codeartifact", &self.codeartifact)
            .field("aws", &self.aws)
            .field("network", &self.network)
            .finish()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("current_server", &self.current_server)
            .field("servers", &self.servers.keys().collect::<Vec<_>>())
            .field("codeartifact", &self.codeartifact)
            .field("aws", &self.aws)
            .field("network", &self.network)
            .finish()
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
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
            .field("registration_verified_at", &self.registration_verified_at)
            .finish()
    }
}

// =========================================================================
// Hostname extraction
// =========================================================================

/// Extract the hostname key from a server URL.
///
/// Returns `host` for standard ports (443/80), or `host:port` for
/// non-standard ports (e.g. `localhost:3000`).
pub(crate) fn hostname_from_url(url_str: &str) -> Result<String> {
    let parsed =
        url::Url::parse(url_str).with_context(|| format!("invalid server URL: {url_str}"))?;

    let host = parsed.host_str().context("server URL has no host")?;

    match parsed.port() {
        Some(port) if !is_standard_port(parsed.scheme(), port) => Ok(format!("{host}:{port}")),
        _ => Ok(host.to_string()),
    }
}

/// Whether a port is the standard port for its scheme.
fn is_standard_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("https", 443) | ("http", 80))
}

// =========================================================================
// Core Config impl
// =========================================================================

impl Config {
    /// Load configuration from disk, or return defaults if not found.
    pub(crate) fn load() -> Result<Self> {
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
    pub(crate) fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        let config_file = ConfigFile::from(self);
        let content =
            serde_json::to_string_pretty(&config_file).context("failed to serialize config")?;

        crate::utils::atomic_write_secure(path.as_path(), content.as_bytes())
            .with_context(|| format!("failed to write config to {}", path.display()))?;

        Ok(())
    }

    /// Atomically load, modify, and save the config file under an
    /// advisory lock.
    ///
    /// This prevents concurrent processes from clobbering each
    /// other's changes. The lock is held for the entire
    /// load-modify-save cycle.
    #[cfg(unix)]
    pub(crate) fn modify(f: impl FnOnce(&mut Config)) -> Result<()> {
        let path = Self::config_path()?;
        let lock_path = path.with_extension("lock");

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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort tightening of lock file permissions.
            let _chmod =
                std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
        }

        crate::utils::flock_exclusive(&lock_file).context("failed to acquire config file lock")?;

        let mut config = Self::load()?;
        f(&mut config);
        config.save()?;

        drop(lock_file);

        Ok(())
    }

    /// Atomically load, modify, and save the config file.
    ///
    /// Non-Unix fallback without advisory locking.
    #[cfg(not(unix))]
    pub(crate) fn modify(f: impl FnOnce(&mut Config)) -> Result<()> {
        let mut config = Self::load()?;
        f(&mut config);
        config.save()
    }

    // =====================================================================
    // Network
    // =====================================================================

    /// Configured DoH provider, if any.
    pub(crate) fn doh(&self) -> Option<&DohConfigSerde> {
        self.network
            .as_ref()
            .and_then(|n| n.dns_over_https.as_ref())
    }

    // =====================================================================
    // Server context
    // =====================================================================

    /// Set the server URL and make it the current server context.
    ///
    /// Extracts the hostname, sets `current_server`, and ensures a
    /// `ServerConfig` entry exists. If this is a new hostname, a fresh
    /// entry is created with the full URL stored.
    pub(crate) fn set_server_url(&mut self, url: &str) {
        if let Ok(hostname) = hostname_from_url(url) {
            self.current_server = Some(hostname.clone());
            let entry = self.servers.entry(hostname).or_default();
            entry.server_url = url.to_string();
        }
    }

    /// Get a reference to the current server's config, if any.
    fn current(&self) -> Option<&ServerConfig> {
        self.current_server
            .as_ref()
            .and_then(|h| self.servers.get(h))
    }

    /// Get a mutable reference to the current server's config, if any.
    fn current_mut(&mut self) -> Option<&mut ServerConfig> {
        self.current_server
            .as_ref()
            .and_then(|h| self.servers.get_mut(h))
    }

    // =====================================================================
    // Per-server accessors (delegate to current ServerConfig)
    // =====================================================================

    /// Get the configured server URL (from the current server context).
    #[must_use]
    pub(crate) fn server_url(&self) -> Option<&str> {
        self.current().map(|s| s.server_url.as_str())
    }

    /// Get the current session token.
    #[must_use]
    pub(crate) fn token(&self) -> Option<&SecretString> {
        self.current().and_then(|s| s.token.as_ref())
    }

    /// Set a new session token (in memory only, call `save()` to persist).
    pub(crate) fn set_token(&mut self, token: &str) {
        if let Some(sc) = self.current_mut() {
            sc.token = Some(SecretString::from(token.to_string()));
        }
    }

    /// Clear the session token in memory (call `save()` to persist).
    pub(crate) fn clear_token(&mut self) {
        if let Some(sc) = self.current_mut() {
            sc.token = None;
        }
    }

    // =====================================================================
    // CodeArtifact (global, not per-server)
    // =====================================================================

    /// Get the CodeArtifact configuration.
    #[must_use]
    pub(crate) fn codeartifact(&self) -> Option<&CodeArtifactConfig> {
        self.codeartifact.as_ref()
    }

    /// Add a CodeArtifact profile (in memory only, call `save()` to
    /// persist). If this is the first profile, it becomes the default.
    pub(crate) fn set_codeartifact_profile(&mut self, name: &str, profile: CodeArtifactProfile) {
        let ca = self
            .codeartifact
            .get_or_insert_with(CodeArtifactConfig::default);
        if ca.profiles.is_empty() && ca.default.is_none() {
            ca.default = Some(name.to_string());
        }
        ca.profiles.insert(name.to_string(), profile);
    }

    // =====================================================================
    // AWS multi-account (global, not per-server)
    // =====================================================================

    /// Get the AWS multi-account configuration.
    #[must_use]
    pub(crate) fn aws(&self) -> Option<&AwsMultiAccountConfig> {
        self.aws.as_ref()
    }

    /// Set the AWS multi-account configuration (in memory only, call `save()` to persist).
    #[allow(
        dead_code,
        reason = "API exposed for callers; lint fires inconsistently across compilation targets"
    )]
    pub(crate) fn set_aws(&mut self, config: AwsMultiAccountConfig) {
        self.aws = Some(config);
    }

    /// Get the path to the config file.
    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".vouch").join("config.json"))
    }
}

/// FAPI 2.0 dynamic registration fields (RFC 7591/7592).
impl Config {
    /// Get the OAuth 2.0 client ID from dynamic registration.
    #[must_use]
    pub(crate) fn client_id(&self) -> Option<&str> {
        self.current().and_then(|s| s.client_id.as_deref())
    }

    /// Get the registration access token (RFC 7592).
    #[must_use]
    pub(crate) fn registration_access_token(&self) -> Option<&SecretString> {
        self.current()
            .and_then(|s| s.registration_access_token.as_ref())
    }

    /// Get the registration client URI (RFC 7592).
    #[must_use]
    pub(crate) fn registration_client_uri(&self) -> Option<&str> {
        self.current()
            .and_then(|s| s.registration_client_uri.as_deref())
    }

    /// Get the DPoP key ID for the stored client keypair.
    #[must_use]
    pub(crate) fn dpop_key_id(&self) -> Option<&str> {
        self.current().and_then(|s| s.dpop_key_id.as_deref())
    }

    /// Set the OAuth 2.0 client ID.
    pub(crate) fn set_client_id(&mut self, client_id: &str) {
        if let Some(sc) = self.current_mut() {
            sc.client_id = Some(client_id.to_string());
        }
    }

    /// Set the registration access token.
    pub(crate) fn set_registration_access_token(&mut self, token: &str) {
        if let Some(sc) = self.current_mut() {
            sc.registration_access_token = Some(SecretString::from(token.to_string()));
        }
    }

    /// Set the registration client URI.
    pub(crate) fn set_registration_client_uri(&mut self, uri: &str) {
        if let Some(sc) = self.current_mut() {
            sc.registration_client_uri = Some(uri.to_string());
        }
    }

    /// Set the DPoP key ID.
    pub(crate) fn set_dpop_key_id(&mut self, kid: &str) {
        if let Some(sc) = self.current_mut() {
            sc.dpop_key_id = Some(kid.to_string());
        }
    }

    /// Get the timestamp of last successful registration verification.
    #[must_use]
    pub(crate) fn registration_verified_at(&self) -> Option<&str> {
        self.current()
            .and_then(|s| s.registration_verified_at.as_deref())
    }

    /// Set the registration verified timestamp.
    pub(crate) fn set_registration_verified_at(&mut self, ts: &str) {
        if let Some(sc) = self.current_mut() {
            sc.registration_verified_at = Some(ts.to_string());
        }
    }

    /// Clear all FAPI 2.0 dynamic registration fields for the
    /// current server.
    pub(crate) fn clear_fapi(&mut self) {
        if let Some(sc) = self.current_mut() {
            sc.client_id = None;
            sc.registration_access_token = None;
            sc.registration_client_uri = None;
            sc.dpop_key_id = None;
            sc.registration_verified_at = None;
        }
    }
}

// =========================================================================
// Conversion: ConfigFile -> Config (with legacy migration)
// =========================================================================

impl From<ConfigFile> for Config {
    fn from(mut file: ConfigFile) -> Self {
        let mut servers = BTreeMap::new();

        // Convert new-format server entries.
        for (hostname, scf) in std::mem::take(&mut file.servers) {
            servers.insert(hostname, ServerConfig::from(scf));
        }

        let mut current_server = file.current_server.take();

        // Migrate legacy flat fields if `servers` was empty.
        if servers.is_empty()
            && let Some(ref url) = file.server_url
            && let Ok(hostname) = hostname_from_url(url)
        {
            let sc = ServerConfig {
                server_url: url.clone(),
                token: std::mem::take(&mut file.token).map(SecretString::from),
                client_id: std::mem::take(&mut file.client_id),
                registration_access_token: std::mem::take(&mut file.registration_access_token)
                    .map(SecretString::from),
                registration_client_uri: std::mem::take(&mut file.registration_client_uri),
                dpop_key_id: std::mem::take(&mut file.dpop_key_id),
                registration_verified_at: None, // field did not exist in legacy format
            };
            current_server = Some(hostname.clone());
            servers.insert(hostname, sc);
        }

        Self {
            current_server,
            servers,
            codeartifact: file.codeartifact.take(),
            aws: file.aws.take(),
            network: file.network.take(),
        }
    }
}

impl From<ServerConfigFile> for ServerConfig {
    fn from(mut scf: ServerConfigFile) -> Self {
        Self {
            server_url: scf.server_url.take().unwrap_or_default(),
            token: scf.token.take().map(SecretString::from),
            client_id: scf.client_id.take(),
            registration_access_token: scf.registration_access_token.take().map(SecretString::from),
            registration_client_uri: scf.registration_client_uri.take(),
            dpop_key_id: scf.dpop_key_id.take(),
            registration_verified_at: scf.registration_verified_at.take(),
        }
    }
}

// =========================================================================
// Conversion: Config -> ConfigFile (for serialization)
// =========================================================================

impl From<&Config> for ConfigFile {
    fn from(config: &Config) -> Self {
        let mut servers = BTreeMap::new();
        for (hostname, sc) in &config.servers {
            servers.insert(hostname.clone(), ServerConfigFile::from(sc));
        }

        Self {
            current_server: config.current_server.clone(),
            servers,
            codeartifact: config.codeartifact.clone(),
            aws: config.aws.clone(),
            network: config.network.clone(),
            // Legacy fields are never written.
            server_url: None,
            token: None,
            client_id: None,
            registration_access_token: None,
            registration_client_uri: None,
            dpop_key_id: None,
        }
    }
}

impl From<&ServerConfig> for ServerConfigFile {
    fn from(sc: &ServerConfig) -> Self {
        Self {
            server_url: Some(sc.server_url.clone()),
            token: sc.token.as_ref().map(|s| s.expose_secret().to_string()),
            client_id: sc.client_id.clone(),
            registration_access_token: sc
                .registration_access_token
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            registration_client_uri: sc.registration_client_uri.clone(),
            dpop_key_id: sc.dpop_key_id.clone(),
            registration_verified_at: sc.registration_verified_at.clone(),
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Hostname extraction
    // -----------------------------------------------------------------

    #[test]
    fn test_hostname_standard_https() {
        assert_eq!(
            hostname_from_url("https://us.vouch.sh").unwrap(),
            "us.vouch.sh"
        );
    }

    #[test]
    fn test_hostname_standard_http() {
        assert_eq!(
            hostname_from_url("http://example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_hostname_with_non_standard_port() {
        assert_eq!(
            hostname_from_url("http://localhost:3000").unwrap(),
            "localhost:3000"
        );
    }

    #[test]
    fn test_hostname_explicit_standard_port() {
        assert_eq!(
            hostname_from_url("https://us.vouch.sh:443").unwrap(),
            "us.vouch.sh"
        );
    }

    #[test]
    fn test_hostname_with_path() {
        assert_eq!(
            hostname_from_url("https://dev.vouch.sh/api/v1").unwrap(),
            "dev.vouch.sh"
        );
    }

    #[test]
    fn test_hostname_invalid_url() {
        assert!(hostname_from_url("not-a-url").is_err());
    }

    // -----------------------------------------------------------------
    // New format round-trip
    // -----------------------------------------------------------------

    #[test]
    fn test_new_format_round_trip() {
        let json = r#"{
            "current_server": "us.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "tok-us",
                    "client_id": "cid-us",
                    "dpop_key_id": "kid-us"
                },
                "dev.vouch.sh": {
                    "server_url": "https://dev.vouch.sh",
                    "token": "tok-dev",
                    "client_id": "cid-dev"
                }
            },
            "codeartifact": {
                "default": "prod",
                "profiles": {
                    "prod": {
                        "domain": "my-domain",
                        "domain_owner": "123456789012",
                        "region": "us-east-1"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.current_server.as_deref(), Some("us.vouch.sh"));
        assert_eq!(config.servers.len(), 2);

        // Current server accessors work.
        assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
        assert!(config.token().is_some());
        assert_eq!(config.client_id(), Some("cid-us"));
        assert_eq!(config.dpop_key_id(), Some("kid-us"));

        // CodeArtifact is global.
        let ca = config.codeartifact().expect("codeartifact should exist");
        assert_eq!(ca.default.as_deref(), Some("prod"));
        assert_eq!(ca.profiles.len(), 1);

        // Round-trip to JSON and back.
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string_pretty(&file2).unwrap();
        let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
        let config2 = Config::from(file3);

        assert_eq!(config2.current_server, config.current_server);
        assert_eq!(config2.servers.len(), config.servers.len());
    }

    // -----------------------------------------------------------------
    // Legacy migration
    // -----------------------------------------------------------------

    #[test]
    fn test_legacy_flat_config_migrates() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "legacy-token",
            "client_id": "legacy-cid",
            "registration_access_token": "legacy-rat",
            "registration_client_uri": "https://vouch.example.com/reg/123",
            "dpop_key_id": "legacy-kid",
            "codeartifact": {
                "default": "prod",
                "profiles": {
                    "prod": {
                        "domain": "d",
                        "domain_owner": "o",
                        "region": "r"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        // Legacy fields migrated into a server entry.
        assert_eq!(config.current_server.as_deref(), Some("vouch.example.com"));
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
        assert!(config.token().is_some());
        assert_eq!(config.client_id(), Some("legacy-cid"));
        assert_eq!(config.dpop_key_id(), Some("legacy-kid"));
        assert!(config.registration_access_token().is_some());
        assert_eq!(
            config.registration_client_uri(),
            Some("https://vouch.example.com/reg/123")
        );

        // CodeArtifact preserved.
        assert!(config.codeartifact().is_some());

        // After round-trip, the legacy flat fields are gone.
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(json2.contains("servers"));
        // Legacy top-level fields should NOT be present.
        let reparsed: serde_json::Value = serde_json::from_str(&json2).unwrap();
        assert!(reparsed.get("server_url").is_none());
        assert!(reparsed.get("token").is_none());
        assert!(reparsed.get("client_id").is_none());
    }

    #[test]
    fn test_legacy_email_field_ignored() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "test-token",
            "email": "alice@example.com"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        assert_eq!(config.server_url(), Some("https://vouch.example.com"));
    }

    // -----------------------------------------------------------------
    // Multi-server config
    // -----------------------------------------------------------------

    #[test]
    fn test_multi_server_isolation() {
        let mut config = Config::default();

        // Set up server 1.
        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok-us");
        config.set_client_id("cid-us");

        // Set up server 2.
        config.set_server_url("https://dev.vouch.sh");
        config.set_token("tok-dev");
        config.set_client_id("cid-dev");

        // Current context is server 2.
        assert_eq!(config.server_url(), Some("https://dev.vouch.sh"));
        assert_eq!(config.client_id(), Some("cid-dev"));

        // Switch back to server 1.
        config.set_server_url("https://us.vouch.sh");
        assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
        assert_eq!(config.client_id(), Some("cid-us"));

        // Both entries exist.
        assert_eq!(config.servers.len(), 2);
    }

    // -----------------------------------------------------------------
    // Empty config
    // -----------------------------------------------------------------

    #[test]
    fn test_empty_config_serializes_to_empty_object() {
        let config = Config::default();
        let file = ConfigFile::from(&config);
        let json = serde_json::to_string(&file).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_empty_json_deserializes() {
        let file: ConfigFile = serde_json::from_str("{}").unwrap();
        let config = Config::from(file);
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.codeartifact().is_none());
    }

    #[test]
    fn test_explicit_null_values_deserialize_as_none() {
        let json = r#"{
            "current_server": null,
            "servers": {},
            "codeartifact": null
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.codeartifact().is_none());
    }

    // -----------------------------------------------------------------
    // CodeArtifact (unchanged global behavior)
    // -----------------------------------------------------------------

    #[test]
    fn test_codeartifact_round_trip() {
        let json = r#"{
            "current_server": "us.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "test-token"
                }
            },
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

        let ca = config
            .codeartifact()
            .expect("codeartifact config should exist");
        assert_eq!(ca.default.as_deref(), Some("prod"));
        assert_eq!(ca.profiles.len(), 2);

        let prod = ca.profiles.get("prod").expect("prod profile should exist");
        assert_eq!(prod.domain, "my-domain");
    }

    #[test]
    fn test_config_without_codeartifact() {
        let json = r#"{
            "current_server": "test.vouch.sh",
            "servers": {
                "test.vouch.sh": {
                    "server_url": "https://test.vouch.sh",
                    "token": "t"
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        assert!(config.codeartifact().is_none());

        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(!json2.contains("codeartifact"));
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

    // -----------------------------------------------------------------
    // FAPI 2.0 field tests
    // -----------------------------------------------------------------

    #[test]
    fn test_fapi_fields_round_trip() {
        let json = r#"{
            "current_server": "vouch.example.com",
            "servers": {
                "vouch.example.com": {
                    "server_url": "https://vouch.example.com",
                    "client_id": "my-client-123",
                    "registration_access_token": "reg-token-abc",
                    "registration_client_uri": "https://vouch.example.com/register/my-client-123",
                    "dpop_key_id": "abc123thumbprint"
                }
            }
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

        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string(&file2).unwrap();
        assert!(json2.contains("my-client-123"));
        assert!(json2.contains("abc123thumbprint"));
    }

    #[test]
    fn test_fapi_fields_absent_when_no_server() {
        let config = Config::default();
        assert!(config.client_id().is_none());
        assert!(config.registration_access_token().is_none());
        assert!(config.registration_client_uri().is_none());
        assert!(config.dpop_key_id().is_none());
    }

    #[test]
    fn test_set_client_id() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
        config.set_client_id("test-client");
        assert_eq!(config.client_id(), Some("test-client"));
    }

    #[test]
    fn test_set_dpop_key_id() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
        config.set_dpop_key_id("my-kid");
        assert_eq!(config.dpop_key_id(), Some("my-kid"));
    }

    #[test]
    fn test_set_registration_access_token() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
        config.set_registration_access_token("secret-reg-token");
        assert!(config.registration_access_token().is_some());
    }

    #[test]
    fn test_set_registration_client_uri() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
        config.set_registration_client_uri("https://example.com/reg/123");
        assert_eq!(
            config.registration_client_uri(),
            Some("https://example.com/reg/123")
        );
    }

    #[test]
    fn test_clear_fapi() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
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
        config.set_server_url("https://example.com");
        config.set_token("session-token");
        config.set_client_id("c1");

        config.clear_fapi();

        assert!(config.token().is_some());
        assert!(config.client_id().is_none());
    }

    #[test]
    fn test_registration_access_token_redacted_in_debug() {
        let mut config = Config::default();
        config.set_server_url("https://example.com");
        config.set_registration_access_token("super-secret-reg-token");

        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("super-secret-reg-token"));

        // Also verify ServerConfig Debug redacts secrets.
        let sc = config.servers.get("example.com").expect("server entry");
        let sc_debug = format!("{sc:?}");
        assert!(sc_debug.contains("[REDACTED]"));
        assert!(!sc_debug.contains("super-secret-reg-token"));
    }

    // -----------------------------------------------------------------
    // Regression: setting server_url also creates context
    // -----------------------------------------------------------------

    #[test]
    fn test_set_server_url_creates_context() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok");
        assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
        assert!(config.token().is_some());
    }

    // -----------------------------------------------------------------
    // AwsMultiAccountConfig round-trip serialization
    // -----------------------------------------------------------------

    #[test]
    fn test_aws_multi_account_config_round_trip() {
        let json = r#"{
            "current_server": "us.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "test-token"
                }
            },
            "aws": {
                "sso_sessions": {
                    "smoketurner": {
                        "management_role": "arn:aws:iam::111:role/VouchManagement",
                        "member_role_name": "VouchAccess",
                        "member_role_path": "/teams/sec/"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        let aws = config.aws().expect("aws config should exist");
        assert_eq!(aws.sso_sessions.len(), 1);

        let session = aws
            .sso_sessions
            .get("smoketurner")
            .expect("smoketurner session");
        assert_eq!(
            session.management_role,
            "arn:aws:iam::111:role/VouchManagement"
        );
        assert_eq!(session.member_role_name, "VouchAccess");
        assert_eq!(session.member_role_path, "/teams/sec/");

        // Round-trip through JSON
        let file2 = ConfigFile::from(&config);
        let json2 = serde_json::to_string_pretty(&file2).unwrap();
        let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
        let config2 = Config::from(file3);

        let aws2 = config2.aws().expect("aws config should survive round-trip");
        let session2 = aws2
            .sso_sessions
            .get("smoketurner")
            .expect("smoketurner session");
        assert_eq!(
            session2.management_role,
            "arn:aws:iam::111:role/VouchManagement"
        );
        assert_eq!(session2.member_role_name, "VouchAccess");
        assert_eq!(session2.member_role_path, "/teams/sec/");
    }

    #[test]
    fn test_aws_member_role_name_default_when_omitted() {
        let json = r#"{
            "aws": {
                "sso_sessions": {
                    "my-session": {
                        "management_role": "arn:aws:iam::123456789012:role/Mgmt"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        let aws = config.aws().expect("aws config should exist");
        let session = aws.sso_sessions.get("my-session").expect("session");
        assert_eq!(session.member_role_name, "VouchAccess");
        assert_eq!(session.member_role_path, "/");
    }

    #[test]
    fn test_normalize_member_role_path_canonical_forms() {
        assert_eq!(normalize_member_role_path("").unwrap(), "/");
        assert_eq!(normalize_member_role_path("/").unwrap(), "/");
        assert_eq!(
            normalize_member_role_path("teams/sec").unwrap(),
            "/teams/sec/"
        );
        assert_eq!(
            normalize_member_role_path("/teams/sec").unwrap(),
            "/teams/sec/"
        );
        assert_eq!(
            normalize_member_role_path("teams/sec/").unwrap(),
            "/teams/sec/"
        );
        assert_eq!(
            normalize_member_role_path("/teams/sec/").unwrap(),
            "/teams/sec/"
        );
    }

    #[test]
    fn test_normalize_member_role_path_rejects_invalid() {
        assert!(normalize_member_role_path("teams sec").is_err());
        assert!(normalize_member_role_path("//teams//sec").is_err());
        assert!(normalize_member_role_path("arn:aws:iam::1:role/foo").is_err());
    }

    #[test]
    fn test_sso_session_config_default() {
        let cfg = SsoSessionConfig::default();
        assert_eq!(cfg.management_role, "");
        assert_eq!(cfg.member_role_name, "VouchAccess");
        assert_eq!(cfg.member_role_path, "/");
    }

    #[test]
    fn test_role_arn_in_no_path() {
        let cfg = SsoSessionConfig::default();
        assert_eq!(
            cfg.role_arn_in("aws", "123456789012"),
            "arn:aws:iam::123456789012:role/VouchAccess"
        );
    }

    #[test]
    fn test_role_arn_in_with_path() {
        let cfg = SsoSessionConfig {
            member_role_path: "/teams/sec/".to_string(),
            ..SsoSessionConfig::default()
        };
        assert_eq!(
            cfg.role_arn_in("aws", "123456789012"),
            "arn:aws:iam::123456789012:role/teams/sec/VouchAccess"
        );
    }

    #[test]
    fn test_role_arn_in_partition_govcloud() {
        let cfg = SsoSessionConfig {
            member_role_path: "/teams/".to_string(),
            ..SsoSessionConfig::default()
        };
        assert_eq!(
            cfg.role_arn_in("aws-us-gov", "123"),
            "arn:aws-us-gov:iam::123:role/teams/VouchAccess"
        );
    }

    #[test]
    fn test_member_role_path_normalized_on_deserialize() {
        let json = r#"{
            "aws": {
                "sso_sessions": {
                    "my-session": {
                        "management_role": "arn:aws:iam::1:role/Mgmt",
                        "member_role_path": "teams/sec"
                    }
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        let aws = config.aws().expect("aws config should exist");
        let session = aws.sso_sessions.get("my-session").expect("session");
        assert_eq!(session.member_role_path, "/teams/sec/");
    }

    #[test]
    fn test_member_role_path_invalid_rejected_on_deserialize() {
        let json = r#"{
            "aws": {
                "sso_sessions": {
                    "my-session": {
                        "management_role": "arn:aws:iam::1:role/Mgmt",
                        "member_role_path": "arn:aws:iam::1:role/foo"
                    }
                }
            }
        }"#;

        let result: std::result::Result<ConfigFile, _> = serde_json::from_str(json);
        assert!(result.is_err(), "ARN-shaped paths must be rejected");
    }

    #[test]
    fn test_aws_empty_sso_sessions_serializes_correctly() {
        let mut config = Config::default();
        config.set_aws(AwsMultiAccountConfig {
            sso_sessions: BTreeMap::new(),
        });

        let file = ConfigFile::from(&config);
        let json = serde_json::to_string(&file).unwrap();

        // Empty sso_sessions map is skipped due to skip_serializing_if
        assert!(!json.contains("sso_sessions"));
    }

    #[test]
    fn test_config_without_aws_section_loads_fine() {
        let json = r#"{
            "current_server": "us.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "test-token"
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert!(config.aws().is_none());
        assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
    }

    // -----------------------------------------------------------------
    // Stale registration detection
    // -----------------------------------------------------------------

    /// When a config's registration_client_uri points to localhost:3000 but the
    /// current server is us.vouch.sh, the hostnames must differ so the caller
    /// can detect and discard the stale registration.
    #[test]
    fn test_hostname_from_url_stale_registration_mismatch() {
        let stale_host = hostname_from_url("http://localhost:3000/reg/abc").unwrap();
        let current_host = hostname_from_url("https://us.vouch.sh").unwrap();
        assert_ne!(
            stale_host, current_host,
            "stale registration URI hostname must differ from current server hostname"
        );
        assert_eq!(stale_host, "localhost:3000");
        assert_eq!(current_host, "us.vouch.sh");
    }

    /// When both URIs resolve to the same server the hostnames are equal,
    /// so the registration is still valid.
    #[test]
    fn test_hostname_from_url_valid_registration_match() {
        let reg_host = hostname_from_url("https://us.vouch.sh/register/my-client-123").unwrap();
        let current_host = hostname_from_url("https://us.vouch.sh").unwrap();
        assert_eq!(reg_host, current_host);
    }

    // -----------------------------------------------------------------
    // Hostname extraction edge cases
    // -----------------------------------------------------------------

    #[test]
    fn test_hostname_trailing_slash() {
        assert_eq!(
            hostname_from_url("https://us.vouch.sh/").unwrap(),
            "us.vouch.sh"
        );
    }

    #[test]
    fn test_hostname_with_path_components() {
        assert_eq!(
            hostname_from_url("https://us.vouch.sh/oauth/token").unwrap(),
            "us.vouch.sh"
        );
    }

    /// https://host:443 — standard port for https, so port is stripped.
    #[test]
    fn test_hostname_https_explicit_443_stripped() {
        assert_eq!(
            hostname_from_url("https://us.vouch.sh:443").unwrap(),
            "us.vouch.sh"
        );
    }

    /// http://host:80 — standard port for http, so port is stripped.
    #[test]
    fn test_hostname_http_explicit_80_stripped() {
        assert_eq!(
            hostname_from_url("http://example.com:80").unwrap(),
            "example.com"
        );
    }

    /// http://host:443 — 443 is non-standard for http, so port is kept.
    #[test]
    fn test_hostname_http_port_443_kept() {
        assert_eq!(
            hostname_from_url("http://example.com:443").unwrap(),
            "example.com:443"
        );
    }

    /// https://host:80 — 80 is non-standard for https, so port is kept.
    #[test]
    fn test_hostname_https_port_80_kept() {
        assert_eq!(
            hostname_from_url("https://example.com:80").unwrap(),
            "example.com:80"
        );
    }

    // -----------------------------------------------------------------
    // Legacy migration edge cases
    // -----------------------------------------------------------------

    /// Legacy config with only a token and no server_url must not crash.
    /// The config should load with no active server context.
    #[test]
    fn test_legacy_no_server_url_does_not_crash() {
        let json = r#"{"token": "orphaned-token"}"#;
        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        // No server context was established; all accessors return None.
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.current_server.is_none());
        assert!(config.servers.is_empty());
    }

    /// Legacy config with an unparseable server_url must not crash.
    /// The migration silently skips it and produces an empty config.
    #[test]
    fn test_legacy_unparseable_server_url_does_not_crash() {
        let json = r#"{"server_url": "not-a-url", "token": "some-token"}"#;
        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);
        // Migration skips the bad URL; nothing should crash.
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.servers.is_empty());
    }

    /// Legacy config with a non-standard port in server_url must migrate correctly
    /// and produce a `host:port` key (e.g. `localhost:3000`).
    #[test]
    fn test_legacy_server_url_non_standard_port_migrates() {
        let json = r#"{
            "server_url": "http://localhost:3000",
            "token": "dev-token",
            "client_id": "dev-client"
        }"#;
        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.current_server.as_deref(), Some("localhost:3000"));
        assert_eq!(config.server_url(), Some("http://localhost:3000"));
        assert!(config.token().is_some());
        assert_eq!(config.client_id(), Some("dev-client"));
        assert_eq!(config.servers.len(), 1);
    }

    // -----------------------------------------------------------------
    // Multi-server isolation: clear_token and clear_fapi
    // -----------------------------------------------------------------

    /// Clearing the token for one server must not affect a second server's token.
    #[test]
    fn test_clear_token_only_affects_current_server() {
        let mut config = Config::default();

        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok-us");

        config.set_server_url("https://dev.vouch.sh");
        config.set_token("tok-dev");

        // Clear token for dev server.
        config.clear_token();
        assert!(config.token().is_none(), "dev token should be cleared");

        // Switch to us server — its token must be untouched.
        config.set_server_url("https://us.vouch.sh");
        assert!(
            config.token().is_some(),
            "us.vouch.sh token should still exist"
        );
    }

    /// Clearing FAPI fields for one server must not affect a second server.
    #[test]
    fn test_clear_fapi_only_affects_current_server() {
        let mut config = Config::default();

        config.set_server_url("https://us.vouch.sh");
        config.set_client_id("cid-us");
        config.set_dpop_key_id("kid-us");
        config.set_registration_client_uri("https://us.vouch.sh/reg/1");

        config.set_server_url("https://dev.vouch.sh");
        config.set_client_id("cid-dev");
        config.set_dpop_key_id("kid-dev");
        config.set_registration_client_uri("http://localhost:3000/reg/2");

        // Clear FAPI for dev server.
        config.clear_fapi();
        assert!(config.client_id().is_none(), "dev client_id should be gone");
        assert!(
            config.dpop_key_id().is_none(),
            "dev dpop_key_id should be gone"
        );

        // Switch to us server — its FAPI fields must be intact.
        config.set_server_url("https://us.vouch.sh");
        assert_eq!(config.client_id(), Some("cid-us"));
        assert_eq!(config.dpop_key_id(), Some("kid-us"));
        assert_eq!(
            config.registration_client_uri(),
            Some("https://us.vouch.sh/reg/1")
        );
    }

    // -----------------------------------------------------------------
    // No-op behaviour when there is no current server context
    // -----------------------------------------------------------------

    /// set_token without a prior set_server_url must be a silent no-op:
    /// no server entry is created and no panic occurs.
    #[test]
    fn test_set_token_without_server_context_is_noop() {
        let mut config = Config::default();
        config.set_token("orphan-token");

        assert!(config.token().is_none());
        assert!(config.servers.is_empty());
    }

    /// All FAPI mutators are no-ops without server context.
    #[test]
    fn test_all_mutators_noop_without_server_context() {
        let mut config = Config::default();
        config.set_client_id("orphan");
        config.set_registration_access_token("orphan");
        config.set_registration_client_uri("orphan");
        config.set_dpop_key_id("orphan");
        config.clear_token();
        config.clear_fapi();

        assert!(config.servers.is_empty());
        assert!(config.client_id().is_none());
        assert!(config.token().is_none());
    }

    // -----------------------------------------------------------------
    // Token value verification (not just is_some)
    // -----------------------------------------------------------------

    #[test]
    fn test_token_value_preserved() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_token("exact-token-value");

        let token = config.token().expect("token should exist");
        assert_eq!(token.expose_secret(), "exact-token-value");
    }

    #[test]
    fn test_registration_access_token_value_preserved() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_registration_access_token("exact-rat-value");

        let rat = config
            .registration_access_token()
            .expect("RAT should exist");
        assert_eq!(rat.expose_secret(), "exact-rat-value");
    }

    // -----------------------------------------------------------------
    // Full round-trip preserves secret values
    // -----------------------------------------------------------------

    #[test]
    fn test_round_trip_preserves_secret_values() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_token("my-jwt-token");
        config.set_registration_access_token("my-reg-token");

        // Serialize to ConfigFile and back.
        let file = ConfigFile::from(&config);
        let json = serde_json::to_string_pretty(&file).unwrap();
        let file2: ConfigFile = serde_json::from_str(&json).unwrap();
        let config2 = Config::from(file2);

        let t = config2.token().expect("token after round-trip");
        assert_eq!(t.expose_secret(), "my-jwt-token");

        let rat = config2
            .registration_access_token()
            .expect("RAT after round-trip");
        assert_eq!(rat.expose_secret(), "my-reg-token");
    }

    // -----------------------------------------------------------------
    // Idempotent set_server_url
    // -----------------------------------------------------------------

    /// Calling set_server_url twice with the same URL does not
    /// duplicate entries or lose state.
    #[test]
    fn test_set_server_url_idempotent() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok1");
        config.set_client_id("cid1");

        // Call again with the same URL.
        config.set_server_url("https://us.vouch.sh");

        assert_eq!(config.servers.len(), 1);
        assert!(config.token().is_some());
        assert_eq!(config.client_id(), Some("cid1"));
    }

    // -----------------------------------------------------------------
    // Defensive: current_server points to nonexistent key
    // -----------------------------------------------------------------

    /// If the config file has a current_server that doesn't match
    /// any entry in servers, all accessors return None gracefully.
    #[test]
    fn test_current_server_nonexistent_key() {
        let json = r#"{
            "current_server": "ghost.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "tok"
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        // current_server doesn't match any key → None.
        assert!(config.server_url().is_none());
        assert!(config.token().is_none());
        assert!(config.client_id().is_none());
        // But the data is still there if we switch context.
        assert_eq!(config.servers.len(), 1);
    }

    // -----------------------------------------------------------------
    // Mixed legacy + new format: servers wins, legacy ignored
    // -----------------------------------------------------------------

    /// When both `servers` and legacy flat fields exist, the `servers`
    /// map takes precedence and legacy fields are ignored.
    #[test]
    fn test_mixed_legacy_and_new_format_servers_wins() {
        let json = r#"{
            "current_server": "us.vouch.sh",
            "servers": {
                "us.vouch.sh": {
                    "server_url": "https://us.vouch.sh",
                    "token": "new-token",
                    "client_id": "new-cid"
                }
            },
            "server_url": "https://old.vouch.sh",
            "token": "old-token",
            "client_id": "old-cid"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        // servers was non-empty, so legacy migration is skipped.
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
        let t = config.token().expect("token should exist");
        assert_eq!(t.expose_secret(), "new-token");
        assert_eq!(config.client_id(), Some("new-cid"));
    }

    // -----------------------------------------------------------------
    // Server URL update (same hostname, URL changes)
    // -----------------------------------------------------------------

    /// Calling set_server_url with a different URL that resolves to
    /// the same hostname updates the stored URL but keeps existing
    /// per-server state.
    #[test]
    fn test_set_server_url_updates_url_same_hostname() {
        let mut config = Config::default();
        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok");
        config.set_client_id("cid");

        // Call with a trailing-slash variant — same hostname.
        config.set_server_url("https://us.vouch.sh/");

        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.server_url(), Some("https://us.vouch.sh/"));
        assert!(config.token().is_some());
        assert_eq!(config.client_id(), Some("cid"));
    }

    // -----------------------------------------------------------------
    // Multi-server full FAPI state survives context switches
    // -----------------------------------------------------------------

    #[test]
    fn test_multi_server_all_fapi_fields_survive_switch() {
        let mut config = Config::default();

        // Populate server A with all FAPI fields.
        config.set_server_url("https://us.vouch.sh");
        config.set_token("tok-us");
        config.set_client_id("cid-us");
        config.set_dpop_key_id("kid-us");
        config.set_registration_access_token("rat-us");
        config.set_registration_client_uri("https://us.vouch.sh/reg/1");

        // Populate server B.
        config.set_server_url("https://eu.vouch.sh");
        config.set_token("tok-eu");
        config.set_client_id("cid-eu");
        config.set_dpop_key_id("kid-eu");

        // Switch back to A and verify every field.
        config.set_server_url("https://us.vouch.sh");
        assert_eq!(config.token().expect("us token").expose_secret(), "tok-us");
        assert_eq!(config.client_id(), Some("cid-us"));
        assert_eq!(config.dpop_key_id(), Some("kid-us"));
        assert_eq!(
            config
                .registration_access_token()
                .expect("us RAT")
                .expose_secret(),
            "rat-us"
        );
        assert_eq!(
            config.registration_client_uri(),
            Some("https://us.vouch.sh/reg/1")
        );

        // Switch to B and verify.
        config.set_server_url("https://eu.vouch.sh");
        assert_eq!(config.token().expect("eu token").expose_secret(), "tok-eu");
        assert_eq!(config.client_id(), Some("cid-eu"));
        assert_eq!(config.dpop_key_id(), Some("kid-eu"));
        assert!(config.registration_access_token().is_none());
        assert!(config.registration_client_uri().is_none());
    }

    // -----------------------------------------------------------------
    // Legacy migration: token value is correct
    // -----------------------------------------------------------------

    #[test]
    fn test_legacy_migration_preserves_token_value() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "token": "legacy-jwt-token-123"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        let t = config.token().expect("migrated token");
        assert_eq!(t.expose_secret(), "legacy-jwt-token-123");
    }

    // -----------------------------------------------------------------
    // Legacy migration: registration_access_token value
    // -----------------------------------------------------------------

    #[test]
    fn test_legacy_migration_preserves_rat_value() {
        let json = r#"{
            "server_url": "https://vouch.example.com",
            "registration_access_token": "legacy-rat-secret"
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        let rat = config.registration_access_token().expect("migrated RAT");
        assert_eq!(rat.expose_secret(), "legacy-rat-secret");
    }

    // -----------------------------------------------------------------
    // New format: server entry with empty/missing fields
    // -----------------------------------------------------------------

    #[test]
    fn test_server_entry_with_no_optional_fields() {
        let json = r#"{
            "current_server": "bare.vouch.sh",
            "servers": {
                "bare.vouch.sh": {
                    "server_url": "https://bare.vouch.sh"
                }
            }
        }"#;

        let file: ConfigFile = serde_json::from_str(json).unwrap();
        let config = Config::from(file);

        assert_eq!(config.server_url(), Some("https://bare.vouch.sh"));
        assert!(config.token().is_none());
        assert!(config.client_id().is_none());
        assert!(config.dpop_key_id().is_none());
        assert!(config.registration_access_token().is_none());
        assert!(config.registration_client_uri().is_none());
    }
}
