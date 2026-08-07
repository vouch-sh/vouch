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
use std::path::{Path, PathBuf};
use vouch_cli::{tr, tr_args};
use vouch_common::dns::{DohConfigSerde, NetworkConfig};

/// Minimal legacy SSO session record.
///
/// Only `management_role` is extracted; `member_role_name`, `member_role_path`,
/// and the session name are dropped during migration. Needs `Serialize` because
/// it is a field of `AwsOrgsConfig`, which derives `Serialize` — the field itself
/// is `skip_serializing` so this impl is never actually called.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LegacySsoSession {
    #[serde(default)]
    management_role: String,
}

/// AWS organizations configuration in `$XDG_CONFIG_HOME/vouch/config.json`.
///
/// Each entry represents one AWS Organization (management account + optional
/// Identity Center instance). Re-running `vouch setup aws` appends a second
/// organization; there is no name key.
///
/// The `sso_sessions` field is read for legacy-format migration but never
/// written back (`skip_serializing`). After `From<ConfigFile> for Config`
/// runs, `sso_sessions` is always empty in memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct AwsOrgsConfig {
    /// Configured AWS organizations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organizations: Vec<AwsOrganization>,

    /// Legacy `aws.sso_sessions` — read for migration, never written back.
    /// Nested under the `aws` object, so it lives on this type (serde cannot
    /// hoist a nested legacy field to `ConfigFile` top-level).
    #[serde(default, skip_serializing)]
    sso_sessions: BTreeMap<String, LegacySsoSession>,
}

/// One AWS Organization: management account (OIDC-trusted anchor) plus optional
/// Identity Center configuration for the TTI credential flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AwsOrganization {
    /// Management account role ARN (Vouch OIDC trust deployed here).
    pub management_role: String,
    /// Identity Center configuration for the TTI (`CreateTokenWithIAM`) flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_center: Option<AwsIdentityCenter>,
}

/// AWS IAM Identity Center configuration for one instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AwsIdentityCenter {
    /// Customer-managed application ARN
    /// (e.g., `arn:aws:sso::111:application/ssoins-x/apl-y`).
    pub application_arn: String,
    /// AWS region where this IdC instance is hosted (e.g., `us-east-1`).
    pub region: String,
}

/// CLI configuration stored in `$XDG_CONFIG_HOME/vouch/config.json`
/// (`~/.config/vouch/config.json` by default)
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
    /// Container registry → AWS profile anchors.
    docker: Option<DockerRegistriesConfig>,
    /// AWS organizations configuration (role chaining + IdC).
    aws: Option<AwsOrgsConfig>,
    /// Global network configuration (DoH, …).
    network: Option<NetworkConfig>,
    /// AI provider Workload Identity Federation configuration.
    ai: Option<AiProvidersConfig>,
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
    /// Key ID of the DPoP/FAPI client keypair (stored in the OS keychain, or
    /// `$XDG_DATA_HOME/vouch/client_key.json` as a fallback).
    dpop_key_id: Option<String>,
    /// ISO 8601 timestamp of last successful registration verification.
    registration_verified_at: Option<String>,
}

/// CodeArtifact configuration with named domain profiles.
///
/// A "domain profile" here is a vouch-local bundle of (domain, domain_owner,
/// region) — a different concept from an *AWS* profile in `~/.aws/config`.
/// The CLI surface keeps the two distinct: `--domain-profile` names one of
/// these, `--profile` always means the AWS profile.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct CodeArtifactConfig {
    /// Name of the default domain profile (used when `--domain-profile` is omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Named domain profiles, keyed by user-chosen name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub domain_profiles: BTreeMap<String, CodeArtifactProfile>,
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
    /// AWS profile in `~/.aws/config` whose role mints tokens for this domain.
    ///
    /// Package managers reach `vouch credential codeartifact` through
    /// argument-less shims (a pip/pnpm keyring helper, a Cargo credential
    /// provider), so the account has to be recorded here rather than passed on
    /// the command line. `None` falls back to resolving a Vouch profile from
    /// `~/.aws/config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_profile: Option<String>,
}

/// Container registry → AWS profile anchors.
///
/// Docker invokes `docker-credential-vouch` as an argument-less symlink, so the
/// account backing each ECR registry cannot be passed on the command line and is
/// recorded here by `vouch setup docker --profile`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct DockerRegistriesConfig {
    /// Registry host → AWS profile name in `~/.aws/config`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub registries: BTreeMap<String, String>,
}

// =========================================================================
// AI provider Workload Identity Federation configuration
// =========================================================================

/// Federation configuration for AI provider APIs (Claude, OpenAI).
///
/// Stored at the top level of `$XDG_CONFIG_HOME/vouch/config.json`. Holds the (non-secret)
/// identifiers a workload presents to a provider's token endpoint to
/// exchange a Vouch-issued OIDC ID token for a short-lived provider token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct AiProvidersConfig {
    /// Anthropic (Claude) federation parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<AnthropicFederation>,
    /// OpenAI federation parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openai: Option<OpenAiFederation>,
}

/// Anthropic (Claude) Workload Identity Federation parameters.
///
/// See <https://platform.claude.com/docs/en/manage-claude/workload-identity-federation>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AnthropicFederation {
    /// Federation rule ID (`fdrl_...`).
    pub federation_rule_id: String,
    /// Anthropic organization ID (UUID).
    pub organization_id: String,
    /// Service account ID (`svac_...`) the minted token acts as.
    pub service_account_id: String,
    /// Workspace ID (`wrkspc_...`).
    pub workspace_id: String,
    /// `aud` claim to request on the assertion. Optional: most federation
    /// rules match on `sub` alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Token endpoint override (defaults to Anthropic's public endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
}

/// OpenAI Workload Identity Federation parameters.
///
/// See <https://developers.openai.com/api/docs/guides/workload-identity-federation>.
/// Note: OpenAI must onboard the Vouch issuer as a workload identity
/// provider first — custom OIDC issuers are not self-service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpenAiFederation {
    /// OpenAI Workload Identity Provider ID for the Vouch issuer.
    pub identity_provider_id: String,
    /// OpenAI service account ID to resolve the mapping against.
    pub service_account_id: String,
    /// `aud` claim to request on the assertion. Set this to whatever
    /// audience OpenAI configured for the Vouch issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Token endpoint override (defaults to OpenAI's public endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
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
    docker: Option<DockerRegistriesConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws: Option<AwsOrgsConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<NetworkConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ai: Option<AiProvidersConfig>,

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
            .field("ai", &self.ai)
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
            .field("ai", &self.ai)
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
    let parsed = url::Url::parse(url_str)
        .with_context(|| tr_args!("err-invalid-server-url", url_str = url_str))?;

    let host = parsed
        .host_str()
        .context(tr!("err-server-url-has-no-host"))?;

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
        Self::load_from(&Self::config_path()?)
    }

    /// Load configuration from `path`, or return defaults if it is missing.
    ///
    /// Split from [`Config::load`] so error handling can be tested against a
    /// temporary directory without touching the process environment.
    fn load_from(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = fs::read_to_string(path).with_context(|| {
                tr_args!("err-failed-read-config", value = path.display().to_string())
            })?;
            let config_file: ConfigFile = serde_json::from_str(&content).with_context(|| {
                tr_args!(
                    "err-failed-parse-config",
                    value = path.display().to_string()
                )
            })?;
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
        self.save_to(&Self::config_path()?)
    }

    /// Save configuration to `path`.
    ///
    /// Split from [`Config::save`] for the same testability reason as
    /// [`Config::load_from`].
    fn save_to(&self, path: &Path) -> Result<()> {
        let config_file = ConfigFile::from(self);
        let content = serde_json::to_string_pretty(&config_file)
            .context(tr!("err-failed-serialize-config"))?;

        vouch_common::fs::atomic_write_secure(path, content.as_bytes()).with_context(|| {
            tr_args!(
                "err-failed-write-config",
                value = path.display().to_string()
            )
        })?;

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
        Self::modify_at(&Self::config_path()?, f)
    }

    /// [`Config::modify`] against an explicit config path.
    ///
    /// Split from [`Config::modify`] for the same testability reason as
    /// [`Config::load_from`].
    #[cfg(unix)]
    fn modify_at(path: &Path, f: impl FnOnce(&mut Config)) -> Result<()> {
        let lock_path = path.with_added_extension("lock");

        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                tr_args!(
                    "err-failed-create-directory-3",
                    value = parent.display().to_string()
                )
            })?;
        }

        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| {
                tr_args!(
                    "err-failed-open-lock-file",
                    value = lock_path.display().to_string()
                )
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort tightening of lock file permissions.
            let _chmod =
                std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
        }

        lock_file
            .lock()
            .context(tr!("err-failed-acquire-config-file-lock"))?;

        let mut config = Self::load_from(path)?;
        f(&mut config);
        config.save_to(path)?;

        drop(lock_file);

        Ok(())
    }

    /// Atomically load, modify, and save the config file.
    ///
    /// Non-Unix fallback without advisory locking.
    #[cfg(not(unix))]
    pub(crate) fn modify(f: impl FnOnce(&mut Config)) -> Result<()> {
        Self::modify_at(&Self::config_path()?, f)
    }

    /// [`Config::modify`] against an explicit config path.
    ///
    /// Split from [`Config::modify`] for the same testability reason as
    /// [`Config::load_from`].
    #[cfg(not(unix))]
    fn modify_at(path: &Path, f: impl FnOnce(&mut Config)) -> Result<()> {
        let mut config = Self::load_from(path)?;
        f(&mut config);
        config.save_to(path)
    }

    // =====================================================================
    // Network
    // =====================================================================

    /// Configured DoH provider, if any.
    pub(crate) fn doh(&self) -> Option<&DohConfigSerde> {
        self.network.as_ref().and_then(NetworkConfig::doh)
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

    /// Look up the AWS profile anchored to a container registry.
    pub(crate) fn docker_registry_profile(&self, registry: &str) -> Option<&str> {
        self.docker
            .as_ref()?
            .registries
            .get(registry)
            .map(String::as_str)
    }

    /// Anchor a container registry to an AWS profile (in memory; call `save()`).
    pub(crate) fn set_docker_registry_profile(&mut self, registry: &str, profile: &str) {
        self.docker
            .get_or_insert_with(DockerRegistriesConfig::default)
            .registries
            .insert(registry.to_string(), profile.to_string());
    }

    /// Add a CodeArtifact domain profile (in memory only, call `save()` to
    /// persist). If this is the first one, it becomes the default.
    pub(crate) fn set_codeartifact_profile(&mut self, name: &str, profile: CodeArtifactProfile) {
        let ca = self
            .codeartifact
            .get_or_insert_with(CodeArtifactConfig::default);
        if ca.domain_profiles.is_empty() && ca.default.is_none() {
            ca.default = Some(name.to_string());
        }
        ca.domain_profiles.insert(name.to_string(), profile);
    }

    // =====================================================================
    // AWS multi-account (global, not per-server)
    // =====================================================================

    /// Get the AWS organizations configuration.
    #[must_use]
    pub(crate) fn aws(&self) -> Option<&AwsOrgsConfig> {
        self.aws.as_ref()
    }

    /// Append an organization to the AWS organizations list (in memory only).
    ///
    /// If an organization with the same management role already exists, its
    /// `identity_center` is updated only when the incoming value is `Some`;
    /// otherwise the existing `identity_center` is preserved. Call `save()`
    /// to persist.
    pub(crate) fn append_aws_org(&mut self, org: AwsOrganization) {
        let orgs = self.aws.get_or_insert_with(AwsOrgsConfig::default);
        if let Some(existing) = orgs
            .organizations
            .iter_mut()
            .find(|o| o.management_role == org.management_role)
        {
            if org.identity_center.is_some() {
                existing.identity_center = org.identity_center;
            }
        } else {
            orgs.organizations.push(org);
        }
    }

    // =====================================================================
    // AI provider federation (global, not per-server)
    // =====================================================================

    /// Get the AI provider federation configuration.
    #[must_use]
    pub(crate) fn ai(&self) -> Option<&AiProvidersConfig> {
        self.ai.as_ref()
    }

    /// Set the Anthropic federation parameters (in memory; call `save()`).
    pub(crate) fn set_ai_anthropic(&mut self, fed: AnthropicFederation) {
        self.ai
            .get_or_insert_with(AiProvidersConfig::default)
            .anthropic = Some(fed);
    }

    /// Set the OpenAI federation parameters (in memory; call `save()`).
    pub(crate) fn set_ai_openai(&mut self, fed: OpenAiFederation) {
        self.ai
            .get_or_insert_with(AiProvidersConfig::default)
            .openai = Some(fed);
    }

    /// Get the path to the config file
    /// (`$XDG_CONFIG_HOME/vouch/config.json`).
    fn config_path() -> Result<PathBuf> {
        vouch_common::paths::config_file().context(tr!("err-could-not-determine-config-directory"))
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

        // Migrate legacy sso_sessions → organizations.
        //
        // When `sso_sessions` is non-empty and `organizations` is empty,
        // each legacy entry becomes an `AwsOrganization` with only the
        // management_role preserved (name key and member_role_* fields are
        // dropped). De-dup by management_role to prevent duplicates on
        // repeated migration runs.
        let aws = file.aws.take().map(|mut a| {
            if a.organizations.is_empty() && !a.sso_sessions.is_empty() {
                let mut seen = std::collections::BTreeSet::new();
                for legacy in std::mem::take(&mut a.sso_sessions).into_values() {
                    if !legacy.management_role.is_empty()
                        && seen.insert(legacy.management_role.clone())
                    {
                        a.organizations.push(AwsOrganization {
                            management_role: legacy.management_role,
                            identity_center: None,
                        });
                    }
                }
            }
            // Ensure sso_sessions is always empty in memory after migration.
            a.sso_sessions = BTreeMap::new();
            a
        });

        Self {
            current_server,
            servers,
            codeartifact: file.codeartifact.take(),
            docker: file.docker.take(),
            aws,
            network: file.network.take(),
            ai: file.ai.take(),
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

        // Guard: an AwsOrgsConfig with empty organizations would serialize as `{}`
        // (the outer Option is not enough — AwsOrgsConfig itself doesn't know to
        // suppress itself when empty). Map empty orgs to None so a user who has
        // not run 'vouch setup aws' has no `aws` key in their config file.
        let aws = config.aws.clone().filter(|a| !a.organizations.is_empty());

        // Same guard: an empty registry map would serialize as `docker: {}`.
        let docker = config.docker.clone().filter(|d| !d.registries.is_empty());

        Self {
            current_server: config.current_server.clone(),
            servers,
            codeartifact: config.codeartifact.clone(),
            docker,
            aws,
            network: config.network.clone(),
            ai: config.ai.clone(),
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
mod tests;
