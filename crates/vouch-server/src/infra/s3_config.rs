// SPDX-License-Identifier: BUSL-1.1
//! S3-based configuration for dynamic config updates.
//!
//! This module provides functionality to:
//! - Fetch configuration from an S3 object (JSON format)
//! - Poll for configuration changes using ETag comparison
//! - Automatically reload TLS certificates when they change
//!
//! ## Configuration
//!
//! Set `VOUCH_S3_CONFIG_BUCKET` to enable S3 configuration. The server will:
//! 1. Fetch the config JSON on startup (fail-fast if unreachable)
//! 2. Poll every N seconds (default 60) using HEAD requests
//! 3. Re-fetch only when ETag changes
//! 4. Hot-reload TLS certificates when they change
//!
//! ## S3 Config JSON Schema
//!
//! All certificate and key fields are base64-encoded PEM. See the example in
//! the implementation plan for the full schema.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::Client as S3Client;
use axum_server::tls_rustls::RustlsConfig;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;

use crate::config::ServerConfig;
use crate::crypto::tpm_decrypt;

/// S3 configuration source settings.
#[derive(Debug, Clone)]
pub struct S3ConfigSource {
    /// S3 bucket name.
    pub bucket: String,
    /// S3 object key.
    pub key: String,
    /// Optional AWS region override.
    pub region: Option<String>,
    /// Polling interval in seconds.
    pub poll_interval_seconds: u64,
}

/// Nested TLS configuration from S3.
#[derive(Clone, Deserialize, Serialize, Default)]
pub struct S3TlsConfig {
    /// Base64-encoded PEM certificate.
    pub cert: Option<String>,
    /// Base64-encoded PEM private key.
    pub key: Option<String>,
}

// Custom Debug that redacts private key to prevent accidental log exposure.
impl std::fmt::Debug for S3TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3TlsConfig")
            .field("cert", &self.cert)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Nested ACME (Let's Encrypt) configuration from S3.
///
/// This is promoted to the envelope wrapper (alongside `tls` and `version`)
/// so that external ACME certificate renewal processes can read it directly
/// from the S3 object without KMS decryption.
#[derive(Clone, Deserialize, Serialize)]
pub struct S3AcmeConfig {
    /// ACME account private key (PEM or base64-encoded).
    pub account_key: String,
    /// ACME account email address.
    pub email: String,
}

// Custom Debug that redacts account_key to prevent accidental log exposure.
impl std::fmt::Debug for S3AcmeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3AcmeConfig")
            .field("account_key", &"[REDACTED]")
            .field("email", &self.email)
            .finish()
    }
}

/// Nested OIDC configuration from S3.
#[derive(Deserialize, Default)]
pub struct S3OidcConfig {
    /// OIDC issuer URL.
    pub issuer_url: Option<String>,
    /// OIDC client ID.
    pub client_id: Option<String>,
    /// OIDC client secret.
    pub client_secret: Option<String>,
}

// Custom Debug that redacts client_secret to prevent accidental log exposure.
impl std::fmt::Debug for S3OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3OidcConfig")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Nested DPoP configuration from S3.
#[derive(Debug, Deserialize, Default)]
pub struct S3DpopConfig {
    /// Require nonce in DPoP proofs.
    pub nonce_required: Option<bool>,
    /// Maximum age of DPoP proofs in seconds.
    pub max_age_seconds: Option<i64>,
}

/// Nested GitHub App configuration from S3.
#[derive(Deserialize, Default)]
pub struct S3GithubConfig {
    /// GitHub App ID.
    pub app_id: Option<u64>,
    /// GitHub App name (slug).
    pub app_name: Option<String>,
    /// Base64-encoded PEM RSA private key.
    pub app_key: Option<String>,
    /// Webhook secret.
    pub webhook_secret: Option<String>,
    /// OAuth client ID.
    pub client_id: Option<String>,
    /// OAuth client secret.
    pub client_secret: Option<String>,
}

// Custom Debug that redacts secrets to prevent accidental log exposure.
impl std::fmt::Debug for S3GithubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3GithubConfig")
            .field("app_id", &self.app_id)
            .field("app_name", &self.app_name)
            .field("app_key", &"[REDACTED]")
            .field("webhook_secret", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Parsed S3 configuration.
///
/// All fields are optional to allow partial configuration updates.
/// Fields present in S3 config override environment variables.
#[derive(Deserialize, Default)]
pub struct S3Config {
    /// Config version (for future compatibility).
    pub version: Option<u32>,

    // Core settings
    /// Address to listen on.
    pub listen_addr: Option<String>,
    /// Relying Party ID (domain).
    pub rp_id: Option<String>,
    /// Relying Party name.
    pub rp_name: Option<String>,
    /// Base URL for this server.
    pub base_url: Option<String>,
    /// Database URL.
    pub database_url: Option<String>,
    /// Regional DSQL endpoints. Maps AWS region to full connection string.
    /// Example: { "us-east-1": "postgres://vouch@abc123.dsql.us-east-1.on.aws/postgres" }
    pub dsql_endpoints: Option<HashMap<String, String>>,
    /// JWT signing secret.
    pub jwt_secret: Option<String>,
    /// Session duration in hours.
    pub session_hours: Option<u64>,

    // OIDC configuration
    /// Nested OIDC config.
    pub oidc: Option<S3OidcConfig>,

    // TLS configuration
    /// Nested TLS config.
    pub tls: Option<S3TlsConfig>,

    // ACME configuration (promoted to envelope wrapper for external access)
    /// Nested ACME config.
    #[serde(rename = "_acme")]
    pub acme: Option<S3AcmeConfig>,

    // Domain restrictions
    /// Allowed email domains for enrollment.
    pub allowed_domains: Option<Vec<String>>,

    // Branding
    /// Organization name.
    pub org_name: Option<String>,

    // DPoP configuration
    /// Nested DPoP config.
    pub dpop: Option<S3DpopConfig>,

    // CORS
    /// CORS allowed origins.
    pub cors_origins: Option<Vec<String>>,

    // GitHub App configuration
    /// Nested GitHub config.
    pub github: Option<S3GithubConfig>,

    // SSH CA key (base64-encoded PEM Ed25519 private key)
    /// SSH CA private key.
    pub ssh_ca_key: Option<String>,

    // OIDC signing key (base64-encoded PEM EC P-256 private key)
    /// OIDC signing key.
    pub oidc_signing_key: Option<String>,

    // Cleanup settings
    /// Cleanup interval in minutes.
    pub cleanup_interval_minutes: Option<u64>,
    /// Auth events retention in days.
    pub auth_events_retention_days: Option<i64>,
    /// OAuth events retention in days.
    pub oauth_events_retention_days: Option<i64>,

    // CLI download URLs
    /// macOS CLI download URL.
    pub cli_download_macos: Option<String>,
    /// Linux CLI download URL.
    pub cli_download_linux: Option<String>,
    /// Windows CLI download URL.
    pub cli_download_windows: Option<String>,

    // Device code settings
    /// Device code expiration in seconds.
    pub device_code_expires_seconds: Option<u64>,
    /// Device code polling interval in seconds.
    pub device_poll_interval_seconds: Option<u64>,
}

// Custom Debug that redacts secrets to prevent accidental log exposure.
impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("version", &self.version)
            .field("listen_addr", &self.listen_addr)
            .field("rp_id", &self.rp_id)
            .field("rp_name", &self.rp_name)
            .field("base_url", &self.base_url)
            .field("database_url", &self.database_url)
            .field("dsql_endpoints", &self.dsql_endpoints)
            .field("jwt_secret", &"[REDACTED]")
            .field("session_hours", &self.session_hours)
            .field("oidc", &self.oidc)
            .field("tls", &self.tls)
            .field("acme", &self.acme)
            .field("allowed_domains", &self.allowed_domains)
            .field("org_name", &self.org_name)
            .field("dpop", &self.dpop)
            .field("cors_origins", &self.cors_origins)
            .field("github", &self.github)
            .field("ssh_ca_key", &"[REDACTED]")
            .field("oidc_signing_key", &"[REDACTED]")
            .field("cleanup_interval_minutes", &self.cleanup_interval_minutes)
            .field(
                "auth_events_retention_days",
                &self.auth_events_retention_days,
            )
            .field(
                "oauth_events_retention_days",
                &self.oauth_events_retention_days,
            )
            .field("cli_download_macos", &self.cli_download_macos)
            .field("cli_download_linux", &self.cli_download_linux)
            .field("cli_download_windows", &self.cli_download_windows)
            .field(
                "device_code_expires_seconds",
                &self.device_code_expires_seconds,
            )
            .field(
                "device_poll_interval_seconds",
                &self.device_poll_interval_seconds,
            )
            .finish()
    }
}

/// Fetch raw bytes and ETag from S3.
async fn fetch_s3_raw(client: &S3Client, source: &S3ConfigSource) -> Result<(Vec<u8>, String)> {
    let response = client
        .get_object()
        .bucket(&source.bucket)
        .key(&source.key)
        .send()
        .await
        .with_context(|| {
            format!(
                "Failed to fetch S3 config from s3://{}/{}",
                source.bucket, source.key
            )
        })?;

    let etag = response.e_tag().map(|s| s.to_string()).unwrap_or_default();

    let body = response
        .body
        .collect()
        .await
        .context("Failed to read S3 config body")?;

    Ok((body.into_bytes().to_vec(), etag))
}

/// Fetch configuration from S3.
///
/// If the S3 object is an encrypted envelope (contains `kms_key_id`), decrypts it
/// using NitroTPM-attested KMS before parsing. The `tls` and `version` fields from
/// the envelope wrapper are merged into the resulting `S3Config`.
///
/// If the S3 object is plain JSON (no `kms_key_id`), parses it directly (backwards
/// compatible with existing configs).
///
/// # Arguments
/// * `s3_client` - S3 client for fetching the config object
/// * `source` - S3 bucket/key/region configuration
/// * `kms_client` - Optional KMS client; required only when the config is an encrypted envelope
///
/// Returns the parsed config and the ETag for change detection.
pub async fn fetch_s3_config(
    s3_client: &S3Client,
    source: &S3ConfigSource,
    kms_client: Option<&KmsClient>,
) -> Result<(S3Config, String)> {
    let (raw_bytes, etag) = fetch_s3_raw(s3_client, source).await?;

    if tpm_decrypt::is_encrypted_envelope(&raw_bytes) {
        tracing::info!("S3 config format: encrypted envelope (KMS + NitroTPM attestation)");

        let kms = kms_client.ok_or_else(|| {
            anyhow::anyhow!(
                "S3 config is an encrypted envelope but no KMS client is available. \
                 This should not happen when running on AWS."
            )
        })?;

        // Parse the envelope wrapper
        let envelope: tpm_decrypt::EncryptedEnvelope =
            serde_json::from_slice(&raw_bytes).context("Failed to parse encrypted envelope")?;

        tracing::info!(
            "Envelope version: {}, KMS key: {}, TLS in wrapper: {}",
            envelope.version,
            envelope.kms_key_id,
            envelope.tls.is_some()
        );

        // Extract wrapper fields (TLS, ACME, and version) before decryption
        let wrapper_tls = envelope.tls.clone();
        let wrapper_acme = envelope.acme.clone();
        let wrapper_version = envelope.version;

        // Decrypt the inner config via attested KMS call
        let plaintext = tpm_decrypt::decrypt_envelope(kms, &envelope).await?;

        // Parse the decrypted JSON as S3Config
        let mut config: S3Config =
            serde_json::from_slice(&plaintext).context("Failed to parse decrypted S3 config")?;

        // Merge wrapper fields into the config
        // TLS from wrapper takes precedence (allows hot-reload without decryption)
        if wrapper_tls.is_some() {
            config.tls = wrapper_tls;
        }
        // ACME from wrapper (for external certificate renewal processes)
        if wrapper_acme.is_some() {
            config.acme = wrapper_acme;
        }
        // Version from wrapper (envelope version, not inner config version)
        if config.version.is_none() {
            config.version = Some(wrapper_version);
        }

        tracing::info!("S3 config decrypted and parsed successfully");
        Ok((config, etag))
    } else {
        tracing::info!("S3 config format: plain JSON");
        let config: S3Config =
            serde_json::from_slice(&raw_bytes).context("Failed to parse S3 config JSON")?;
        Ok((config, etag))
    }
}

/// Check if configuration has changed using HEAD request.
///
/// Returns `Some(new_etag)` if the config has changed, `None` if unchanged.
pub async fn check_config_changed(
    client: &S3Client,
    source: &S3ConfigSource,
    current_etag: &str,
) -> Result<Option<String>> {
    let response = client
        .head_object()
        .bucket(&source.bucket)
        .key(&source.key)
        .send()
        .await
        .with_context(|| {
            format!(
                "Failed to check S3 config at s3://{}/{}",
                source.bucket, source.key
            )
        })?;

    let new_etag = response.e_tag().unwrap_or_default();

    if new_etag != current_etag {
        Ok(Some(new_etag.to_string()))
    } else {
        Ok(None)
    }
}

/// Start background polling task for S3 configuration changes.
///
/// This task:
/// 1. Polls S3 every `poll_interval_seconds` using HEAD requests
/// 2. Re-fetches config only when ETag changes
/// 3. Automatically reloads TLS certificates when they change
///
/// For encrypted envelope configs, runtime updates only read TLS from the
/// plaintext wrapper — no KMS decryption is needed for hot-reload.
pub fn start_s3_config_task(
    s3_client: S3Client,
    source: S3ConfigSource,
    config: Arc<ArcSwap<ServerConfig>>,
    tls_config: Option<RustlsConfig>,
    initial_etag: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut current_etag = initial_etag;
        let interval = std::time::Duration::from_secs(source.poll_interval_seconds);

        loop {
            tokio::time::sleep(interval).await;

            // HEAD request to check ETag
            match check_config_changed(&s3_client, &source, &current_etag).await {
                Ok(None) => {
                    tracing::trace!("S3 config unchanged (etag: {})", current_etag);
                }
                Ok(Some(new_etag)) => {
                    tracing::info!(
                        "S3 config changed (old: {}, new: {})",
                        current_etag,
                        new_etag
                    );

                    // For runtime updates, only TLS can change. If the config is
                    // an encrypted envelope, TLS is in the plaintext wrapper — we
                    // don't need to decrypt. Fetch raw bytes and handle both cases.
                    match fetch_runtime_config(&s3_client, &source).await {
                        Ok((s3_cfg, etag)) => {
                            if let Err(e) = apply_config_update(&config, &tls_config, s3_cfg).await
                            {
                                tracing::error!("Failed to apply config update: {e:#}");
                            } else {
                                current_etag = etag;
                                tracing::info!("S3 config applied successfully");
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to fetch S3 config: {e:#}");
                        }
                    }
                }
                Err(e) => {
                    // S3 unreachable - log warning and continue with current config
                    tracing::warn!("Failed to check S3 config: {e:#}, continuing with current");
                }
            }
        }
    })
}

/// Fetch S3 config for runtime updates (polling).
///
/// For encrypted envelopes, only extracts the plaintext wrapper fields (TLS, version)
/// without performing KMS decryption. For plain JSON, parses the full config.
///
/// Since `apply_config_update` only applies TLS changes at runtime, this is sufficient.
async fn fetch_runtime_config(
    s3_client: &S3Client,
    source: &S3ConfigSource,
) -> Result<(S3Config, String)> {
    let (raw_bytes, etag) = fetch_s3_raw(s3_client, source).await?;

    if tpm_decrypt::is_encrypted_envelope(&raw_bytes) {
        // Encrypted envelope — extract only the wrapper fields (no decryption needed).
        // Only TLS changes are applied at runtime, and TLS lives in the wrapper.
        let envelope: tpm_decrypt::EncryptedEnvelope = serde_json::from_slice(&raw_bytes)
            .context("Failed to parse encrypted envelope during polling")?;

        let config = S3Config {
            version: Some(envelope.version),
            tls: envelope.tls,
            acme: envelope.acme,
            ..S3Config::default()
        };

        tracing::debug!("Encrypted envelope: extracted wrapper TLS for runtime update");
        Ok((config, etag))
    } else {
        // Plain JSON — parse full config (unchanged behavior)
        let config: S3Config =
            serde_json::from_slice(&raw_bytes).context("Failed to parse S3 config JSON")?;
        Ok((config, etag))
    }
}

/// Apply S3 configuration update to the running server.
///
/// This function:
/// 1. Creates a new ServerConfig by merging S3 values
/// 2. Reloads TLS certificates if they changed
/// 3. Atomically swaps the config
async fn apply_config_update(
    config: &Arc<ArcSwap<ServerConfig>>,
    tls_config: &Option<RustlsConfig>,
    s3_config: S3Config,
) -> Result<()> {
    // Load current config and clone it for modification
    let current = config.load();
    let mut new_config = (**current).clone();

    // Track if TLS config changed
    let old_tls_cert = new_config.tls_cert.clone();
    let old_tls_key = new_config
        .tls_key
        .as_ref()
        .map(|s| s.expose_secret().to_string());

    // Merge S3 config
    new_config.merge_s3_config(&s3_config, true); // Runtime update - block sensitive fields

    // Check if TLS config changed
    let tls_changed = new_config.tls_cert != old_tls_cert
        || new_config
            .tls_key
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            != old_tls_key;

    // Reload TLS if configured and changed
    if tls_changed
        && let Some(tls) = tls_config
        && let (Some(cert), Some(key)) = (&new_config.tls_cert, &new_config.tls_key)
    {
        tracing::info!("TLS config changed, reloading certificates");
        super::tls::reload_tls_from_config(tls, cert, key).await?;
        tracing::info!("TLS certificates reloaded successfully");
    }

    // Atomically swap the config
    config.store(Arc::new(new_config));

    Ok(())
}

impl ServerConfig {
    /// Merge S3 configuration into this config.
    ///
    /// # Arguments
    /// * `s3` - The S3 configuration to merge
    /// * `is_runtime_update` - If true, only TLS config can be updated
    ///
    /// # Runtime Updates
    /// Only TLS certificates can be updated at runtime (for hot-reload).
    /// All other configuration changes require a server restart.
    pub fn merge_s3_config(&mut self, s3: &S3Config, is_runtime_update: bool) {
        // Runtime updates: ONLY allow TLS changes
        if is_runtime_update {
            if let Some(tls) = &s3.tls {
                if let Some(v) = &tls.cert {
                    self.tls_cert = Some(v.clone());
                }
                if let Some(v) = &tls.key {
                    self.tls_key = Some(SecretString::from(v.clone()));
                }
            }
            // All other fields are ignored at runtime
            return;
        }

        // Initial startup: apply all config

        // Database URL - priority: dsql_endpoints > database_url
        if let Some(endpoints) = &s3.dsql_endpoints {
            match crate::config::resolve_dsql_endpoints(endpoints) {
                Ok(resolved) => {
                    // Log which location was used (AZ or region)
                    let location = std::env::var("AWS_AZ")
                        .or_else(|_| std::env::var("AWS_REGION"))
                        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                        .unwrap_or_else(|_| "unknown".into());
                    tracing::info!("Using dsql_endpoints for location {}", location);
                    self.database_url = resolved;
                }
                Err(e) => {
                    tracing::error!("Failed to resolve dsql_endpoints: {e}");
                    // Fall through to database_url if present
                    if let Some(v) = &s3.database_url {
                        self.database_url = v.clone();
                    }
                }
            }
        } else if let Some(v) = &s3.database_url {
            self.database_url = v.clone();
        }

        // Core settings
        if let Some(v) = &s3.listen_addr {
            self.listen_addr = v.clone();
        }
        if let Some(v) = &s3.rp_id {
            self.rp_id = v.clone();
        }
        if let Some(v) = &s3.rp_name {
            self.rp_name = v.clone();
        }
        if let Some(v) = &s3.base_url {
            self.base_url = v.clone();
        }
        if let Some(v) = &s3.jwt_secret {
            self.jwt_secret = SecretString::from(v.clone());
        }
        if let Some(v) = s3.session_hours {
            self.session_hours = v;
        }

        // OIDC configuration
        if let Some(oidc) = &s3.oidc {
            if let Some(v) = &oidc.issuer_url {
                self.oidc_issuer_url = Some(v.clone());
            }
            if let Some(v) = &oidc.client_id {
                self.oidc_client_id = Some(v.clone());
            }
            if let Some(v) = &oidc.client_secret {
                self.oidc_client_secret = Some(SecretString::from(v.clone()));
            }
        }

        // TLS configuration
        if let Some(tls) = &s3.tls {
            if let Some(v) = &tls.cert {
                self.tls_cert = Some(v.clone());
            }
            if let Some(v) = &tls.key {
                self.tls_key = Some(SecretString::from(v.clone()));
            }
        }

        // Domain restrictions
        if let Some(v) = &s3.allowed_domains {
            self.allowed_domains = Some(v.clone());
        }

        // Branding
        if let Some(v) = &s3.org_name {
            self.org_name = Some(v.clone());
        }

        // DPoP configuration
        if let Some(dpop) = &s3.dpop {
            if let Some(v) = dpop.nonce_required {
                self.dpop_nonce_required = v;
            }
            if let Some(v) = dpop.max_age_seconds {
                self.dpop_max_age_seconds = v;
            }
        }

        // CORS
        if let Some(v) = &s3.cors_origins {
            self.cors_origins = Some(v.clone());
        }

        // GitHub App configuration
        if let Some(github) = &s3.github {
            if let Some(v) = github.app_id {
                self.github_app_id = Some(v);
            }
            if let Some(v) = &github.app_name {
                self.github_app_name = Some(v.clone());
            }
            if let Some(v) = &github.app_key {
                self.github_app_key = Some(SecretString::from(v.clone()));
            }
            if let Some(v) = &github.webhook_secret {
                self.github_webhook_secret = Some(SecretString::from(v.clone()));
            }
            if let Some(v) = &github.client_id {
                self.github_app_client_id = Some(v.clone());
            }
            if let Some(v) = &github.client_secret {
                self.github_app_client_secret = Some(SecretString::from(v.clone()));
            }
        }

        // SSH CA key
        if let Some(v) = &s3.ssh_ca_key {
            self.ssh_ca_key = Some(SecretString::from(v.clone()));
        }

        // OIDC signing key
        if let Some(v) = &s3.oidc_signing_key {
            self.oidc_signing_key = Some(SecretString::from(v.clone()));
        }

        // Cleanup settings
        if let Some(v) = s3.cleanup_interval_minutes {
            self.cleanup_interval_minutes = v;
        }
        if let Some(v) = s3.auth_events_retention_days {
            self.auth_events_retention_days = v;
        }
        if let Some(v) = s3.oauth_events_retention_days {
            self.oauth_events_retention_days = v;
        }

        // CLI download URLs
        if let Some(v) = &s3.cli_download_macos {
            self.cli_download_macos = Some(v.clone());
        }
        if let Some(v) = &s3.cli_download_linux {
            self.cli_download_linux = Some(v.clone());
        }
        if let Some(v) = &s3.cli_download_windows {
            self.cli_download_windows = Some(v.clone());
        }

        // Device code settings
        if let Some(v) = s3.device_code_expires_seconds {
            self.device_code_expires_seconds = v;
        }
        if let Some(v) = s3.device_poll_interval_seconds {
            self.device_poll_interval_seconds = v;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_merge_s3_config_empty() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config::default();

        let original_rp_id = config.rp_id.clone();
        config.merge_s3_config(&s3, false);

        // Should be unchanged
        assert_eq!(config.rp_id, original_rp_id);
    }

    #[test]
    fn test_merge_s3_config_overrides() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            rp_id: Some("new.example.com".to_string()),
            session_hours: Some(12),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false);

        assert_eq!(config.rp_id, "new.example.com");
        assert_eq!(config.session_hours, 12);
    }

    #[test]
    fn test_merge_s3_config_nested_tls() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            tls: Some(S3TlsConfig {
                cert: Some("base64cert".to_string()),
                key: Some("base64key".to_string()),
            }),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false);

        assert_eq!(config.tls_cert, Some("base64cert".to_string()));
        assert!(config.tls_key.is_some());
    }

    #[test]
    fn test_merge_s3_config_nested_oidc() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            oidc: Some(S3OidcConfig {
                issuer_url: Some("https://new-issuer.com".to_string()),
                client_id: Some("new-client-id".to_string()),
                client_secret: Some("new-secret".to_string()),
            }),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false);

        assert_eq!(
            config.oidc_issuer_url,
            Some("https://new-issuer.com".to_string())
        );
        assert_eq!(config.oidc_client_id, Some("new-client-id".to_string()));
    }

    #[test]
    fn test_merge_s3_config_nested_dpop() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            dpop: Some(S3DpopConfig {
                nonce_required: Some(true),
                max_age_seconds: Some(600),
            }),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false);

        assert!(config.dpop_nonce_required);
        assert_eq!(config.dpop_max_age_seconds, 600);
    }

    #[test]
    fn test_merge_s3_config_nested_github() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            github: Some(S3GithubConfig {
                app_id: Some(12345),
                app_name: Some("my-app".to_string()),
                app_key: Some("base64key".to_string()),
                webhook_secret: Some("secret".to_string()),
                client_id: Some("client-id".to_string()),
                client_secret: Some("client-secret".to_string()),
            }),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false);

        assert_eq!(config.github_app_id, Some(12345));
        assert_eq!(config.github_app_name, Some("my-app".to_string()));
        assert!(config.github_app_key.is_some());
    }

    #[test]
    fn test_merge_s3_config_runtime_only_allows_tls() {
        let mut config = crate::test_utils::test_config();
        let original_rp_id = config.rp_id.clone();
        let original_session_hours = config.session_hours;

        let s3 = S3Config {
            rp_id: Some("new.example.com".to_string()),
            session_hours: Some(24),
            tls: Some(S3TlsConfig {
                cert: Some("new_cert".to_string()),
                key: Some("new_key".to_string()),
            }),
            ..Default::default()
        };

        // Runtime update - only TLS should change
        config.merge_s3_config(&s3, true);

        // rp_id and session_hours should be UNCHANGED
        assert_eq!(config.rp_id, original_rp_id);
        assert_eq!(config.session_hours, original_session_hours);

        // TLS should be updated
        assert_eq!(config.tls_cert, Some("new_cert".to_string()));
        assert!(config.tls_key.is_some());
    }

    #[test]
    fn test_merge_s3_config_startup_allows_all() {
        let mut config = crate::test_utils::test_config();

        let s3 = S3Config {
            rp_id: Some("new.example.com".to_string()),
            session_hours: Some(24),
            tls: Some(S3TlsConfig {
                cert: Some("new_cert".to_string()),
                key: Some("new_key".to_string()),
            }),
            ..Default::default()
        };

        // Startup (not runtime) - all fields should update
        config.merge_s3_config(&s3, false);

        assert_eq!(config.rp_id, "new.example.com");
        assert_eq!(config.session_hours, 24);
        assert_eq!(config.tls_cert, Some("new_cert".to_string()));
    }

    #[test]
    fn test_s3_config_deserialization() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "session_hours": 12,
            "oidc": {
                "issuer_url": "https://accounts.google.com",
                "client_id": "test-id"
            },
            "tls": {
                "cert": "base64cert",
                "key": "base64key"
            },
            "allowed_domains": ["example.com", "test.com"]
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert_eq!(config.version, Some(1));
        assert_eq!(config.rp_id, Some("vouch.example.com".to_string()));
        assert_eq!(config.session_hours, Some(12));
        assert!(config.oidc.is_some());
        assert!(config.tls.is_some());
        assert_eq!(
            config.allowed_domains,
            Some(vec!["example.com".to_string(), "test.com".to_string()])
        );
    }

    #[test]
    fn test_s3_config_deserialization_with_acme() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "_acme": {
                "account_key": "secret-acme-key",
                "email": "admin@example.com"
            }
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert_eq!(config.version, Some(1));
        assert_eq!(config.rp_id, Some("vouch.example.com".to_string()));
        assert!(config.acme.is_some());
        let acme = config.acme.unwrap();
        assert_eq!(acme.account_key, "secret-acme-key");
        assert_eq!(acme.email, "admin@example.com");
    }

    #[test]
    fn test_s3_config_dsql_endpoints_deserialization() {
        let json = r#"{
            "version": 1,
            "dsql_endpoints": {
                "us-east-1": "postgres://vouch@abc123.dsql.us-east-1.on.aws/postgres",
                "us-west-2": "postgres://vouch@xyz789.dsql.us-west-2.on.aws/postgres"
            },
            "rp_id": "vouch.example.com"
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert!(config.dsql_endpoints.is_some());
        let endpoints = config.dsql_endpoints.unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints.get("us-east-1"),
            Some(&"postgres://vouch@abc123.dsql.us-east-1.on.aws/postgres".to_string())
        );
        assert_eq!(
            endpoints.get("us-west-2"),
            Some(&"postgres://vouch@xyz789.dsql.us-west-2.on.aws/postgres".to_string())
        );
    }
}
