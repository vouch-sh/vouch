// SPDX-License-Identifier: Apache-2.0 OR MIT
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

use rustls::crypto::hpke::{HpkePrivateKey, HpkePublicKey};

use crate::config::{IdpConfig, OidcProviderConfig, SamlProviderConfig, ServerConfig};
use crate::crypto::tpm_decrypt;
use crate::infra::kms_arn::KmsArnResolver;

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
/// Stored as `_acme` in the S3 config JSON so that external ACME certificate
/// renewal processes can read it directly from the S3 object.
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

/// Document encryption key configuration from S3.
///
/// When present in the S3 config, the server uses the P-384 private key
/// (decrypted from KMS at startup) for HPKE document encryption.
/// Provisioned by the `generate-document-key` subcommand.
#[derive(Clone, Deserialize, Serialize)]
pub struct S3DocumentKeyConfig {
    /// KMS key ID that protects the encrypted private key.
    pub kms_key_id: String,
    /// Base64-encoded KMS ciphertext blob (encrypted P-384 private key DER).
    pub encrypted_private_key: String,
}

impl std::fmt::Debug for S3DocumentKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3DocumentKeyConfig")
            .field("kms_key_id", &self.kms_key_id)
            .field("encrypted_private_key", &"[REDACTED]")
            .finish()
    }
}

/// Decrypted P-384 HPKE key pair for document encryption.
///
/// Recovered from `S3DocumentKeyConfig` by decrypting the private key via KMS.
pub struct DocumentKeyMaterial {
    /// P-384 public key (uncompressed point, 97 bytes).
    pub public_key: HpkePublicKey,
    /// P-384 private key (scalar, 48 bytes). Zeroizes on drop.
    pub private_key: HpkePrivateKey,
}

impl std::fmt::Debug for DocumentKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentKeyMaterial")
            .field(
                "public_key",
                &format_args!("[{} bytes]", self.public_key.0.len()),
            )
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// One identity provider entry inside the S3 config `idps` array.
///
/// Uses an internally-tagged enum: each object carries a `type` field whose
/// value is `"oidc"` or `"saml"`, plus the type-specific fields. The `id` is
/// a top-level field on every variant.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum S3IdpEntry {
    Oidc {
        id: String,
        issuer: String,
        client_id: String,
        client_secret: String,
    },
    Saml {
        id: String,
        metadata_url: String,
        #[serde(default)]
        sp_entity_id: Option<String>,
        #[serde(default)]
        email_attribute: Option<String>,
        #[serde(default)]
        domain_attribute: Option<String>,
    },
}

impl std::fmt::Debug for S3IdpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oidc {
                id,
                issuer,
                client_id,
                ..
            } => f
                .debug_struct("S3IdpEntry::Oidc")
                .field("id", id)
                .field("issuer", issuer)
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .finish(),
            Self::Saml {
                id,
                metadata_url,
                sp_entity_id,
                email_attribute,
                domain_attribute,
            } => f
                .debug_struct("S3IdpEntry::Saml")
                .field("id", id)
                .field("metadata_url", metadata_url)
                .field("sp_entity_id", sp_entity_id)
                .field("email_attribute", email_attribute)
                .field("domain_attribute", domain_attribute)
                .finish(),
        }
    }
}

impl S3IdpEntry {
    fn into_idp_config(self) -> IdpConfig {
        match self {
            Self::Oidc {
                id,
                issuer,
                client_id,
                client_secret,
            } => IdpConfig::Oidc(OidcProviderConfig {
                id,
                issuer_url: issuer,
                client_id,
                client_secret: SecretString::from(client_secret),
            }),
            Self::Saml {
                id,
                metadata_url,
                sp_entity_id,
                email_attribute,
                domain_attribute,
            } => IdpConfig::Saml(SamlProviderConfig {
                id,
                metadata_url,
                sp_entity_id,
                email_attribute,
                domain_attribute,
            }),
        }
    }
}

/// Nested DPoP configuration from S3.
#[derive(Debug, Deserialize, Default)]
pub struct S3DpopConfig {
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

    // Identity providers (OIDC + SAML unified).
    /// Ordered IdP list. Each entry carries `type: "oidc" | "saml"`, `id`, and
    /// type-specific fields. Order controls login-page button order.
    pub idps: Option<Vec<S3IdpEntry>>,

    // TLS configuration
    /// Nested TLS config.
    pub tls: Option<S3TlsConfig>,

    // ACME configuration
    /// Nested ACME config.
    #[serde(rename = "_acme")]
    pub acme: Option<S3AcmeConfig>,

    // Domain restrictions
    /// Allowed email domains for enrollment.
    pub allowed_domains: Option<Vec<String>>,

    // Branding
    /// Organization name.
    pub org_name: Option<String>,

    // Protected Resource Metadata (RFC 9728)
    /// Human-readable name of this protected resource.
    pub resource_name: Option<String>,
    /// URL of developer documentation for this protected resource.
    pub resource_documentation: Option<String>,
    /// URL of the resource's data-use policy.
    pub resource_policy_uri: Option<String>,
    /// URL of the resource's terms of service.
    pub resource_tos_uri: Option<String>,

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

    /// AWS KMS key ID for SSH CA signing (multi-region `mrk-` prefix).
    pub ssh_ca_kms_key_id: Option<String>,

    // OIDC signing key (base64-encoded PEM EC P-256 private key)
    /// OIDC signing key.
    pub oidc_signing_key: Option<String>,

    /// AWS KMS key ID for OIDC signing (multi-region `mrk-` prefix).
    pub oidc_signing_kms_key_id: Option<String>,

    /// OIDC RSA signing key (base64-encoded PEM RSA-3072 private key).
    pub oidc_rsa_signing_key: Option<String>,

    /// AWS KMS key ID for OIDC RSA signing (RSA_3072).
    pub oidc_rsa_signing_kms_key_id: Option<String>,

    /// AWS KMS key ID for HMAC state token signing.
    pub jwt_hmac_kms_key_id: Option<String>,

    /// AWS account ID that owns the KMS keys configured above.
    ///
    /// When set, the server constructs full KMS ARNs at startup using
    /// `AWS_PARTITION`, `AWS_REGION`, and this account ID so it can address
    /// keys in a different account. Bare values that are already ARNs
    /// (`arn:...`) are passed through unchanged.
    pub kms_account_id: Option<String>,

    /// mTLS listener port.
    pub mtls_port: Option<u16>,

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

    // Document encryption key
    /// P-384 document encryption key (provisioned by `generate-document-key`).
    pub document_key: Option<S3DocumentKeyConfig>,
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
            .field("idps", &self.idps)
            .field("tls", &self.tls)
            .field("acme", &self.acme)
            .field("allowed_domains", &self.allowed_domains)
            .field("org_name", &self.org_name)
            .field("resource_name", &self.resource_name)
            .field("resource_documentation", &self.resource_documentation)
            .field("resource_policy_uri", &self.resource_policy_uri)
            .field("resource_tos_uri", &self.resource_tos_uri)
            .field("dpop", &self.dpop)
            .field("cors_origins", &self.cors_origins)
            .field("github", &self.github)
            .field("ssh_ca_key", &"[REDACTED]")
            .field("ssh_ca_kms_key_id", &self.ssh_ca_kms_key_id)
            .field("oidc_signing_key", &"[REDACTED]")
            .field("oidc_signing_kms_key_id", &self.oidc_signing_kms_key_id)
            .field("oidc_rsa_signing_key", &"[REDACTED]")
            .field(
                "oidc_rsa_signing_kms_key_id",
                &self.oidc_rsa_signing_kms_key_id,
            )
            .field("jwt_hmac_kms_key_id", &self.jwt_hmac_kms_key_id)
            .field("kms_account_id", &self.kms_account_id)
            .field("mtls_port", &self.mtls_port)
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
            .field("document_key", &self.document_key)
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

/// Decrypt a `document_key` config entry to recover the P-384 HPKE key pair.
///
/// Calls `kms:Decrypt` (uses NitroTPM attestation when available) to decrypt
/// the private key ciphertext, then derives the HPKE key pair from the DER.
///
/// `key_arn` is the already-resolved KMS key identifier (full ARN when
/// `kms_account_id` is configured, otherwise the raw value from S3 config).
async fn decrypt_document_key(
    kms_client: &KmsClient,
    doc_key: &S3DocumentKeyConfig,
    key_arn: &str,
    use_attestation: bool,
) -> Result<DocumentKeyMaterial> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let encrypted_bytes = BASE64
        .decode(&doc_key.encrypted_private_key)
        .context("Failed to base64-decode document_key.encrypted_private_key")?;

    let plaintext =
        tpm_decrypt::kms_decrypt(kms_client, key_arn, &encrypted_bytes, use_attestation)
            .await
            .context("KMS Decrypt for document_key failed")?;

    let (public_key, private_key) =
        crate::crypto::document_crypto::p384_hpke_keys_from_private_key_der(&plaintext)
            .context("Failed to extract P-384 HPKE keys from document_key DER")?;

    tracing::info!("Document encryption key decrypted via KMS");

    Ok(DocumentKeyMaterial {
        public_key,
        private_key,
    })
}

/// Fetch configuration from S3.
///
/// Parses the S3 object as plain JSON. If the config contains a `document_key`
/// section, the P-384 private key is decrypted via KMS (with NitroTPM attestation
/// when available) and returned as `DocumentKeyMaterial`.
///
/// # Arguments
/// * `s3_client` - S3 client for fetching the config object
/// * `source` - S3 bucket/key/region configuration
/// * `kms_client` - Optional KMS client; required for document key decryption
/// * `use_attestation` - Whether to use NitroTPM attestation for KMS calls
///
/// Returns the parsed config, the ETag for change detection, and optionally the
/// document key material for `HpkeDocumentCrypto`.
pub async fn fetch_s3_config(
    s3_client: &S3Client,
    source: &S3ConfigSource,
    kms_client: Option<&KmsClient>,
    use_attestation: bool,
) -> Result<(S3Config, String, Option<DocumentKeyMaterial>)> {
    let (raw_bytes, etag) = fetch_s3_raw(s3_client, source).await?;

    let config: S3Config =
        serde_json::from_slice(&raw_bytes).context("Failed to parse S3 config JSON")?;

    let doc_keys = if let Some(doc_key_config) = &config.document_key {
        let kms = kms_client.ok_or_else(|| {
            anyhow::anyhow!("S3 config has document_key but no KMS client is available")
        })?;
        let resolver = KmsArnResolver::from_env(config.kms_account_id.as_deref());
        let key_arn = resolver.resolve(&doc_key_config.kms_key_id);
        Some(decrypt_document_key(kms, doc_key_config, &key_arn, use_attestation).await?)
    } else {
        None
    };

    Ok((config, etag, doc_keys))
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

                    // For runtime updates, only TLS can change.
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
/// Parses the S3 object as plain JSON. Since `apply_config_update` only applies
/// TLS changes at runtime, most fields are ignored.
async fn fetch_runtime_config(
    s3_client: &S3Client,
    source: &S3ConfigSource,
) -> Result<(S3Config, String)> {
    let (raw_bytes, etag) = fetch_s3_raw(s3_client, source).await?;
    let config: S3Config =
        serde_json::from_slice(&raw_bytes).context("Failed to parse S3 config JSON")?;
    Ok((config, etag))
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

    // Merge S3 config (runtime update — oidc block check is skipped for runtime updates)
    new_config.merge_s3_config(&s3_config, true)?;

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
        super::tls::reload_tls_from_config(tls, cert, key)?;
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
    pub fn merge_s3_config(
        &mut self,
        s3: &S3Config,
        is_runtime_update: bool,
    ) -> anyhow::Result<()> {
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
            return Ok(());
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

        // Unified IdP list (OIDC + SAML). Any legacy single-provider blocks
        // (`oidc` / `saml`) in the JSON are silently ignored by serde because
        // there are no struct fields to deserialize into.
        if let Some(idps) = &s3.idps {
            self.idps = idps
                .iter()
                .cloned()
                .map(S3IdpEntry::into_idp_config)
                .collect();
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

        // Protected Resource Metadata (RFC 9728)
        if let Some(v) = &s3.resource_name {
            self.resource_name = Some(v.clone());
        }
        if let Some(v) = &s3.resource_documentation {
            self.resource_documentation = Some(v.clone());
        }
        if let Some(v) = &s3.resource_policy_uri {
            self.resource_policy_uri = Some(v.clone());
        }
        if let Some(v) = &s3.resource_tos_uri {
            self.resource_tos_uri = Some(v.clone());
        }

        // DPoP configuration
        if let Some(dpop) = &s3.dpop
            && let Some(v) = dpop.max_age_seconds
        {
            self.dpop_max_age_seconds = v;
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
        if let Some(v) = &s3.ssh_ca_kms_key_id {
            self.ssh_ca_kms_key_id = Some(v.clone());
        }

        // OIDC signing key
        if let Some(v) = &s3.oidc_signing_key {
            self.oidc_signing_key = Some(SecretString::from(v.clone()));
        }
        if let Some(v) = &s3.oidc_signing_kms_key_id {
            self.oidc_signing_kms_key_id = Some(v.clone());
        }

        // OIDC RSA signing key
        if let Some(v) = &s3.oidc_rsa_signing_key {
            self.oidc_rsa_signing_key = Some(SecretString::from(v.clone()));
        }
        if let Some(v) = &s3.oidc_rsa_signing_kms_key_id {
            self.oidc_rsa_signing_kms_key_id = Some(v.clone());
        }

        // JWT HMAC KMS key ID
        if let Some(v) = &s3.jwt_hmac_kms_key_id {
            self.jwt_hmac_kms_key_id = Some(v.clone());
        }

        // KMS account ID (for cross-account ARN construction)
        if let Some(v) = &s3.kms_account_id {
            self.kms_account_id = Some(v.clone());
        }

        // mTLS port
        if let Some(v) = s3.mtls_port {
            self.mtls_port = v;
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    #[test]
    fn test_merge_s3_config_empty() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config::default();

        let original_rp_id = config.rp_id.clone();
        config.merge_s3_config(&s3, false).unwrap();

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

        config.merge_s3_config(&s3, false).unwrap();

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

        config.merge_s3_config(&s3, false).unwrap();

        assert_eq!(config.tls_cert, Some("base64cert".to_string()));
        assert!(config.tls_key.is_some());
    }

    #[test]
    fn test_merge_s3_config_legacy_oidc_and_saml_blocks_silently_ignored() {
        // Legacy single-provider `oidc` / `saml` blocks in the S3 JSON are
        // silently ignored: serde drops unknown top-level fields, the merge
        // succeeds, and the existing `idps` on the config remain unchanged.
        let json = r#"{
            "oidc": { "issuer_url": "https://x", "client_id": "y" },
            "saml": { "idp_metadata_url": "https://z" }
        }"#;
        let s3: S3Config = serde_json::from_str(json).expect("parse");
        let mut config = crate::test_utils::test_config();
        let original_idp_count = config.idps.len();

        config.merge_s3_config(&s3, false).unwrap();

        assert_eq!(
            config.idps.len(),
            original_idp_count,
            "legacy blocks must not alter the idps list"
        );
    }

    #[test]
    fn test_merge_s3_config_nested_dpop() {
        let mut config = crate::test_utils::test_config();
        let s3 = S3Config {
            dpop: Some(S3DpopConfig {
                max_age_seconds: Some(600),
            }),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false).unwrap();

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

        config.merge_s3_config(&s3, false).unwrap();

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
        config.merge_s3_config(&s3, true).unwrap();

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
        config.merge_s3_config(&s3, false).unwrap();

        assert_eq!(config.rp_id, "new.example.com");
        assert_eq!(config.session_hours, 24);
        assert_eq!(config.tls_cert, Some("new_cert".to_string()));
    }

    #[test]
    fn test_s3_config_deserialization() {
        // Legacy top-level `oidc` block is unknown to serde and silently dropped.
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
        assert!(config.tls.is_some());
        assert!(
            config.idps.is_none(),
            "legacy 'oidc' block must not populate the new 'idps' field"
        );
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
    fn test_s3_config_deserialization_with_document_key() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "document_key": {
                "kms_key_id": "mrk-doc-key-123",
                "encrypted_private_key": "YmFzZTY0Y2lwaGVydGV4dA=="
            }
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert!(config.document_key.is_some());
        let dk = config.document_key.unwrap();
        assert_eq!(dk.kms_key_id, "mrk-doc-key-123");
        assert_eq!(dk.encrypted_private_key, "YmFzZTY0Y2lwaGVydGV4dA==");
    }

    #[test]
    fn test_s3_config_deserialization_without_document_key() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com"
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");
        assert!(config.document_key.is_none());
    }

    #[test]
    fn test_s3_config_deserialization_with_kms_key_ids() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "ssh_ca_kms_key_id": "mrk-abc123def456",
            "oidc_signing_kms_key_id": "mrk-789ghi012jkl",
            "jwt_hmac_kms_key_id": "mrk-hmac-test"
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert_eq!(
            config.ssh_ca_kms_key_id,
            Some("mrk-abc123def456".to_string())
        );
        assert_eq!(
            config.oidc_signing_kms_key_id,
            Some("mrk-789ghi012jkl".to_string())
        );
        assert_eq!(
            config.jwt_hmac_kms_key_id,
            Some("mrk-hmac-test".to_string())
        );
    }

    #[test]
    fn test_merge_s3_config_kms_key_ids() {
        let mut config = crate::test_utils::test_config();
        assert!(config.ssh_ca_kms_key_id.is_none());
        assert!(config.oidc_signing_kms_key_id.is_none());
        assert!(config.jwt_hmac_kms_key_id.is_none());

        let s3 = S3Config {
            ssh_ca_kms_key_id: Some("mrk-ssh-key".to_string()),
            oidc_signing_kms_key_id: Some("mrk-oidc-key".to_string()),
            jwt_hmac_kms_key_id: Some("mrk-hmac-key".to_string()),
            ..Default::default()
        };

        config.merge_s3_config(&s3, false).unwrap();

        assert_eq!(config.ssh_ca_kms_key_id, Some("mrk-ssh-key".to_string()));
        assert_eq!(
            config.oidc_signing_kms_key_id,
            Some("mrk-oidc-key".to_string())
        );
        assert_eq!(config.jwt_hmac_kms_key_id, Some("mrk-hmac-key".to_string()));
    }

    #[test]
    fn test_s3_acme_config_debug_redacts_account_key() {
        let acme = S3AcmeConfig {
            account_key: "super-secret-pem-key".to_string(),
            email: "admin@example.com".to_string(),
        };
        let debug = format!("{acme:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must redact account_key"
        );
        assert!(
            !debug.contains("super-secret-pem-key"),
            "Debug output must not leak the actual key"
        );
        assert!(
            debug.contains("admin@example.com"),
            "Debug output should show email"
        );
    }

    #[test]
    fn test_s3_document_key_config_debug_redacts_encrypted_key() {
        let dk = S3DocumentKeyConfig {
            kms_key_id: "mrk-test-123".to_string(),
            encrypted_private_key: "c2VjcmV0LWNpcGhlcnRleHQ=".to_string(),
        };
        let debug = format!("{dk:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must redact encrypted_private_key"
        );
        assert!(
            !debug.contains("c2VjcmV0LWNpcGhlcnRleHQ="),
            "Debug output must not leak the actual ciphertext"
        );
        assert!(
            debug.contains("mrk-test-123"),
            "Debug output should show kms_key_id"
        );
    }

    #[test]
    fn test_merge_s3_config_runtime_blocks_kms_key_ids() {
        let mut config = crate::test_utils::test_config();

        let s3 = S3Config {
            ssh_ca_kms_key_id: Some("mrk-ssh-key".to_string()),
            oidc_signing_kms_key_id: Some("mrk-oidc-key".to_string()),
            jwt_hmac_kms_key_id: Some("mrk-hmac-key".to_string()),
            ..Default::default()
        };

        // Runtime update should NOT apply KMS key IDs
        config.merge_s3_config(&s3, true).unwrap();

        assert!(config.ssh_ca_kms_key_id.is_none());
        assert!(config.oidc_signing_kms_key_id.is_none());
        assert!(config.jwt_hmac_kms_key_id.is_none());
    }

    #[test]
    fn test_s3_config_deserialization_with_rsa_signing_key_fields() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "oidc_rsa_signing_key": "base64encodedpemkey",
            "oidc_rsa_signing_kms_key_id": "mrk-rsa-key-123"
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");

        assert_eq!(
            config.oidc_rsa_signing_key,
            Some("base64encodedpemkey".to_string())
        );
        assert_eq!(
            config.oidc_rsa_signing_kms_key_id,
            Some("mrk-rsa-key-123".to_string())
        );
    }

    #[test]
    fn test_merge_s3_config_rsa_signing_key_startup() {
        let mut config = crate::test_utils::test_config();
        assert!(config.oidc_rsa_signing_key.is_none());
        assert!(config.oidc_rsa_signing_kms_key_id.is_none());

        let s3 = S3Config {
            oidc_rsa_signing_key: Some("base64encodedpemkey".to_string()),
            oidc_rsa_signing_kms_key_id: Some("mrk-rsa-key-123".to_string()),
            ..Default::default()
        };

        // Startup merge should apply RSA key fields
        config.merge_s3_config(&s3, false).unwrap();

        assert!(config.oidc_rsa_signing_key.is_some());
        assert_eq!(
            config.oidc_rsa_signing_kms_key_id,
            Some("mrk-rsa-key-123".to_string())
        );
    }

    #[test]
    fn test_merge_s3_config_rsa_signing_key_runtime_blocked() {
        let mut config = crate::test_utils::test_config();

        let s3 = S3Config {
            oidc_rsa_signing_key: Some("base64encodedpemkey".to_string()),
            oidc_rsa_signing_kms_key_id: Some("mrk-rsa-key-123".to_string()),
            ..Default::default()
        };

        // Runtime update should NOT apply RSA signing key fields
        config.merge_s3_config(&s3, true).unwrap();

        assert!(config.oidc_rsa_signing_key.is_none());
        assert!(config.oidc_rsa_signing_kms_key_id.is_none());
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

    #[test]
    fn test_merge_s3_config_idps_array_oidc_and_saml() {
        let json = r#"{
            "idps": [
                {
                    "id": "google",
                    "type": "oidc",
                    "issuer": "https://accounts.google.com",
                    "client_id": "client-abc",
                    "client_secret": "secret-xyz"
                },
                {
                    "id": "corp-saml",
                    "type": "saml",
                    "metadata_url": "https://idp.example.com/saml/metadata",
                    "sp_entity_id": "https://vouch.example.com",
                    "email_attribute": "email",
                    "domain_attribute": "department"
                }
            ]
        }"#;
        let s3: S3Config = serde_json::from_str(json).expect("parse");
        let mut config = crate::test_utils::test_config();
        config.idps.clear();

        config.merge_s3_config(&s3, false).unwrap();

        assert_eq!(config.idps.len(), 2);
        assert_eq!(config.idps[0].id(), "google");
        assert_eq!(config.idps[0].kind_str(), "oidc");
        assert_eq!(config.idps[1].id(), "corp-saml");
        assert_eq!(config.idps[1].kind_str(), "saml");
    }

    /// Regression: S3-sourced IdP slugs must be checked against the documented
    /// `[a-z0-9-]{1,32}` format, just like env-var-sourced slugs. Before the
    /// fix, an uppercase id like `MyProvider` would pass validate() while the
    /// same id via VOUCH_IDPS was rejected. See issue #382.
    #[test]
    fn test_merge_s3_config_validates_idp_slug_format() {
        let json = r#"{
            "idps": [
                {
                    "id": "MyProvider",
                    "type": "oidc",
                    "issuer": "https://accounts.google.com",
                    "client_id": "client-abc",
                    "client_secret": "secret-xyz"
                }
            ]
        }"#;
        let s3: S3Config = serde_json::from_str(json).expect("parse");
        let mut config = crate::test_utils::test_config();
        config.idps.clear();

        config.merge_s3_config(&s3, false).unwrap();

        let err = config
            .validate()
            .expect_err("uppercase slug must be rejected")
            .to_string();
        assert!(
            err.contains("must match [a-z0-9-]"),
            "expected slug format error, got: {err}"
        );
    }

    #[test]
    fn test_merge_s3_config_rejects_underscore_in_idp_slug() {
        let json = r#"{
            "idps": [
                {
                    "id": "corp_saml",
                    "type": "saml",
                    "metadata_url": "https://idp.example.com/saml/metadata"
                }
            ]
        }"#;
        let s3: S3Config = serde_json::from_str(json).expect("parse");
        let mut config = crate::test_utils::test_config();
        config.idps.clear();

        config.merge_s3_config(&s3, false).unwrap();

        assert!(
            config.validate().is_err(),
            "underscore in slug must be rejected"
        );
    }

    #[test]
    fn test_s3_config_deserialization_with_idps_saml_only() {
        let json = r#"{
            "version": 1,
            "rp_id": "vouch.example.com",
            "idps": [
                {
                    "id": "corp-saml",
                    "type": "saml",
                    "metadata_url": "https://idp.example.com/saml/metadata",
                    "sp_entity_id": "https://vouch.example.com"
                }
            ]
        }"#;

        let config: S3Config = serde_json::from_str(json).expect("Failed to parse");
        let idps = config.idps.expect("idps present");
        assert_eq!(idps.len(), 1);
        match &idps[0] {
            S3IdpEntry::Saml {
                id,
                metadata_url,
                sp_entity_id,
                email_attribute,
                domain_attribute,
            } => {
                assert_eq!(id, "corp-saml");
                assert_eq!(metadata_url, "https://idp.example.com/saml/metadata");
                assert_eq!(sp_entity_id.as_deref(), Some("https://vouch.example.com"));
                assert!(email_attribute.is_none());
                assert!(domain_attribute.is_none());
            }
            other => panic!("expected SAML entry, got {other:?}"),
        }
    }
}
