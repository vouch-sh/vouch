// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server initialization pipeline.
//!
//! Handles configuration loading (env + S3), database connection and migration,
//! building `AppState`, and starting background tasks.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use secrecy::ExposeSecret;
use tokio::task::JoinHandle;

use crate::{
    AppState, config,
    crypto::{
        keys::{OidcRsaSigningKey, OidcSigningKey},
        ssh_ca, tpm_decrypt,
    },
    db::{Pool, dsql::DsqlEndpoint, migrations::run_dsql_migrations, pool::redact_database_url},
    infra::{
        bootstrap, cleanup, kms_arn::KmsArnResolver, s3_config, s3_config::DocumentKeyMaterial,
    },
    services::integrations::github::GitHubApp,
};

/// All components needed to run the server after initialization.
pub struct ServerComponents {
    /// Validated server configuration.
    pub(crate) config: config::ServerConfig,
    /// Database connection pool.
    pub(crate) db: Pool,
    /// Shared application state.
    pub(crate) state: Arc<AppState>,
    /// S3 client for config polling (None if S3 config is not used).
    pub(crate) s3_client: Option<aws_sdk_s3::Client>,
    /// S3 config source settings (None if S3 config is not used).
    pub(crate) s3_source: Option<s3_config::S3ConfigSource>,
    /// Initial S3 config ETag for change detection (None if S3 config is not used).
    pub(crate) initial_etag: Option<String>,
    /// Background cleanup task handle (None if cleanup is disabled).
    pub(crate) cleanup_handle: Option<JoinHandle<()>>,
}

impl ServerComponents {
    /// Build the HTTP router with all routes, middleware, and state.
    /// # Errors
    ///
    /// Returns an error if rate limiter configuration fails.
    pub fn build_app(&self) -> anyhow::Result<axum::Router> {
        super::router::build_app(self.state.clone(), &self.config)
    }
}

/// Initialize all server components from CLI arguments.
///
/// This function:
/// 1. Loads configuration from environment, S3, and database
/// 2. Connects to the database and runs migrations
/// 3. Builds `AppState` with WebAuthn, SSH CA, OIDC, GitHub, DPoP
/// 4. Starts the background cleanup task
///
/// `instance` carries IMDS-discovered facts and the bootstrap parameter blob
/// (see `infra::bootstrap`); `None` when not running on EC2 or when bootstrap
/// was skipped because config is already fully specified via env/CLI.
///
/// # Errors
///
/// Returns an error if configuration is invalid, database connection fails,
/// or required components cannot be initialized.
pub async fn initialize(
    args: config::Args,
    instance: Option<&bootstrap::Bootstrap>,
) -> Result<ServerComponents> {
    let mut config = config::ServerConfig::from_args(args, instance)?;

    // Probe NitroTPM BEFORE S3 config loading so we know whether to
    // use attested kms:Decrypt for document key decryption.
    let use_attestation = probe_nitro_tpm().await;

    // Load S3 config if configured (BEFORE database connection).
    // If the config has a document_key, also recovers the HPKE key pair.
    //
    // The KMS client built here is scoped to document-key decryption only:
    // it uses the S3 SDK config (region = `s3_config_region`) because the
    // document key's KMS key is typically co-located with the S3 bucket.
    // `build_app_state` builds a separate signing KMS client from
    // `aws_region` on demand — signing-key ARNs embed `aws_region`, and the
    // AWS SDK picks the KMS endpoint from the client's configured region, so
    // reusing one client for both purposes breaks cross-region deployments
    // where `VOUCH_S3_CONFIG_REGION` differs from `aws_region`.
    let (s3_client, s3_source, initial_etag, doc_keys, kms_arn_resolver) =
        load_s3_config(&mut config, use_attestation).await?;

    // Connect to database and run migrations
    let db = connect_and_migrate(&config).await?;

    // Validate config after all sources merged (env, S3)
    config.validate()?;
    tracing::info!(
        "Configuration validated: rp_id={}, base_url={}, tls={}, NitroTPM={}",
        config.rp_id,
        config.base_url,
        config.tls_configured(),
        use_attestation,
    );

    crate::geo::warmup();
    tracing::info!("GeoIP database initialized");

    log_startup_summary(&config);

    // Re-bind the resolver to the FINAL (post-merge) kms_account_id: S3 merge
    // may have set it, and `merge_s3_config` runs strictly after `load_s3_config`
    // returned the pre-merge resolver above.
    let kms_arn_resolver = kms_arn_resolver.with_account_id(config.kms_account_id.as_deref());

    // Build AppState and start background tasks. `build_app_state` builds
    // its own KMS client for signing operations from `aws_region` (not
    // `s3_config_region`) so signing-key ARN and KMS endpoint share a region.
    let state = build_app_state(&config, db.clone(), doc_keys, None, kms_arn_resolver).await?;

    // Start background cleanup task if enabled
    let cleanup_handle = if config.cleanup_interval_minutes > 0 {
        tracing::info!(
            "Starting cleanup task: interval={}m, auth_event_retention={}d, \
             oauth_event_retention={}d",
            config.cleanup_interval_minutes,
            config.auth_events_retention_days,
            config.oauth_events_retention_days,
        );
        Some(cleanup::start_cleanup_task(
            state.store.clone(),
            state.audit.clone(),
            config.cleanup_interval_minutes,
            config.auth_events_retention_days,
            config.oauth_events_retention_days,
        ))
    } else {
        tracing::info!("Background cleanup task disabled");
        None
    };

    Ok(ServerComponents {
        config,
        db,
        state,
        s3_client,
        s3_source,
        initial_etag,
        cleanup_handle,
    })
}

/// Check if NitroTPM attestation is available and functional.
///
/// Returns true only if /dev/tpm0 exists, `nitro-tpm-attest` is in PATH,
/// and the probe exercise succeeds.
async fn probe_nitro_tpm() -> bool {
    if !tpm_decrypt::is_nitro_tpm_available() {
        tracing::info!("NitroTPM: not available (/dev/tpm0 missing)");
        return false;
    }
    if !tpm_decrypt::is_attest_binary_available() {
        tracing::warn!("NitroTPM: device present but nitro-tpm-attest binary missing");
        return false;
    }
    match tokio::task::spawn_blocking(tpm_decrypt::probe_attestation).await {
        Ok(Ok(n)) => {
            tracing::info!("NitroTPM: attestation probe succeeded ({n} bytes)");
            true
        }
        Ok(Err(e)) => {
            tracing::warn!("NitroTPM: attestation probe failed: {e:#}");
            false
        }
        Err(e) => {
            tracing::warn!("NitroTPM: attestation probe task panicked: {e}");
            false
        }
    }
}

/// Load configuration from S3 if configured.
///
/// Fetches the initial config from S3 and merges into the server config.
/// If the config has a `document_key`, decrypts it via KMS (with NitroTPM
/// attestation when available) and returns the key material.
///
/// Constructs two `KmsArnResolver`s for this boot. The one used to resolve
/// the document key takes its region from `s3_config_region` (falling back
/// to `aws_region`) so it matches the doc-key KMS client below. The one
/// returned to the caller uses `config.aws_partition`/`config.aws_region`
/// for signing keys; the caller re-binds it to the final merged
/// `kms_account_id` before reusing it. In both, the account ID is the S3
/// document's own `kms_account_id` — the only value that isn't already
/// known before the document is fetched.
///
/// The KMS client built here is used **only for document-key decryption**.
/// It reuses the S3 SDK config (region = `s3_config_region`) because the
/// document key's KMS key lives in the same region as the S3 bucket
/// (the account may differ — that is what `kms_account_id` selects). It is
/// deliberately NOT returned for signing operations: signing-key ARNs embed
/// `aws_region` (see `KmsArnResolver`), and the AWS SDK picks the KMS
/// endpoint from the client's configured region. Reusing this client for
/// signing would send signing calls to the S3 bucket's region instead of the
/// server's local region, breaking cross-region deployments where
/// `VOUCH_S3_CONFIG_REGION` differs from `aws_region`. `build_app_state`
/// builds its own signing KMS client from `aws_region` on demand.
async fn load_s3_config(
    config: &mut config::ServerConfig,
    use_attestation: bool,
) -> Result<(
    Option<aws_sdk_s3::Client>,
    Option<s3_config::S3ConfigSource>,
    Option<String>,
    Option<DocumentKeyMaterial>,
    KmsArnResolver,
)> {
    let Some(bucket) = &config.s3_config_bucket else {
        tracing::info!("Configuration source: environment variables");
        let resolver = KmsArnResolver::new(
            config.kms_account_id.as_deref(),
            config.aws_partition.as_deref(),
            config.aws_region.as_deref(),
        );
        return Ok((None, None, None, None, resolver));
    };

    tracing::info!(
        "Configuration source: S3 (s3://{}/{})",
        bucket,
        config.s3_config_key
    );

    // Only override the region when VOUCH_S3_CONFIG_REGION is set; passing
    // Option::<Region>::None to `.region(...)` disables the default region
    // provider chain (env / shared config / IMDS) and breaks S3 requests.
    let sdk_config = crate::config::aws_config_loader(
        config.s3_config_region.as_deref(),
        config.aws_use_fips_endpoint,
    )?
    .load()
    .await;

    let s3_client = aws_sdk_s3::Client::new(&sdk_config);

    // KMS client for document key decryption only. Uses the S3 SDK config
    // (region = `s3_config_region`) since the document key's KMS key is
    // typically co-located with the S3 bucket. Signing operations use a
    // separate client built from `aws_region` in `build_app_state`.
    let doc_key_kms_client = aws_sdk_kms::Client::from_conf(
        aws_sdk_kms::config::Builder::from(&sdk_config)
            .timeout_config(kms_timeout_config())
            .build(),
    );

    let source = s3_config::S3ConfigSource {
        bucket: bucket.clone(),
        key: config.s3_config_key.clone(),
        region: config.s3_config_region.clone(),
        poll_interval_seconds: config.s3_config_poll_interval,
    };

    // kms_account_id is always None pre-merge (it has no CLI/env source of
    // its own — see ServerConfig::from_args); fetch_s3_config rebinds it to
    // the S3 document's own value before resolving the document key.
    //
    // Two resolvers, matching the two KMS clients: the document key's KMS
    // key lives in the same region as the S3 bucket, so its ARN region must
    // be `s3_config_region` — the same region `doc_key_kms_client` sends
    // requests to. The resolver returned to the caller keeps `aws_region`
    // for signing keys, pairing with the signing client `build_app_state`
    // creates.
    let doc_key_resolver = KmsArnResolver::new(
        config.kms_account_id.as_deref(),
        config.aws_partition.as_deref(),
        config
            .s3_config_region
            .as_deref()
            .or(config.aws_region.as_deref()),
    );
    let kms_resolver = KmsArnResolver::new(
        config.kms_account_id.as_deref(),
        config.aws_partition.as_deref(),
        config.aws_region.as_deref(),
    );

    // Fetch initial config - fail fast if unreachable.
    // If the config has a document_key, the private key is decrypted
    // via KMS (with NitroTPM attestation when available) using
    // `doc_key_kms_client` (region = `s3_config_region`).
    let (s3_cfg, etag, doc_keys) = s3_config::fetch_s3_config(
        &s3_client,
        &source,
        Some(&doc_key_kms_client),
        use_attestation,
        &doc_key_resolver,
    )
    .await
    .context("Failed to fetch S3 configuration")?;

    // Merge S3 config (S3 wins over env vars) — fail fast if oidc block present
    config.merge_s3_config(&s3_cfg, false)?;
    tracing::info!("S3 configuration merged (etag: {etag})");

    Ok((
        Some(s3_client),
        Some(source),
        Some(etag),
        doc_keys,
        kms_resolver,
    ))
}

/// Connect to the database and run migrations.
async fn connect_and_migrate(config: &config::ServerConfig) -> Result<Pool> {
    let db = Pool::connect(&config.database_url, &config.pool_config).await?;
    tracing::info!(
        "Connected to {:?} database: {}",
        db.db_type(),
        redact_database_url(&config.database_url),
    );

    // Run migrations based on database type
    // Note: DSQL requires a custom migration runner due to DDL/DML transaction restrictions
    let (migrations_applied, migrations_total) = match &db {
        Pool::Sqlite(pool) => {
            let migrator = sqlx::migrate!("./migrations/sqlite");
            let total = migrator.iter().count();
            let before: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
                .fetch_one(pool)
                .await
                .unwrap_or(0);
            migrator.run(pool).await?;
            let after: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
                .fetch_one(pool)
                .await?;
            (
                usize::try_from(after.saturating_sub(before))
                    .context("migration count delta exceeds usize")?,
                total,
            )
        }
        Pool::Postgres(pool) => {
            // Check if this is a DSQL endpoint
            let is_dsql = DsqlEndpoint::from_url(&config.database_url)
                .ok()
                .and_then(|ep| ep)
                .is_some();

            if is_dsql {
                tracing::info!("DSQL detected, using DSQL-compatible migration runner");
                run_dsql_migrations(pool).await?
            } else {
                let migrator = sqlx::migrate!("./migrations/postgres");
                let total = migrator.iter().count();
                let before: i64 =
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
                        .fetch_one(pool)
                        .await
                        .unwrap_or(0);
                migrator.run(pool).await?;
                let after: i64 =
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
                        .fetch_one(pool)
                        .await?;
                (
                    usize::try_from(after.saturating_sub(before))
                        .context("migration count delta exceeds usize")?,
                    total,
                )
            }
        }
    };
    if migrations_applied > 0 {
        tracing::info!(
            "Database migrations complete: {migrations_applied} applied ({migrations_total} total)"
        );
    } else {
        tracing::info!("Database migrations up to date ({migrations_total} total)");
    }

    Ok(db)
}

/// Build shared application state with all service components.
#[expect(
    clippy::too_many_lines,
    reason = "sequential construction of every AppState component"
)]
async fn build_app_state(
    config: &config::ServerConfig,
    db: Pool,
    doc_keys: Option<DocumentKeyMaterial>,
    kms_client: Option<aws_sdk_kms::Client>,
    kms_arn_resolver: KmsArnResolver,
) -> Result<Arc<AppState>> {
    // Build WebAuthn instance
    // Use base_url as origin (handles localhost with http and port correctly)
    let rp_origin = url::Url::parse(&config.base_url)?;
    let webauthn_builder =
        webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)?.rp_name(&config.rp_name);
    let webauthn = webauthn_builder.build()?;

    // Create a KMS client if any KMS key IDs are configured but no client
    // was provided (e.g., non-S3 deployments that still use KMS signing).
    //
    // The fallback client uses `aws_region` (the server's local region), not
    // `s3_config_region`, because signing-key ARNs embed `aws_region` and the
    // AWS SDK selects the KMS endpoint from the client's configured region.
    // Mixing the two breaks cross-region deployments where
    // `VOUCH_S3_CONFIG_REGION` differs from `aws_region`.
    let kms_needs = config.ssh_ca_kms_key_id.is_some()
        || config.oidc_signing_kms_key_id.is_some()
        || config.oidc_rsa_signing_kms_key_id.is_some()
        || config.jwt_hmac_kms_key_id.is_some();
    let kms_client = if kms_needs && kms_client.is_none() {
        tracing::info!("Creating KMS client for signing key access");
        let sdk_config = crate::config::aws_config_loader(
            signing_kms_client_region(config).as_deref(),
            config.aws_use_fips_endpoint,
        )?
        .load()
        .await;
        Some(aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::config::Builder::from(&sdk_config)
                .timeout_config(kms_timeout_config())
                .build(),
        ))
    } else {
        kms_client
    };

    // Initialize SSH CA if configured
    // Priority: KMS key ID > PEM content (VOUCH_SSH_CA_KEY) > file path (VOUCH_SSH_CA_KEY_PATH)
    let ssh_ca = if let Some(key_id) = &config.ssh_ca_kms_key_id {
        let client = kms_client
            .as_ref()
            .context("KMS client required for SSH CA KMS signing")?
            .clone();
        let key_arn = kms_arn_resolver.resolve(key_id);
        let ca = ssh_ca::SshCa::from_kms(client, key_arn.clone(), &config.rp_id)
            .await
            .context("Failed to initialize KMS SSH CA")?;
        let pub_key = ca
            .public_key()
            .context("KMS SSH CA loaded but public key is not extractable")?;
        tracing::info!("SSH CA initialized (KMS): {} ({})", key_arn, pub_key);
        Some(ca)
    } else {
        match ssh_ca::SshCa::load(
            config.ssh_ca_key.as_ref().map(|s| s.expose_secret()),
            config.ssh_ca_key_path.as_deref(),
            &config.rp_id,
        ) {
            Ok(Some(ca)) => {
                let pub_key = ca
                    .public_key()
                    .context("SSH CA loaded but public key is not extractable")?;
                tracing::info!("SSH CA initialized: {}", pub_key);
                Some(ca)
            }
            Ok(None) => {
                tracing::info!("SSH CA disabled");
                None
            }
            Err(e) => {
                tracing::warn!("Failed to initialize SSH CA: {e}");
                None
            }
        }
    };

    // Initialize OIDC signing key (ES256 for AWS and OIDC ID tokens)
    // Priority: KMS key ID > PEM content (VOUCH_OIDC_SIGNING_KEY) > generate ephemeral
    let oidc_key = if let Some(key_id) = &config.oidc_signing_kms_key_id {
        let client = kms_client
            .as_ref()
            .context("KMS client required for OIDC KMS signing")?
            .clone();
        let key_arn = kms_arn_resolver.resolve(key_id);
        let key = OidcSigningKey::from_kms(client, key_arn.clone())
            .await
            .context("Failed to initialize KMS OIDC signing key")?;
        tracing::info!(
            "OIDC ES256 signing key initialized (KMS): {} (kid={})",
            key_arn,
            key.key_id(),
        );
        key
    } else {
        let key = OidcSigningKey::load_or_generate(
            config.oidc_signing_key.as_ref().map(|s| s.expose_secret()),
        )?;

        if config.oidc_signing_key.is_none() {
            tracing::warn!(
                "Using ephemeral OIDC signing key -- all issued tokens will be \
                 invalidated on server restart. Set VOUCH_OIDC_SIGNING_KEY to persist."
            );
        }
        key
    };

    // Initialize OIDC RSA signing key (RS256 for ID tokens).
    // Priority: KMS key ID > PEM content > generate ephemeral (with warning).
    // The RSA key is always initialized so RS256 is available for OIDC conformance.
    let oidc_rsa_key = if let Some(key_id) = &config.oidc_rsa_signing_kms_key_id {
        let client = kms_client
            .as_ref()
            .context("KMS client required for OIDC RSA KMS signing")?
            .clone();
        let key_arn = kms_arn_resolver.resolve(key_id);
        let key = OidcRsaSigningKey::from_kms(client, key_arn.clone())
            .await
            .context("Failed to initialize KMS OIDC RSA signing key")?;
        tracing::info!(
            "OIDC RS256 signing key initialized (KMS): {} (kid={})",
            key_arn,
            key.key_id(),
        );
        Some(key)
    } else {
        // Clone the PEM content (or None) before crossing the spawn_blocking boundary.
        // RSA-3072 generation takes ~200ms; offload to avoid blocking the tokio runtime.
        let pem_owned = config
            .oidc_rsa_signing_key
            .as_ref()
            .map(|s| s.expose_secret().to_string());
        let key = tokio::task::spawn_blocking(move || {
            OidcRsaSigningKey::load_or_generate(pem_owned.as_deref())
        })
        .await
        .map_err(|e| anyhow::anyhow!("RSA key generation task panicked: {e}"))??;

        if config.oidc_rsa_signing_key.is_none() {
            tracing::warn!(
                "Using ephemeral OIDC RSA signing key -- AWS credential tokens \
                 (and RS256 ID tokens) will fail verification after a restart \
                 and across multiple instances. Set VOUCH_OIDC_RSA_SIGNING_KEY \
                 or VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID to persist."
            );
        }
        tracing::info!("OIDC RSA signing key initialized: {}", key.key_id());
        Some(key)
    };

    // Initialize state token signer (Local HS256 or KMS HMAC-SHA256)
    let state_signer = if let Some(key_id) = &config.jwt_hmac_kms_key_id {
        let client = kms_client
            .as_ref()
            .context("KMS client required for HMAC state token signing")?
            .clone();
        let key_arn = kms_arn_resolver.resolve(key_id);
        tracing::info!("State token signer initialized (KMS HMAC): {key_arn}");
        crate::crypto::jwt::StateTokenSigner::from_kms(client, key_arn)
    } else {
        crate::crypto::jwt::StateTokenSigner::local(config.jwt_secret_bytes().to_vec())
    };

    // Build shared HTTP client for outbound API calls (GitHub, OIDC, etc.)
    let user_agent = format!("vouch-server/{}", env!("CARGO_PKG_VERSION"));
    let extra_ca_pem = config
        .extra_ca_certs
        .as_deref()
        .map(|path| {
            tracing::info!("Loading extra CA certificates from {path}");
            std::fs::read(path)
        })
        .transpose()
        .context("Failed to read VOUCH_EXTRA_CA_CERTS file")?;
    let http_client = vouch_common::http::server_client(&user_agent, extra_ca_pem.as_deref())
        .context("Failed to create shared HTTP client")?;

    // Build unified IdP list (OIDC + SAML) from the configured `idps` Vec.
    let enrollment_domains = match &config.allowed_domains {
        Some(domains) => domains.join(", "),
        None => "(open enrollment)".to_string(),
    };
    let mut idps: Vec<crate::services::idp::ConfiguredIdp> = Vec::with_capacity(config.idps.len());
    for idp_cfg in &config.idps {
        let configured = build_configured_idp(idp_cfg, &http_client, config, &enrollment_domains)
            .await
            .with_context(|| format!("Failed to configure IdP '{}'", idp_cfg.id()))?;
        idps.push(configured);
    }

    // Initialize GitHub App if configured
    let github_app = match GitHubApp::load(config, http_client.clone()) {
        Ok(Some(app)) => {
            tracing::info!(
                "GitHub integration: webhooks={}, oauth={}",
                config.github_webhook_secret.is_some(),
                config.github_oauth_configured(),
            );
            Some(Arc::new(app))
        }
        Ok(None) => {
            if config.github_app_id.is_some()
                || config.github_app_key.is_some()
                || config.github_webhook_secret.is_some()
                || config.github_app_client_id.is_some()
            {
                tracing::warn!(
                    "Partial GitHub configuration detected -- GitHub App requires \
                     at least VOUCH_GITHUB_APP_ID and VOUCH_GITHUB_APP_KEY"
                );
            }
            None
        }
        Err(e) => {
            tracing::warn!("Failed to initialize GitHub App: {e}");
            None
        }
    };

    // Wrap config in ArcSwap for dynamic updates
    let config_swap = Arc::new(ArcSwap::from_pointee(config.clone()));

    // Create document store and audit store with appropriate crypto.
    // When document keys are available (from config.document_key), use
    // HpkeDocumentCrypto for database-level encryption. Otherwise fall
    // back to PlaintextDocumentCrypto for development.
    let crypto: std::sync::Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        if let Some(keys) = doc_keys {
            tracing::info!(
                "Document encryption initialized (KMS HPKE): {} ({})",
                keys.suite_id.label(),
                keys.suite_id
            );
            std::sync::Arc::new(
                crate::crypto::document_crypto::HpkeDocumentCrypto::new(
                    keys.suite_id,
                    keys.public_key,
                    keys.private_key,
                )
                .context("Failed to initialize HpkeDocumentCrypto from document key")?,
            )
        } else {
            tracing::info!("Document encryption: plaintext (no document key configured)");
            std::sync::Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto)
        };
    let store = crate::db::store::DocumentStore::new(db.clone(), crypto.clone());
    let audit = crate::db::audit::AuditStore::new(db.clone(), crypto);

    let state = Arc::new(AppState {
        db,
        store,
        audit,
        config: config_swap,
        webauthn,
        ssh_ca,
        oidc_key,
        oidc_rsa_key,
        state_signer,
        github_app,
        http_client,
        session_cache: crate::db::SessionCache::new(
            config.session_cache_max_capacity,
            config.session_cache_ttl_secs,
        ),
        org_keys_cache: Default::default(),
        idps,
    });

    // Per-org issuer signing keys exist only when the document store encrypts
    // at rest. Refuse to start an unencrypted server that has claimed issuer
    // subdomains: it would advertise per-org issuer hosts as a tenant boundary
    // while signing everything with the shared platform key.
    if !state.store.is_encrypted() && crate::db::any_subdomain_claimed(&state.store).await? {
        anyhow::bail!(
            "issuer subdomains are claimed but document encryption is not configured; \
             configure the KMS document key or release all issuer subdomains before starting"
        );
    }

    Ok(state)
}

/// Build a `ConfiguredIdp` from an `IdpConfig` entry by performing the
/// type-specific discovery step (OIDC discovery, SAML metadata fetch).
async fn build_configured_idp(
    idp_cfg: &crate::config::IdpConfig,
    http_client: &reqwest::Client,
    config: &crate::config::ServerConfig,
    enrollment_domains: &str,
) -> Result<crate::services::idp::ConfiguredIdp> {
    match idp_cfg {
        crate::config::IdpConfig::Oidc(oidc_cfg) => {
            let discovered =
                crate::services::idp::oidc::fetch_discovery(http_client, &oidc_cfg.issuer_url)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to fetch OIDC discovery for IdP '{}' (issuer: {}). \
                             Check that the issuer URL is reachable.",
                            oidc_cfg.id, oidc_cfg.issuer_url
                        )
                    })?;
            let brand = crate::services::idp::IdpBrand::from_issuer(&discovered.issuer);
            tracing::info!(
                "IdP '{}' (oidc): brand={}, issuer={}, auth={}, token={}, jwks={}, \
                 enrollment_domains={}",
                oidc_cfg.id,
                brand.display_name(),
                discovered.issuer,
                discovered.authorization_endpoint,
                discovered.token_endpoint,
                discovered.jwks_uri,
                enrollment_domains,
            );
            Ok(crate::services::idp::ConfiguredIdp::Oidc(
                crate::services::idp::ConfiguredOidcProvider {
                    id: oidc_cfg.id.clone(),
                    client_id: oidc_cfg.client_id.clone(),
                    client_secret: oidc_cfg.client_secret.clone(),
                    provider: discovered,
                },
            ))
        }
        crate::config::IdpConfig::Saml(saml_cfg) => {
            let metadata_xml = http_client
                .get(&saml_cfg.metadata_url)
                .send()
                .await
                .with_context(|| {
                    format!("Failed to fetch SAML metadata for IdP '{}'", saml_cfg.id)
                })?
                .error_for_status()
                .with_context(|| {
                    format!(
                        "SAML metadata fetch returned error for IdP '{}'",
                        saml_cfg.id
                    )
                })?
                .text()
                .await
                .with_context(|| {
                    format!(
                        "Failed to read SAML metadata body for IdP '{}'",
                        saml_cfg.id
                    )
                })?;
            let idp_metadata =
                crate::services::idp::saml::metadata::parse_idp_metadata(&metadata_xml)
                    .with_context(|| {
                        format!("Failed to parse SAML metadata for IdP '{}'", saml_cfg.id)
                    })?;
            let brand = crate::services::idp::IdpBrand::from_entity_id(&idp_metadata.entity_id);
            let sp_entity_id = saml_cfg
                .sp_entity_id
                .clone()
                .unwrap_or_else(|| config.base_url.clone());
            let acs_url = format!("{}/saml/acs", config.base_url);
            let sso_url = idp_metadata
                .sso_post_url
                .as_deref()
                .or(idp_metadata.sso_redirect_url.as_deref())
                .unwrap_or("(none)");
            tracing::info!(
                "IdP '{}' (saml): brand={}, entity_id={}, sso_url={}, binding={}, certs={}",
                saml_cfg.id,
                brand.display_name(),
                idp_metadata.entity_id,
                sso_url,
                if idp_metadata.sso_post_url.is_some() {
                    "HTTP-POST"
                } else {
                    "HTTP-Redirect"
                },
                idp_metadata.signing_certificates.len(),
            );
            Ok(crate::services::idp::ConfiguredIdp::Saml(
                crate::services::idp::saml::SamlProvider {
                    id: saml_cfg.id.clone(),
                    idp_metadata,
                    sp_entity_id,
                    acs_url,
                    email_attribute: saml_cfg.email_attribute.clone(),
                    domain_attribute: saml_cfg.domain_attribute.clone(),
                },
            ))
        }
    }
}

/// Log the runtime/feature configuration summary at startup — one log per
/// feature for searchable CloudWatch events — plus security warnings for
/// suspicious configurations.
fn log_startup_summary(config: &config::ServerConfig) {
    // AWS SDK and runtime configuration. region/az/partition/fips print the
    // values ServerConfig resolved (env, or on EC2 the bootstrap parameter /
    // IMDS) rather than raw process env, since the bootstrap blob is never
    // written back to the environment. dualstack/sts_regional/defaults_mode
    // are unit-pinned Environment= lines in the AMI, always real process env.
    let env_or = |key: &str| -> String { std::env::var(key).unwrap_or_else(|_| "(empty)".into()) };
    tracing::info!(
        "AWS SDK: region={}, az={}, partition={}, fips={}, dualstack={}, sts_regional={}, \
         defaults_mode={}",
        config.aws_region.as_deref().unwrap_or("(empty)"),
        config.aws_az.as_deref().unwrap_or("(empty)"),
        config.aws_partition.as_deref().unwrap_or("(empty)"),
        config
            .aws_use_fips_endpoint
            .map_or_else(|| "(empty)".to_string(), |v| v.to_string()),
        env_or("AWS_USE_DUALSTACK_ENDPOINT"),
        env_or("AWS_STS_REGIONAL_ENDPOINTS"),
        env_or("AWS_DEFAULTS_MODE"),
    );
    tracing::info!("Logging: RUST_LOG={}", env_or("RUST_LOG"));

    if !config.trusted_proxies.is_empty() {
        let cidrs: Vec<String> = config
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        tracing::warn!(
            "Trusted proxies configured: {} -- X-Forwarded-For will be parsed for client IP",
            cidrs.join(", "),
        );
    }

    let pool_cfg = &config.pool_config;
    tracing::info!(
        "Database pool: max_connections={}, min_connections={}, idle_timeout={}s, acquire_timeout={}s",
        pool_cfg.max_connections,
        pool_cfg.min_connections,
        pool_cfg.idle_timeout_secs,
        pool_cfg.acquire_timeout_secs,
    );
    tracing::info!(
        "Sessions: duration={}h, dpop_max_age={}s, cache_max_capacity={}, cache_ttl={}s",
        config.session_hours,
        config.dpop_max_age_seconds,
        config.session_cache_max_capacity,
        config.session_cache_ttl_secs,
    );
    tracing::info!(
        "Device flow: code_expires={}s, poll_interval={}s",
        config.device_code_expires_seconds,
        config.device_poll_interval_seconds,
    );

    log_authenticator_policy(config);

    match &config.cors_origins {
        Some(origins) => tracing::info!("CORS: origins={}", origins.join(", ")),
        None => tracing::info!("CORS: same-origin only"),
    }

    // Warn if rp_id is localhost but TLS is configured (likely a
    // misconfiguration: a loopback rp_id in what looks like production).
    // WebAuthn origin relaxation is now disabled whenever TLS is configured,
    // so origin binding is NOT weakened here — but the loopback rp_id itself
    // is almost certainly wrong for a TLS deployment.
    if vouch_common::is_loopback_host(&config.rp_id) && config.tls_configured() {
        tracing::warn!(
            target: "security",
            "rp_id is '{}' but TLS is configured -- this looks like a production \
             deployment with a loopback relying-party ID, which is almost \
             certainly a misconfiguration",
            config.rp_id,
        );
    }

    // Loudly flag certification test mode at startup. This is a login-bypass
    // switch (see router.rs) intended only for OpenID conformance testing.
    if config.certification_test_token.is_some() {
        tracing::warn!(
            target: "security",
            "CERTIFICATION TEST MODE is ENABLED (VOUCH_CERTIFICATION_TEST_TOKEN is \
             set): login-bypass endpoint active, global rate limiting disabled, \
             and the upstream-IdP requirement relaxed. MUST NOT be set in production."
        );
    }
}

/// Log authenticator policy settings at startup.
fn log_authenticator_policy(config: &config::ServerConfig) {
    let aaguid_policy = match &config.allowed_aaguids {
        vouch_common::AaguidPolicy::Any => "any".to_string(),
        vouch_common::AaguidPolicy::FipsOnly => "fips-only".to_string(),
        vouch_common::AaguidPolicy::YubiKey5Only => "yubikey-5-only".to_string(),
        vouch_common::AaguidPolicy::AllowList(set) => {
            format!("allowlist ({} AAGUIDs)", set.len())
        }
    };
    tracing::info!(
        "Authenticator policy: aaguid={}, require_attestation_cert={}",
        aaguid_policy,
        config.require_attestation_cert,
    );
}

/// Timeout configuration for AWS KMS API calls.
///
/// The AWS SDK has no default timeouts, so all KMS operations (Sign,
/// GetPublicKey, GenerateMac, VerifyMac, Decrypt) can hang indefinitely.
/// These values are aggressive because KMS calls are same-region within AWS.
fn kms_timeout_config() -> aws_sdk_kms::config::timeout::TimeoutConfig {
    aws_sdk_kms::config::timeout::TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(1))
        .operation_attempt_timeout(Duration::from_secs(2))
        .operation_timeout(Duration::from_secs(5))
        .build()
}

/// Select the AWS region for the signing KMS client.
///
/// Signing keys (SSH CA, OIDC ES256/RS256, JWT HMAC) are addressed by ARNs
/// that embed `aws_region` (see `KmsArnResolver`), and the AWS SDK picks the
/// KMS endpoint from the client's configured region. The two must match, so
/// the signing KMS client is built from `aws_region` — never from
/// `s3_config_region`, which can differ when `VOUCH_S3_CONFIG_REGION` is
/// pinned to the S3 bucket's region in a cross-region deployment. Returning
/// `aws_region.clone()` (rather than `None`) when set keeps the loader on
/// the explicit region; returning `None` when `aws_region` is unset falls
/// back to the AWS SDK's default region provider chain (env / shared config
/// / IMDS), which is the correct behavior for non-pinned deployments.
fn signing_kms_client_region(config: &config::ServerConfig) -> Option<String> {
    config.aws_region.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the cross-region KMS signing bug: the signing KMS
    /// client's region source must be `aws_region`, NOT `s3_config_region`.
    ///
    /// When `VOUCH_S3_CONFIG_REGION` is pinned to a different region than
    /// the server's local region, signing-key ARNs (built from `aws_region`)
    /// and the KMS client's endpoint region (previously built from
    /// `s3_config_region`) would diverge, sending `Sign` / `GetPublicKey` /
    /// `GenerateMac` calls to the wrong regional KMS endpoint and failing
    /// with `NotFoundException` / `AccessDeniedException` for single-region
    /// keys. The fix is to build the signing KMS client from `aws_region`.
    #[test]
    fn signing_kms_client_region_uses_aws_region_not_s3_config_region() {
        let mut config = crate::test_utils::test_config();
        config.aws_region = Some("us-east-1".to_string());
        config.s3_config_region = Some("us-west-2".to_string());

        let region = signing_kms_client_region(&config);
        assert_eq!(
            region.as_deref(),
            Some("us-east-1"),
            "signing KMS client must use aws_region, not s3_config_region"
        );
        assert_ne!(
            region.as_deref(),
            config.s3_config_region.as_deref(),
            "signing KMS client must not pick up VOUCH_S3_CONFIG_REGION"
        );
    }

    /// When `aws_region` is unset, the signing KMS client must let the AWS
    /// SDK's default region provider chain resolve the region (env / shared
    /// config / IMDS) by passing `None` to `aws_config_loader` — rather than
    /// accidentally falling back to `s3_config_region`.
    #[test]
    fn signing_kms_client_region_returns_none_when_aws_region_unset() {
        let mut config = crate::test_utils::test_config();
        config.aws_region = None;
        // Even if s3_config_region is set, it must NOT bleed into signing.
        config.s3_config_region = Some("us-west-2".to_string());

        let region = signing_kms_client_region(&config);
        assert!(
            region.is_none(),
            "signing KMS client must use the SDK default chain when aws_region is unset, \
             not s3_config_region"
        );
    }

    /// Document-key KMS decryption uses the S3 SDK config's region
    /// (`s3_config_region`), which the loader reads from
    /// `config.s3_config_region` in `load_s3_config`. This test pins that
    /// invariant alongside the signing invariant above: the two paths must
    /// draw their regions from different sources when the regions differ.
    #[test]
    fn document_key_and_signing_clients_use_distinct_region_sources() {
        let mut config = crate::test_utils::test_config();
        config.aws_region = Some("us-east-1".to_string());
        config.s3_config_region = Some("us-west-2".to_string());

        let signing_region = signing_kms_client_region(&config);
        let doc_key_region = config.s3_config_region.clone();

        assert_eq!(signing_region.as_deref(), Some("us-east-1"));
        assert_eq!(doc_key_region.as_deref(), Some("us-west-2"));
        assert_ne!(
            signing_region, doc_key_region,
            "cross-region deployments must route document-key and signing KMS calls \
             to different regional endpoints"
        );
    }
}
