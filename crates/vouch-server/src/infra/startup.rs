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
    crypto::{ssh_ca, tpm_decrypt},
    db::{Pool, dsql::DsqlEndpoint, migrations::run_dsql_migrations, pool::redact_database_url},
    infra::{cleanup, kms_arn::KmsArnResolver, s3_config, s3_config::DocumentKeyMaterial},
    services::{
        integrations::github::GitHubApp,
        oidc::{OidcRsaSigningKey, OidcSigningKey},
    },
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
/// # Errors
///
/// Returns an error if configuration is invalid, database connection fails,
/// or required components cannot be initialized.
pub async fn initialize(args: config::Args) -> Result<ServerComponents> {
    let mut config = config::ServerConfig::from_args(args)?;

    // Probe NitroTPM BEFORE S3 config loading so we know whether to
    // use attested kms:Decrypt for document key decryption.
    let use_attestation = probe_nitro_tpm().await;

    // Load S3 config if configured (BEFORE database connection).
    // If the config has a document_key, also recovers the HPKE key pair.
    let (s3_client, s3_source, initial_etag, doc_keys, kms_client) =
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

    // AWS SDK and runtime configuration
    let env_or = |key: &str| -> String { std::env::var(key).unwrap_or_else(|_| "(empty)".into()) };
    tracing::info!(
        "AWS SDK: region={}, fips={}, dualstack={}, sts_regional={}, defaults_mode={}",
        env_or("AWS_REGION"),
        env_or("AWS_USE_FIPS_ENDPOINT"),
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

    crate::geo::warmup();
    tracing::info!("GeoIP database initialized");

    // Feature status summary — one log per feature for searchable CloudWatch events
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

    log_authenticator_policy(&config);

    if !config.oidc_configured() && !config.saml_configured() {
        tracing::warn!(
            "No upstream IdP configured -- enrollment (vouch enroll) will not work. \
             Set VOUCH_OIDC_* for OIDC or VOUCH_SAML_* for SAML."
        );
    }

    match &config.cors_origins {
        Some(origins) => tracing::info!("CORS: origins={}", origins.join(", ")),
        None => tracing::info!("CORS: same-origin only"),
    }

    // Warn if rp_id is localhost but TLS is configured (likely production)
    if vouch_common::is_loopback_host(&config.rp_id) && config.tls_configured() {
        tracing::warn!(
            target: "security",
            "rp_id is '{}' but TLS is configured -- \
             this allows WebAuthn origin relaxation in what appears to be a production deployment",
            config.rp_id,
        );
    }

    // Build AppState and start background tasks
    let state = build_app_state(&config, db.clone(), doc_keys, kms_client).await?;

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
async fn load_s3_config(
    config: &mut config::ServerConfig,
    use_attestation: bool,
) -> Result<(
    Option<aws_sdk_s3::Client>,
    Option<s3_config::S3ConfigSource>,
    Option<String>,
    Option<DocumentKeyMaterial>,
    Option<aws_sdk_kms::Client>,
)> {
    let Some(bucket) = &config.s3_config_bucket else {
        tracing::info!("Configuration source: environment variables");
        return Ok((None, None, None, None, None));
    };

    tracing::info!(
        "Configuration source: S3 (s3://{}/{})",
        bucket,
        config.s3_config_key
    );

    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(
            config
                .s3_config_region
                .as_ref()
                .map(|r| aws_config::Region::new(r.clone())),
        )
        .load()
        .await;

    let s3_client = aws_sdk_s3::Client::new(&sdk_config);

    // Create KMS client for document key decryption and signing.
    // Uses the same SDK config (region, credentials) as S3.
    let kms_client = aws_sdk_kms::Client::from_conf(
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

    // Fetch initial config - fail fast if unreachable.
    // If the config has a document_key, the P-384 private key is decrypted
    // via KMS (with NitroTPM attestation when available).
    let (s3_cfg, etag, doc_keys) =
        s3_config::fetch_s3_config(&s3_client, &source, Some(&kms_client), use_attestation)
            .await
            .context("Failed to fetch S3 configuration")?;

    // Merge S3 config (S3 wins over env vars)
    config.merge_s3_config(&s3_cfg, false); // Initial merge - all fields allowed
    tracing::info!("S3 configuration merged (etag: {etag})");

    Ok((
        Some(s3_client),
        Some(source),
        Some(etag),
        doc_keys,
        Some(kms_client),
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
async fn build_app_state(
    config: &config::ServerConfig,
    db: Pool,
    doc_keys: Option<DocumentKeyMaterial>,
    kms_client: Option<aws_sdk_kms::Client>,
) -> Result<Arc<AppState>> {
    // Build WebAuthn instance
    // Use base_url as origin (handles localhost with http and port correctly)
    let rp_origin = url::Url::parse(&config.base_url)?;
    let webauthn_builder =
        webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)?.rp_name(&config.rp_name);
    let webauthn = webauthn_builder.build()?;

    // Create a KMS client if any KMS key IDs are configured but no client
    // was provided (e.g., non-S3 deployments that still use KMS signing).
    let kms_needs = config.ssh_ca_kms_key_id.is_some()
        || config.oidc_signing_kms_key_id.is_some()
        || config.oidc_rsa_signing_kms_key_id.is_some()
        || config.jwt_hmac_kms_key_id.is_some();
    let kms_client = if kms_needs && kms_client.is_none() {
        tracing::info!("Creating KMS client for signing key access");
        let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &config.s3_config_region {
            builder = builder.region(aws_config::Region::new(region.clone()));
        }
        let sdk_config = builder.load().await;
        Some(aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::config::Builder::from(&sdk_config)
                .timeout_config(kms_timeout_config())
                .build(),
        ))
    } else {
        kms_client
    };

    // Build the KMS ARN resolver once. When `kms_account_id` is set, raw key
    // IDs from config are wrapped into full cross-account ARNs using
    // AWS_PARTITION/AWS_REGION from the environment.
    let kms_arn_resolver = KmsArnResolver::from_env(config.kms_account_id.as_deref());

    // Initialize SSH CA if configured
    // Priority: KMS key ID > PEM content (VOUCH_SSH_CA_KEY) > file path (VOUCH_SSH_CA_KEY_PATH)
    let ssh_ca = if let Some(key_id) = &config.ssh_ca_kms_key_id {
        let client = kms_client
            .as_ref()
            .context("KMS client required for SSH CA KMS signing")?
            .clone();
        let key_arn = kms_arn_resolver.resolve(key_id);
        let ca = ssh_ca::SshCa::from_kms(client, key_arn, &config.rp_id)
            .await
            .context("Failed to initialize KMS SSH CA")?;
        let pub_key = ca
            .public_key()
            .context("KMS SSH CA loaded but public key is not extractable")?;
        tracing::info!("SSH CA initialized (KMS): {}", pub_key);
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
        let key = OidcSigningKey::from_kms(client, key_arn)
            .await
            .context("Failed to initialize KMS OIDC signing key")?;
        tracing::info!("OIDC signing key initialized (KMS): {}", key.key_id());
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
        let key = OidcRsaSigningKey::from_kms(client, key_arn)
            .await
            .context("Failed to initialize KMS OIDC RSA signing key")?;
        tracing::info!("OIDC RSA signing key initialized (KMS): {}", key.key_id());
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

    // Fetch upstream IdP configuration if configured (OIDC or SAML, mutually exclusive).
    let upstream_idp = if config.oidc_configured() {
        let issuer = config
            .oidc_issuer_url
            .as_deref()
            .context("OIDC issuer URL missing")?;
        let provider = crate::services::idp::oidc::fetch_discovery(&http_client, issuer)
            .await
            .context(
                "Failed to fetch upstream OIDC discovery document. \
                     Check that VOUCH_OIDC_ISSUER is reachable.",
            )?;
        let brand = crate::services::idp::IdpBrand::from_issuer(&provider.issuer);
        let enrollment_domains = match &config.allowed_domains {
            Some(domains) => domains.join(", "),
            None => "(open enrollment)".to_string(),
        };
        tracing::info!(
            "Upstream IdP: {} (OIDC), issuer={}, auth={}, token={}, jwks={}, enrollment_domains={}",
            brand.display_name(),
            provider.issuer,
            provider.authorization_endpoint,
            provider.token_endpoint,
            provider.jwks_uri,
            enrollment_domains,
        );
        Some(crate::services::idp::UpstreamIdp::Oidc(Box::new(provider)))
    } else if config.saml_configured() {
        let metadata_url = config
            .saml_idp_metadata_url
            .as_deref()
            .context("SAML metadata URL missing")?;
        let metadata_xml = http_client
            .get(metadata_url)
            .send()
            .await
            .context("Failed to fetch SAML IdP metadata")?
            .error_for_status()
            .context("SAML IdP metadata request returned error status")?
            .text()
            .await
            .context("Failed to read SAML IdP metadata body")?;
        let idp_metadata = crate::services::idp::saml::metadata::parse_idp_metadata(&metadata_xml)
            .context("Failed to parse SAML IdP metadata")?;
        let brand = crate::services::idp::IdpBrand::from_entity_id(&idp_metadata.entity_id);
        let sp_entity_id = config
            .saml_sp_entity_id
            .clone()
            .unwrap_or_else(|| config.base_url.clone());
        let acs_url = format!("{}/saml/acs", config.base_url);
        let sso_url = idp_metadata
            .sso_post_url
            .as_deref()
            .or(idp_metadata.sso_redirect_url.as_deref())
            .unwrap_or("(none)");
        tracing::info!(
            "Upstream IdP: {} (SAML), entity_id={}, sso_url={}, binding={}, certs={}",
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
        let provider = crate::services::idp::saml::SamlProvider {
            idp_metadata,
            sp_entity_id,
            acs_url,
            email_attribute: config.saml_email_attribute.clone(),
            domain_attribute: config.saml_domain_attribute.clone(),
        };
        Some(crate::services::idp::UpstreamIdp::Saml(provider))
    } else {
        None
    };

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
            tracing::info!("Document encryption: HPKE (P-384 key pair from KMS)");
            std::sync::Arc::new(
                crate::crypto::document_crypto::HpkeDocumentCrypto::new(
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
        upstream_idp,
    });

    Ok(state)
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
