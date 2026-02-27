// SPDX-License-Identifier: BUSL-1.1
//! Server initialization pipeline.
//!
//! Handles configuration loading (env + S3), database connection and migration,
//! building `AppState`, and starting background tasks.

use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use secrecy::ExposeSecret;
use tokio::task::JoinHandle;

use crate::{
    AppState, config,
    crypto::{ssh_ca, tpm_decrypt},
    db::{Pool, dsql::DsqlEndpoint, migrations::run_dsql_migrations, pool::redact_database_url},
    infra::{cleanup, s3_config, s3_config::DocumentKeyMaterial},
    services::{integrations::github::GitHubApp, oidc::OidcSigningKey},
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
    pub fn build_app(&self) -> axum::Router {
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

    // Load S3 config if configured (BEFORE database connection).
    // If the config has a document_key, also recovers the HPKE key pair.
    let (s3_client, s3_source, initial_etag, doc_keys) = load_s3_config(&mut config).await?;

    tracing::info!("Starting vouch-server on {}", config.listen_addr);

    // Connect to database and run migrations
    let db = connect_and_migrate(&config).await?;

    // Validate config after all sources merged (env, S3)
    config.validate()?;
    tracing::info!(
        "Configuration validated: rp_id={}, base_url={}, tls={}, NitroTPM={}",
        config.rp_id,
        config.base_url,
        config.tls_configured(),
        tpm_decrypt::is_nitro_tpm_available(),
    );

    // Feature status summary — one log per feature for searchable CloudWatch events
    tracing::info!(
        "Sessions: duration={}h, dpop_max_age={}s",
        config.session_hours,
        config.dpop_max_age_seconds,
    );

    if config.oidc_configured() {
        tracing::info!(
            "OIDC: configured, issuer={}",
            config.oidc_issuer_url.as_deref().unwrap_or("unknown"),
        );
    } else {
        tracing::warn!(
            "OIDC not configured -- enrollment (vouch enroll) will not work. \
             Set VOUCH_OIDC_ISSUER, VOUCH_OIDC_CLIENT_ID, and VOUCH_OIDC_CLIENT_SECRET"
        );
    }

    match &config.allowed_domains {
        Some(domains) => tracing::info!("Allowed domains: {}", domains.join(", ")),
        None => tracing::info!("Allowed domains: unrestricted"),
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
    let state = build_app_state(&config, db.clone(), doc_keys).await?;

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

/// Load configuration from S3 if configured.
///
/// Fetches the initial config from S3, handles encrypted envelopes via
/// NitroTPM + KMS, and merges into the server config. If the config has
/// a `document_key`, also returns the key material for document encryption.
async fn load_s3_config(
    config: &mut config::ServerConfig,
) -> Result<(
    Option<aws_sdk_s3::Client>,
    Option<s3_config::S3ConfigSource>,
    Option<String>,
    Option<DocumentKeyMaterial>,
)> {
    let Some(bucket) = &config.s3_config_bucket else {
        tracing::info!("Configuration source: environment variables");
        return Ok((None, None, None, None));
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

    // Create KMS client for envelope decryption (only used if config is encrypted).
    // Uses the same SDK config (region, credentials) as S3.
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    let source = s3_config::S3ConfigSource {
        bucket: bucket.clone(),
        key: config.s3_config_key.clone(),
        region: config.s3_config_region.clone(),
        poll_interval_seconds: config.s3_config_poll_interval,
    };

    // Fetch initial config - fail fast if unreachable.
    // If the S3 object is an encrypted envelope, this will use NitroTPM
    // attestation + KMS to decrypt the config secrets. If the config has
    // a document_key, the P-384 private key is decrypted via plain KMS.
    let (s3_cfg, etag, doc_keys) =
        s3_config::fetch_s3_config(&s3_client, &source, Some(&kms_client))
            .await
            .context("Failed to fetch S3 configuration")?;

    // Merge S3 config (S3 wins over env vars)
    config.merge_s3_config(&s3_cfg, false); // Initial merge - all fields allowed
    tracing::info!("S3 configuration merged (etag: {etag})");

    Ok((Some(s3_client), Some(source), Some(etag), doc_keys))
}

/// Connect to the database and run migrations.
async fn connect_and_migrate(config: &config::ServerConfig) -> Result<Pool> {
    let db = Pool::connect(&config.database_url).await?;
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
            ((after - before) as usize, total)
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
                ((after - before) as usize, total)
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
) -> Result<Arc<AppState>> {
    // Build WebAuthn instance
    // Use base_url as origin (handles localhost with http and port correctly)
    let rp_origin = url::Url::parse(&config.base_url)?;
    let webauthn_builder =
        webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)?.rp_name(&config.rp_name);
    let webauthn = webauthn_builder.build()?;

    // Initialize SSH CA if configured
    // Priority: PEM content (VOUCH_SSH_CA_KEY) > file path (VOUCH_SSH_CA_KEY_PATH)
    let ssh_ca = match ssh_ca::SshCa::load(
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
    };

    // Initialize OIDC signing key (ES256 for AWS and OIDC ID tokens)
    let oidc_key = OidcSigningKey::load_or_generate(
        config.oidc_signing_key.as_ref().map(|s| s.expose_secret()),
    )?;

    if config.oidc_signing_key.is_none() {
        tracing::warn!(
            "Using ephemeral OIDC signing key -- all issued tokens will be \
             invalidated on server restart. Set VOUCH_OIDC_SIGNING_KEY to persist."
        );
    }

    // Build shared HTTP client for outbound API calls (GitHub, OIDC, etc.)
    let http_client =
        vouch_common::http::server_client(&format!("vouch-server/{}", env!("CARGO_PKG_VERSION")))
            .context("Failed to create shared HTTP client")?;

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
        github_app,
        http_client,
    });

    Ok(state)
}
