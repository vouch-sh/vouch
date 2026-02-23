// SPDX-License-Identifier: BUSL-1.1
//! Vouch identity server.

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    Router,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    serve::ListenerExt,
};
use axum_server::accept::NoDelayAcceptor;
use clap::Parser;
use rust_embed::Embed;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing_subscriber::EnvFilter;

use vouch_server::{
    AppState, config,
    crypto::{ssh_ca, tpm_decrypt},
    db::{Pool, dsql::DsqlEndpoint, migrations::run_dsql_migrations},
    handlers,
    infra::{cleanup, encrypt_config, rate_limit, request_id, s3_config},
    services::{
        integrations::github::GitHubApp,
        oidc::{OidcSigningKey, dpop},
    },
};

// ============================================================================
// Subcommand Dispatch
// ============================================================================

/// Top-level CLI with subcommands.
#[derive(Parser)]
#[command(name = "vouch-server", about = "Vouch identity server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Start the identity server.
    Serve(config::Args),
    /// Encrypt a plain S3Config JSON into a KMS-encrypted envelope.
    EncryptConfig(encrypt_config::EncryptConfigArgs),
}

#[derive(Embed)]
#[folder = "static/"]
struct Assets;

async fn favicon_handler() -> Response {
    static_handler(Path("images/favicon.ico".to_string())).await
}

async fn static_handler(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            // Use rust-embed's SHA256 hash as ETag for cache validation
            let etag = format!("\"{}\"", hex::encode(content.metadata.sha256_hash()));
            // Images and fonts rarely change — cache for 24h.
            // CSS/JS may change on each deploy — always revalidate via ETag.
            let mime_type = mime.type_().as_str();
            let cache_control = match mime_type {
                "image" | "font" => "public, max-age=86400",
                _ => "no-cache",
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (header::CACHE_CONTROL, cache_control.to_string()),
                    (header::ETAG, etag),
                ],
                content.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the aws-lc-rs crypto provider for rustls before any TLS usage.
    // Required by rustls 0.23+ which no longer auto-selects a provider.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls CryptoProvider"))?;

    // Load .env file if present (before anything else so env vars are available)
    dotenvy::dotenv().ok();

    // Two-pass CLI parse for backwards compatibility:
    // If the first argument is a known subcommand or help flag, parse with Cli struct
    // (so subcommands appear in --help). Otherwise, parse with config::Args directly
    // (legacy: `vouch-server --listen-addr ...`).
    let first_arg = std::env::args().nth(1).unwrap_or_default();
    match first_arg.as_str() {
        "serve" | "encrypt-config" | "help" | "--help" | "-h" => {
            let cli = Cli::parse();
            match cli.command {
                Commands::Serve(args) => run_server(args).await,
                Commands::EncryptConfig(args) => {
                    // encrypt-config logs to stderr so stdout is pure JSON
                    tracing_subscriber::fmt()
                        .with_writer(std::io::stderr)
                        .with_env_filter(
                            EnvFilter::try_from_default_env()
                                .unwrap_or_else(|_| EnvFilter::new("info")),
                        )
                        .init();
                    encrypt_config::run(args).await
                }
            }
        }
        _ => {
            // Legacy mode: no subcommand, parse as direct server args
            let args = config::Args::parse();
            run_server(args).await
        }
    }
}

async fn run_server(args: config::Args) -> Result<()> {
    // Initialize logging (only for serve mode; encrypt-config inits its own)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut config = config::ServerConfig::from_args(args)?;

    // Load S3 config if configured (BEFORE database connection)
    let (s3_client, s3_source, initial_etag) = if let Some(bucket) = &config.s3_config_bucket {
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
        // attestation + KMS to decrypt the config secrets.
        let (s3_cfg, etag) = s3_config::fetch_s3_config(&s3_client, &source, Some(&kms_client))
            .await
            .context("Failed to fetch S3 configuration")?;

        // Merge S3 config (S3 wins over env vars)
        config.merge_s3_config(&s3_cfg, false); // Initial merge - all fields allowed
        tracing::info!("S3 configuration merged (etag: {etag})");

        (Some(s3_client), Some(source), Some(etag))
    } else {
        tracing::info!("Configuration source: environment variables");
        (None, None, None)
    };

    tracing::info!("Starting vouch-server on {}", config.listen_addr);

    // Connect to database
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

    // Load additional settings from database (allowed_domains, org_name, download URLs)
    let db_settings = config.load_from_db(&db).await?;
    if db_settings.is_empty() {
        tracing::info!("No database settings configured");
    } else {
        tracing::info!("Loaded database settings: {}", db_settings.join(", "));
    }

    // Validate config after all sources merged (env, S3, database)
    config.validate()?;
    tracing::info!(
        "Configuration validated: rp_id={}, base_url={}, tls={}, NitroTPM={}",
        config.rp_id,
        config.base_url,
        config.tls_configured(),
        tpm_decrypt::is_nitro_tpm_available(),
    );

    // Warn if rp_id is localhost but TLS is configured (likely production)
    if vouch_common::is_loopback_host(&config.rp_id) && config.tls_configured() {
        tracing::warn!(
            target: "security",
            "rp_id is '{}' but TLS is configured — \
             this allows WebAuthn origin relaxation in what appears to be a production deployment",
            config.rp_id,
        );
    }

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
            if let Ok(pub_key) = ca.public_key() {
                tracing::info!("SSH CA initialized: {}", pub_key);
            } else {
                tracing::info!("SSH CA initialized");
            }
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

    // Build shared HTTP client for outbound API calls (GitHub, OIDC, etc.)
    let http_client =
        vouch_common::http::server_client(&format!("vouch-server/{}", env!("CARGO_PKG_VERSION")))
            .context("Failed to create shared HTTP client")?;

    // Initialize GitHub App if configured
    let github_app = match GitHubApp::load(&config, http_client.clone()) {
        Ok(Some(app)) => Some(Arc::new(app)),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("Failed to initialize GitHub App: {e}");
            None
        }
    };

    // Create DPoP state (single instance shared between AppState and cleanup task)
    let dpop_state = Arc::new(dpop::DpopState::new());

    // Create rate limiter for auth/token endpoints.
    // Uses GovernorConfig::secure() preset: burst of 2, replenish 1 every 4s per IP.
    let auth_rate_limiter = rate_limit::build_auth_rate_limiter();

    // Wrap config in ArcSwap for dynamic updates
    let config_swap = Arc::new(ArcSwap::from_pointee(config.clone()));

    // Create shared state
    let state = Arc::new(AppState {
        db: db.clone(),
        config: config_swap.clone(),
        webauthn,
        ssh_ca,
        dpop: Arc::clone(&dpop_state),
        oidc_key,
        github_app,
        http_client,
    });

    // Start background cleanup task if enabled
    let cleanup_handle = if config.cleanup_interval_minutes > 0 {
        tracing::info!(
            "Starting background cleanup task (interval: {} minutes)",
            config.cleanup_interval_minutes
        );
        Some(cleanup::start_cleanup_task(
            db.clone(),
            dpop_state,
            config.cleanup_interval_minutes,
            config.auth_events_retention_days,
            config.oauth_events_retention_days,
        ))
    } else {
        tracing::info!("Background cleanup task disabled");
        None
    };

    // S3 config polling task handle (set up after TLS config is created if needed)
    let mut s3_poll_handle: Option<tokio::task::JoinHandle<()>> = None;

    // Build router from two groups with separate CORS policies:
    // - API routes: permissive CORS (Access-Control-Allow-Origin: *) for OIDC/SCIM integration
    // - UI routes: restrictive same-origin CORS (or configured via VOUCH_CORS_ORIGINS)

    // Rate-limited auth/token routes.
    // These endpoints are brute-force targets so rate limiting is critical.
    let rate_limited_routes = Router::new()
        .route("/v1/auth/login/start", post(handlers::auth::login_start))
        .route(
            "/v1/auth/login/complete",
            post(handlers::auth::login_complete),
        )
        .route(
            "/v1/auth/register/start",
            post(handlers::auth::register_start),
        )
        .route(
            "/v1/auth/register/complete",
            post(handlers::auth::register_complete),
        )
        .route("/oauth/token", post(handlers::oidc::token))
        .route("/oauth/device", post(handlers::device::device_code))
        .layer(auth_rate_limiter);

    let api_routes = Router::new()
        // OIDC Provider endpoints
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .route("/oauth/authorize", get(handlers::oidc::authorize))
        // OIDC Core Section 5.3.1: UserInfo MUST support GET and POST
        .route(
            "/oauth/userinfo",
            get(handlers::oidc::userinfo).post(handlers::oidc::userinfo),
        )
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
        // Auth endpoints
        .route("/v1/auth/status", get(handlers::auth::status))
        // Merge rate-limited routes
        .merge(rate_limited_routes)
        // Key management (authenticated API)
        .route("/v1/keys", get(handlers::keys::list_keys))
        .route(
            "/v1/keys/{id}",
            patch(handlers::keys::rename_key).delete(handlers::keys::delete_key),
        )
        // Credential issuance
        .route(
            "/v1/credentials/ssh",
            post(handlers::credentials::issue_ssh_certificate),
        )
        .route(
            "/v1/credentials/ssh/ca",
            get(handlers::credentials::get_ssh_ca_public_key),
        )
        .route(
            "/v1/credentials/ssh/krl",
            get(handlers::credentials::get_ssh_krl),
        )
        .route(
            "/v1/credentials/ssh/krl/{serial}",
            get(handlers::credentials::check_ssh_revocation),
        )
        .route(
            "/v1/credentials/aws/token",
            get(handlers::credentials::get_aws_token),
        )
        // GitHub credential endpoints
        .route(
            "/v1/credentials/github/status",
            get(handlers::credentials::get_github_status),
        )
        .route(
            "/v1/credentials/github/token",
            post(handlers::credentials::get_github_token),
        )
        // Cloud integration config API
        .route(
            "/v1/integrations/aws",
            get(handlers::integrations::get_aws_integration)
                .put(handlers::integrations::set_aws_integration)
                .delete(handlers::integrations::delete_aws_integration),
        )
        // Org admin API (JSON, JWT Bearer auth)
        .route(
            "/api/v1/org/auth-events",
            get(handlers::admin::list_auth_events),
        )
        .route(
            "/api/v1/org/scim-tokens",
            get(handlers::admin::list_scim_tokens).post(handlers::admin::create_scim_token),
        )
        .route(
            "/api/v1/org/scim-tokens/{id}",
            delete(handlers::admin::delete_scim_token),
        )
        // GitHub webhook API
        .route(
            "/api/webhooks/github",
            post(handlers::github::github_webhook),
        )
        // Applications API (JSON)
        .route(
            "/api/v1/applications",
            get(handlers::applications::list_applications_api)
                .post(handlers::applications::create_application_api),
        )
        .route(
            "/api/v1/applications/{id}",
            get(handlers::applications::get_application_api)
                .patch(handlers::applications::update_application_api)
                .delete(handlers::applications::delete_application_api),
        )
        .route(
            "/api/v1/applications/{id}/rotate",
            post(handlers::applications::rotate_secret_api),
        )
        .route(
            "/api/v1/applications/{id}/revoke",
            post(handlers::applications::revoke_tokens_api),
        )
        // SCIM 2.0 endpoints (RFC 7643/7644)
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(handlers::scim::service_provider_config),
        )
        .route("/scim/v2/Schemas", get(handlers::scim::schemas))
        .route(
            "/scim/v2/ResourceTypes",
            get(handlers::scim::resource_types),
        )
        .route(
            "/scim/v2/Users",
            get(handlers::scim::list_users).post(handlers::scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(handlers::scim::get_user)
                .patch(handlers::scim::patch_user)
                .delete(handlers::scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(handlers::scim::list_groups).post(handlers::scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(handlers::scim::get_group)
                .patch(handlers::scim::patch_group)
                .delete(handlers::scim::delete_group),
        )
        .layer(build_api_cors_layer())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::PRAGMA,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::EXPIRES,
            HeaderValue::from_static("0"),
        ));

    let ui_routes = Router::new()
        // Landing page with smart routing
        .route("/", get(handlers::home::home_page))
        .route("/install", get(handlers::install::install_page))
        .route("/health", get(|| async { "ok" }))
        // Legal pages (redirect to vouch.sh)
        .route("/privacy", get(handlers::legal::privacy_page))
        .route("/terms", get(handlers::legal::terms_page))
        // Integrations page
        .route(
            "/integrations",
            get(handlers::integrations::integrations_page),
        )
        // Browser-based WebAuthn login (RFC 6749, RFC 9207, RFC 9700)
        .route("/login", get(handlers::browser_login::login_page))
        .route(
            "/login/webauthn/start",
            post(handlers::browser_login::browser_login_start),
        )
        .route(
            "/login/webauthn/complete",
            post(handlers::browser_login::browser_login_complete),
        )
        // Browser-based enrollment
        .route("/device", get(handlers::enroll::device_verify_page))
        .route("/device", post(handlers::enroll::device_verify_submit))
        // Direct enrollment (browser-only, no CLI required)
        .route("/enroll/start", get(handlers::enroll::direct_enroll_start))
        .route(
            "/enroll/webauthn/start",
            post(handlers::enroll::browser_register_start),
        )
        .route(
            "/enroll/webauthn/complete",
            post(handlers::enroll::browser_register_complete),
        )
        // Key management during enrollment (uses cookie for auth)
        .route("/enroll/keys", get(handlers::enroll::enroll_keys_page))
        .route("/logout", post(handlers::auth::logout))
        .route("/enroll/keys/api", get(handlers::enroll_keys::list_keys))
        .route(
            "/enroll/keys/{id}",
            patch(handlers::enroll_keys::rename_key).delete(handlers::enroll_keys::delete_key),
        )
        // GitHub App installation
        .route(
            "/github/connect",
            get(handlers::github::github_connect_page),
        )
        .route("/github/callback", get(handlers::github::github_callback))
        .route("/github/link", get(handlers::github::github_link_start))
        .route(
            "/github/reconnect",
            post(handlers::github::github_reconnect),
        )
        .route(
            "/github/success",
            get(handlers::github::github_success_page),
        )
        // OAuth Application Registration Portal
        .route(
            "/applications",
            get(handlers::applications::list_applications_page),
        )
        .route(
            "/applications/new",
            get(handlers::applications::create_application_page)
                .post(handlers::applications::create_application_form),
        )
        .route(
            "/applications/{id}",
            get(handlers::applications::detail_application_page)
                .post(handlers::applications::update_application_form),
        )
        .route(
            "/applications/{id}/delete",
            post(handlers::applications::delete_application_form),
        )
        .route(
            "/applications/{id}/rotate",
            post(handlers::applications::rotate_secret_form),
        )
        // Static file serving for CSS, JS, and assets (embedded in binary via rust-embed)
        .route("/static/{*path}", get(static_handler))
        // Browsers request /favicon.ico at the root path
        .route("/favicon.ico", get(favicon_handler))
        .layer(build_ui_cors_layer(&config));

    let app = apply_security_layers(api_routes.merge(ui_routes), &config)
        .layer(request_id::propagate_request_id_layer())
        .layer(request_id::set_request_id_layer())
        .with_state(state.clone());

    // Start server with graceful shutdown
    if config.tls_configured() {
        let tls_config = vouch_server::infra::tls::build_tls_config(&config).await?;

        // TLS mode: always listen on 443 (HTTPS) and 80 (HTTP redirect)
        let https_addr: std::net::SocketAddr =
            "[::]:443".parse().context("Invalid HTTPS listen address")?;
        let http_addr: std::net::SocketAddr =
            "[::]:80".parse().context("Invalid HTTP listen address")?;

        tracing::info!(
            "TLS enabled - listening on https://{} and http://{} (redirect)",
            https_addr,
            http_addr
        );
        tracing::info!("Send SIGHUP to reload TLS certificates");

        // Create shared cancellation token for coordinated shutdown
        let shutdown_token = CancellationToken::new();

        // Spawn shutdown signal handler that cancels the token
        let shutdown_token_for_signal = shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_token_for_signal.cancel();
        });

        // Start S3 config polling task if configured (with TLS config for hot reload)
        if let (Some(client), Some(source), Some(etag)) =
            (s3_client.clone(), s3_source.clone(), initial_etag.clone())
        {
            tracing::info!(
                "Starting S3 config polling task (interval: {}s)",
                source.poll_interval_seconds
            );
            s3_poll_handle = Some(s3_config::start_s3_config_task(
                client,
                source,
                config_swap.clone(),
                Some(tls_config.clone()),
                etag,
            ));
        }

        // Clone for SIGHUP handler - read from current config (not env vars)
        let tls_config_for_reload = tls_config.clone();
        let config_for_sighup = config_swap.clone();

        // Spawn SIGHUP handler for certificate hot reload
        #[cfg(unix)]
        tokio::spawn(async move {
            let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                tracing::warn!("Failed to register SIGHUP handler, TLS hot reload disabled");
                return;
            };

            loop {
                sighup.recv().await;
                tracing::info!("Received SIGHUP, reloading TLS certificates...");

                // Read from current config (supports both env vars and S3 config)
                let cfg = config_for_sighup.load();
                match (&cfg.tls_cert, &cfg.tls_key) {
                    (Some(cert), Some(key)) => {
                        match vouch_server::infra::tls::reload_tls_from_config(
                            &tls_config_for_reload,
                            cert,
                            key,
                        )
                        .await
                        {
                            Ok(()) => tracing::info!("TLS certificates reloaded successfully"),
                            Err(e) => tracing::error!("Failed to reload TLS certificates: {e:#}"),
                        }
                    }
                    _ => tracing::warn!("TLS not configured, nothing to reload"),
                }
            }
        });

        // Create handle for graceful shutdown of HTTPS server
        let handle = axum_server::Handle::new();
        let handle_for_shutdown = handle.clone();

        // Spawn HTTPS shutdown handler (uses cancellation token)
        let token_for_https = shutdown_token.clone();
        tokio::spawn(async move {
            token_for_https.cancelled().await;
            tracing::info!("Initiating graceful shutdown (30s timeout)");
            handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });

        // Build HTTP redirect router (with state for Host validation)
        let redirect_app = vouch_server::build_redirect_router(state.clone());

        // Spawn HTTP redirect server (port 80) - best effort, not fatal if fails
        let token_for_http = shutdown_token.clone();
        let http_handle = tokio::spawn(async move {
            match tokio::net::TcpListener::bind(http_addr).await {
                Ok(listener) => {
                    tracing::info!("HTTP redirect server listening on {}", http_addr);
                    let listener = listener.tap_io(|tcp| {
                        if let Err(err) = tcp.set_nodelay(true) {
                            tracing::trace!(
                                "failed to set TCP_NODELAY on incoming connection: {err:#}"
                            );
                        }
                    });
                    if let Err(e) = axum::serve(listener, redirect_app)
                        .with_graceful_shutdown(token_for_http.cancelled_owned())
                        .await
                    {
                        tracing::error!("HTTP redirect server error: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not bind HTTP redirect on {}: {e} (continuing without redirect)",
                        http_addr
                    );
                    tracing::warn!(
                        "Hint: Ports below 1024 require CAP_NET_BIND_SERVICE capability"
                    );
                }
            }
        });

        // Run HTTPS server (port 443) - this blocks until shutdown
        axum_server::bind_rustls(https_addr, tls_config)
            .map(|acceptor| acceptor.acceptor(NoDelayAcceptor::new()))
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;

        // Wait for HTTP redirect server to finish
        let _ = http_handle.await;
    } else {
        // Start S3 config polling task if configured (no TLS)
        if let (Some(client), Some(source), Some(etag)) = (s3_client, s3_source, initial_etag) {
            tracing::info!(
                "Starting S3 config polling task (interval: {}s)",
                source.poll_interval_seconds
            );
            s3_poll_handle = Some(s3_config::start_s3_config_task(
                client,
                source,
                config_swap,
                None, // No TLS config to reload
                etag,
            ));
        }

        let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
        tracing::info!("Listening on http://{}", config.listen_addr);

        let listener = listener.tap_io(|tcp| {
            if let Err(err) = tcp.set_nodelay(true) {
                tracing::trace!("failed to set TCP_NODELAY on incoming connection: {err:#}");
            }
        });
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    // Clean up background tasks
    if let Some(handle) = s3_poll_handle {
        tracing::info!("Shutting down S3 config polling task");
        handle.abort();
    }
    if let Some(handle) = cleanup_handle {
        tracing::info!("Shutting down cleanup task");
        handle.abort();
    }

    // Close database pool (signals DSQL token refresh task to stop)
    tracing::info!("Closing database pool");
    db.close().await;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Build permissive CORS layer for API endpoints (OIDC, SCIM, v1, api).
///
/// These endpoints authenticate via tokens in request bodies or Authorization headers,
/// never cookies — so `Access-Control-Allow-Origin: *` without credentials is safe and
/// allows any OIDC relying party to integrate without configuration.
fn build_api_cors_layer() -> CorsLayer {
    use axum::http::{Method, header};

    CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Build restrictive CORS layer for UI routes (login, enroll, applications, etc.).
///
/// These routes use cookie-based sessions and should not be accessible cross-origin
/// by default. `VOUCH_CORS_ORIGINS` can override this for advanced use cases.
fn build_ui_cors_layer(config: &config::ServerConfig) -> CorsLayer {
    use axum::http::{Method, header};

    match &config.cors_origins {
        Some(origins) if !origins.is_empty() => {
            tracing::info!("UI CORS configured for origins: {:?}", origins);
            let parsed_origins: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();

            CorsLayer::new()
                .allow_origin(parsed_origins)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::ORIGIN,
                ])
                .allow_credentials(true)
                .max_age(std::time::Duration::from_secs(3600))
        }
        _ => {
            // No CORS configured — restrictive same-origin defaults
            CorsLayer::new()
        }
    }
}

/// Apply security response headers globally to the router.
///
/// Sets X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
/// Cross-Origin-Opener-Policy, Content-Security-Policy, and HSTS (when TLS is configured).
fn apply_security_layers(
    router: Router<Arc<AppState>>,
    config: &config::ServerConfig,
) -> Router<Arc<AppState>> {
    use axum::http::{HeaderName, HeaderValue};

    let router = router
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "camera=(), microphone=(), geolocation=(), payment=()",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            ),
        ));

    // HSTS only when TLS is configured
    if config.tls_configured() {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
    } else {
        router
    }
}

/// Redact the password from a database URL for safe logging.
///
/// - `postgres://user:secret@host/db` → `postgres://user:***@host/db`
/// - `sqlite:path.db` → `sqlite:path.db` (no password to redact)
fn redact_database_url(url: &str) -> String {
    // SQLite URLs use "sqlite:" prefix and never contain passwords
    if url.starts_with("sqlite:") {
        return url.to_string();
    }

    // Try to parse as a standard URL (postgres://, postgresql://)
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                // url::Url::set_password returns Result<(), ()>
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        // If parsing fails, return the URL with a generic redaction
        Err(_) => url.to_string(),
    }
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        }
        () = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
