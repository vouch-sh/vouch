// SPDX-License-Identifier: BUSL-1.1
//! Vouch identity server.

use anyhow::Result;
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use clap::Parser;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::signal;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;

use vouch_server::{AppState, cleanup, config, dpop, github_app, handlers, oidc_key, ssh_ca};

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (before anything else so env vars are available)
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse command-line arguments and environment variables
    let args = config::Args::parse();
    let mut config = config::ServerConfig::from_args(args)?;
    tracing::info!("Starting vouch-server on {}", config.listen_addr);

    // Connect to database
    let db = SqlitePool::connect(&config.database_url).await?;
    tracing::info!("Connected to database");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("Database migrations complete");

    // Load configuration from database (overrides env vars where set)
    config.load_from_db(&db).await?;
    tracing::info!("Configuration loaded from database");

    // Build WebAuthn instance
    // Use verification_base_url as origin (handles localhost with http and port correctly)
    let rp_origin = url::Url::parse(&config.verification_base_url)?;
    let webauthn_builder =
        webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)?.rp_name(&config.rp_name);
    let webauthn = webauthn_builder.build()?;

    // Initialize SSH CA if configured
    // Priority: PEM content (VOUCH_SSH_CA_KEY) > file path (VOUCH_SSH_CA_KEY_PATH)
    let ssh_ca = match ssh_ca::SshCa::load(
        config.ssh_ca_key.as_deref(),
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
    let oidc_key = oidc_key::OidcSigningKey::load_or_generate(config.oidc_signing_key.as_deref())?;
    tracing::info!("OIDC signing key initialized: {}", oidc_key.key_id());

    // Initialize GitHub App if configured
    let github_app = match github_app::GitHubApp::load(&config) {
        Ok(Some(app)) => {
            tracing::info!("GitHub App initialized: app_id={}", app.app_id().0);
            Some(app)
        }
        Ok(None) => {
            tracing::info!("GitHub App not configured");
            None
        }
        Err(e) => {
            tracing::warn!("Failed to initialize GitHub App: {e}");
            None
        }
    };

    // Create DPoP state
    let dpop_state = Arc::new(dpop::DpopState::new());

    // Create shared state
    let state = Arc::new(AppState {
        db: db.clone(),
        config: config.clone(),
        webauthn,
        ssh_ca,
        dpop: dpop::DpopState::new(),
        oidc_key,
        github_app,
    });

    // Start background cleanup task if enabled
    let cleanup_handle = if config.cleanup_interval_minutes > 0 {
        tracing::info!(
            "Starting background cleanup task (interval: {} minutes)",
            config.cleanup_interval_minutes
        );
        Some(cleanup::start_cleanup_task(
            db,
            dpop_state,
            config.cleanup_interval_minutes,
            config.auth_events_retention_days,
            config.oauth_events_retention_days,
        ))
    } else {
        tracing::info!("Background cleanup task disabled");
        None
    };

    // Build router
    let app = Router::new()
        // Landing page with smart routing
        .route("/", get(handlers::home::home_page))
        .route("/install", get(handlers::install::install_page))
        .route("/health", get(|| async { "ok" }))
        // Legal pages
        .route("/about", get(handlers::about::about_page))
        .route("/privacy", get(handlers::legal::privacy_page))
        .route("/terms", get(handlers::legal::terms_page))
        // Documentation pages
        .route("/docs", get(handlers::docs::docs_index_page))
        .route(
            "/docs/getting-started",
            get(handlers::docs::getting_started_page),
        )
        .route("/docs/aws", get(handlers::docs::aws_setup_page))
        .route("/docs/gcp", get(handlers::docs::gcp_setup_page))
        .route("/docs/ssh", get(handlers::docs::ssh_page))
        .route("/docs/kubernetes", get(handlers::docs::kubernetes_page))
        .route("/docs/github", get(handlers::docs::github_setup_page))
        .route("/docs/docker", get(handlers::docs::docker_page))
        .route("/docs/applications", get(handlers::docs::applications_page))
        .route("/docs/scim", get(handlers::docs::scim_page))
        // Integrations page
        .route(
            "/integrations",
            get(handlers::integrations::integrations_page),
        )
        // OIDC Provider endpoints
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .route("/oauth/authorize", get(handlers::oidc::authorize))
        .route("/oauth/userinfo", get(handlers::oidc::userinfo))
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        // Legacy auth endpoints
        .route(
            "/v1/auth/register/start",
            post(handlers::auth::register_start),
        )
        .route(
            "/v1/auth/register/complete",
            post(handlers::auth::register_complete),
        )
        .route("/v1/auth/login/start", post(handlers::auth::login_start))
        .route(
            "/v1/auth/login/complete",
            post(handlers::auth::login_complete),
        )
        .route("/v1/auth/status", get(handlers::auth::status))
        // Device Authorization Grant (RFC 8628)
        .route("/oauth/device", post(handlers::device::device_code))
        // Unified token endpoint (handles both authorization_code and device_code grants)
        .route("/oauth/token", post(handlers::oidc::token))
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
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
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
        .route(
            "/v1/credentials/gcp/token",
            get(handlers::credentials::get_gcp_token),
        )
        .route(
            "/v1/credentials/k8s/token",
            get(handlers::credentials::get_k8s_token),
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
            "/v1/integrations/gcp",
            get(handlers::integrations::get_gcp_integration)
                .put(handlers::integrations::set_gcp_integration)
                .delete(handlers::integrations::delete_gcp_integration),
        )
        .route(
            "/v1/integrations/aws",
            get(handlers::integrations::get_aws_integration)
                .put(handlers::integrations::set_aws_integration)
                .delete(handlers::integrations::delete_aws_integration),
        )
        // GCP browser-based configuration
        .route(
            "/gcp/configure",
            get(handlers::integrations::gcp_configure_page)
                .post(handlers::integrations::gcp_configure_submit),
        )
        .route(
            "/gcp/configure/delete",
            post(handlers::integrations::gcp_configure_delete),
        )
        // GitHub App installation
        .route(
            "/api/webhooks/github",
            post(handlers::github::github_webhook),
        )
        .route(
            "/github/connect",
            get(handlers::github::github_connect_page),
        )
        .route("/github/callback", get(handlers::github::github_callback))
        .route(
            "/github/success",
            get(handlers::github::github_success_page),
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
        // OAuth Application Registration Portal (Phase 7)
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
        // Static file serving for CSS, JS, and assets
        // Use /static in Docker, fall back to static for local development
        .nest_service(
            "/static",
            ServeDir::new(if std::path::Path::new("/static").exists() {
                "/static"
            } else if std::path::Path::new("crates/vouch-server/static").exists() {
                "crates/vouch-server/static"
            } else {
                "static"
            }),
        )
        .layer(build_cors_layer(&config))
        .with_state(state);

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Clean up background tasks
    if let Some(handle) = cleanup_handle {
        tracing::info!("Shutting down cleanup task");
        handle.abort();
    }

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Build CORS layer based on configuration.
fn build_cors_layer(config: &config::ServerConfig) -> CorsLayer {
    use axum::http::{Method, header};

    match &config.cors_origins {
        None => {
            // No CORS configured - use restrictive defaults
            CorsLayer::new()
        }
        Some(origins) if origins.iter().any(|o| o == "*") => {
            // Allow all origins (not recommended for production)
            tracing::warn!("CORS configured to allow all origins - not recommended for production");
            CorsLayer::permissive()
        }
        Some(origins) => {
            // Allow specific origins
            tracing::info!("CORS configured for origins: {:?}", origins);
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
    }
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .ok()
            .map(|mut s| async move { s.recv().await });
        // If signal setup fails, just wait forever
        std::future::pending::<()>().await
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
