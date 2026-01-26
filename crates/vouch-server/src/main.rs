//! Vouch identity server.

use anyhow::Result;
use axum::{
    Router,
    routing::{delete, get, post},
};
use clap::Parser;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::signal;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::EnvFilter;

mod cleanup;
mod config;
mod db;
mod dpop;
mod extractors;
mod handlers;
mod ssh_ca;
mod webauthn_verify;

#[cfg(test)]
mod test_utils;

/// Shared application state.
pub struct AppState {
    pub db: SqlitePool,
    pub config: config::ServerConfig,
    pub webauthn: webauthn_rs::Webauthn,
    /// SSH Certificate Authority (optional, None if disabled).
    pub ssh_ca: Option<ssh_ca::SshCa>,
    /// RFC 9449 DPoP state (nonce manager, JTI cache).
    pub dpop: dpop::DpopState,
}

#[tokio::main]
async fn main() -> Result<()> {
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
    let rp_origin = url::Url::parse(&format!("https://{}", config.rp_id))?;
    let webauthn_builder =
        webauthn_rs::WebauthnBuilder::new(&config.rp_id, &rp_origin)?.rp_name(&config.rp_name);
    let webauthn = webauthn_builder.build()?;

    // Initialize SSH CA if configured
    let ssh_ca = if let Some(ref key_path) = config.ssh_ca_key_path {
        if key_path.is_empty() {
            tracing::info!("SSH CA disabled (empty key path)");
            None
        } else {
            let path = std::path::Path::new(key_path);
            match ssh_ca::SshCa::load_or_create(path, &config.rp_id) {
                Ok(ca) => {
                    if let Ok(pub_key) = ca.public_key() {
                        tracing::info!("SSH CA initialized: {}", pub_key);
                    } else {
                        tracing::info!("SSH CA initialized");
                    }
                    Some(ca)
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize SSH CA: {e}");
                    None
                }
            }
        }
    } else {
        None
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
        .route("/admin-setup", get(handlers::home::admin_setup_page))
        .route(
            "/developer-setup",
            get(handlers::home::developer_setup_page),
        )
        .route("/health", get(|| async { "ok" }))
        // Legal pages
        .route("/privacy", get(handlers::legal::privacy_page))
        .route("/terms", get(handlers::legal::terms_page))
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
        .route("/oauth/device/code", post(handlers::device::device_code))
        // Unified token endpoint (handles both authorization_code and device_code grants)
        .route("/oauth/token", post(handlers::oidc::token))
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
        // Key management
        .route("/v1/keys", get(handlers::keys::list_keys))
        .route("/v1/keys/{id}", delete(handlers::keys::delete_key))
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
        // Admin login/logout
        .route(
            "/admin/login",
            get(handlers::admin::admin_login_page).post(handlers::admin::admin_login_start),
        )
        .route("/admin/callback", get(handlers::admin::admin_oidc_callback))
        .route("/admin/logout", post(handlers::admin::admin_logout))
        // Admin setup wizard
        .route("/admin/setup", get(handlers::admin::setup_page))
        .route("/admin/setup/oidc", post(handlers::admin::setup_save_oidc))
        .route("/admin/setup/test", post(handlers::admin::setup_test_oidc))
        .route("/admin/users", get(handlers::admin::list_users))
        .route(
            "/admin/users/{id}/delete",
            post(handlers::admin::delete_user),
        )
        // Admin API (JSON)
        .route(
            "/api/v1/admin/auth-events",
            get(handlers::admin::list_auth_events),
        )
        .route(
            "/api/v1/admin/scim-tokens",
            get(handlers::admin::list_scim_tokens).post(handlers::admin::create_scim_token),
        )
        .route(
            "/api/v1/admin/scim-tokens/{id}",
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
