//! Vouch identity server.

use anyhow::Result;
use axum::{
    Router,
    routing::{delete, get, post},
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod handlers;

/// Shared application state.
pub struct AppState {
    pub db: SqlitePool,
    pub config: config::ServerConfig,
    pub webauthn: webauthn_rs::Webauthn,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Load configuration from environment
    let mut config = config::ServerConfig::from_env()?;
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

    // Create shared state
    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        webauthn,
    });

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
        // OIDC Provider endpoints
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .route("/oauth/authorize", get(handlers::oidc::authorize))
        .route("/oauth/userinfo", get(handlers::oidc::userinfo))
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
        .route("/oauth/token", post(handlers::device::device_token))
        // Browser-based enrollment
        .route("/device", get(handlers::enroll::device_verify_page))
        .route("/device", post(handlers::enroll::device_verify_submit))
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
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
        // Admin setup wizard
        .route("/admin/setup", get(handlers::admin::setup_page))
        .route("/admin/setup/oidc", post(handlers::admin::setup_save_oidc))
        .route("/admin/setup/test", post(handlers::admin::setup_test_oidc))
        .route("/admin/users", get(handlers::admin::list_users))
        .route(
            "/admin/users/{id}/delete",
            post(handlers::admin::delete_user),
        )
        // Static file serving for CSS, JS, and assets
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Listening on {}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
