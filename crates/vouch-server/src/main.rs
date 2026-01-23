//! vouch identity server
//!
//! Handles FIDO2 authentication, credential issuance, and delegation management.

use anyhow::Result;
use axum::{
    routing::{delete, get, post},
    Router,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

mod config;
mod db;
mod handlers;
mod services;

use config::ServerConfig;

/// Application state shared across handlers
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub config: ServerConfig,
    pub webauthn: webauthn_rs::Webauthn,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,vouch_server=debug".into()),
        )
        .init();

    tracing::info!("Starting vouch server...");

    // Load configuration
    let config = ServerConfig::load()?;
    
    // Connect to database
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&db).await?;

    // Initialize WebAuthn
    let webauthn = webauthn_rs::WebauthnBuilder::new(
        &config.rp_id,
        &config.rp_origin,
    )?
    .rp_name(&config.rp_name)
    .build()?;

    // Create shared state
    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        webauthn,
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(|| async { "ok" }))
        
        // Authentication
        .route("/v1/auth/register/start", post(handlers::auth::register_start))
        .route("/v1/auth/register/complete", post(handlers::auth::register_complete))
        .route("/v1/auth/login/start", get(handlers::auth::login_start))
        .route("/v1/auth/login/complete", post(handlers::auth::login_complete))
        .route("/v1/auth/status", get(handlers::auth::status))
        
        // Credentials
        .route("/v1/credentials/github", post(handlers::credentials::github))
        .route("/v1/credentials/aws", post(handlers::credentials::aws))
        .route("/v1/credentials/ssh", post(handlers::credentials::ssh))
        
        // Delegations
        .route("/v1/delegations", post(handlers::delegations::create))
        .route("/v1/delegations", get(handlers::delegations::list))
        .route("/v1/delegations/:id", get(handlers::delegations::show))
        .route("/v1/delegations/:id", delete(handlers::delegations::revoke))
        
        // WebAuthn ceremony pages (browser-based)
        .route("/auth/register", get(handlers::webauthn::register_page))
        .route("/auth/login", get(handlers::webauthn::login_page))
        
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
