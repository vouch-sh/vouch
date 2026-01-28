// SPDX-License-Identifier: BUSL-1.1
//! Home page handler with smart routing based on configuration.
//!
//! This module provides the main landing page for Vouch that adapts based on
//! whether OIDC is configured:
//! - Not configured: Shows admin setup wizard
//! - Configured: Shows org enrollment page (delegates to landing.rs)

use crate::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

/// Home page template (two-persona selection).
#[derive(Template)]
#[template(path = "home.html")]
pub struct HomeTemplate;

impl IntoResponse for HomeTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Admin setup page template.
#[derive(Template)]
#[template(path = "admin_setup.html")]
pub struct AdminSetupTemplate {
    pub server_url: String,
}

impl IntoResponse for AdminSetupTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Developer setup page template.
#[derive(Template)]
#[template(path = "developer_setup.html")]
pub struct DeveloperSetupTemplate {
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
}

impl IntoResponse for DeveloperSetupTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Home page with smart routing.
/// GET /
///
/// If OIDC is not configured, shows the two-persona selection page (admin vs developer).
/// If OIDC is configured, shows the org enrollment page.
#[allow(clippy::unused_async)]
pub async fn home_page(State(state): State<Arc<AppState>>) -> Response {
    if state.config.oidc_configured() {
        // OIDC configured - show org enrollment page (delegate to landing)
        super::landing::landing_page(State(state))
            .await
            .into_response()
    } else {
        // OIDC not configured - show two-persona selection page
        HomeTemplate.into_response()
    }
}

/// Admin setup page - step-by-step wizard for configuring Vouch.
/// GET /admin-setup
#[allow(clippy::unused_async)]
pub async fn admin_setup_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    AdminSetupTemplate {
        server_url: state.config.verification_base_url.clone(),
    }
}

/// Developer setup page - CLI installation and enrollment instructions.
/// GET /developer-setup
#[allow(clippy::unused_async)]
pub async fn developer_setup_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let has_downloads = state.config.cli_download_macos.is_some()
        || state.config.cli_download_linux.is_some()
        || state.config.cli_download_windows.is_some();

    DeveloperSetupTemplate {
        has_downloads,
        download_macos: state.config.cli_download_macos.clone(),
        download_linux: state.config.cli_download_linux.clone(),
        download_windows: state.config.cli_download_windows.clone(),
    }
}
