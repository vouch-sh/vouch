// SPDX-License-Identifier: BUSL-1.1
//! Home page handler.
//!
//! The home page always shows the landing/enrollment page with
//! "Sign in with Google", CLI instructions, and download links.

use crate::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

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

/// Home page — always shows the landing/enrollment page.
/// GET /
#[allow(clippy::unused_async)]
pub async fn home_page(State(state): State<Arc<AppState>>) -> Response {
    super::landing::landing_page(State(state))
        .await
        .into_response()
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
