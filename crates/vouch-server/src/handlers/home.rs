// SPDX-License-Identifier: BUSL-1.1
//! Home page handler.
//!
//! The home page shows the landing/enrollment page with
//! "Sign in with Google", CLI instructions, and download links.

use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

/// Home page template.
#[derive(Template)]
#[template(path = "landing.html")]
pub struct HomeTemplate {
    pub server_url: String,
    pub org_name: String,
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
}

impl_template_response!(HomeTemplate);

/// Home page showing enrollment instructions.
/// GET /
#[allow(clippy::unused_async)]
pub async fn home_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let has_downloads = state.config.cli_download_macos.is_some()
        || state.config.cli_download_linux.is_some()
        || state.config.cli_download_windows.is_some();

    HomeTemplate {
        server_url: state.config.verification_base_url.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        has_downloads,
        download_macos: state.config.cli_download_macos.clone(),
        download_linux: state.config.cli_download_linux.clone(),
        download_windows: state.config.cli_download_windows.clone(),
    }
}
