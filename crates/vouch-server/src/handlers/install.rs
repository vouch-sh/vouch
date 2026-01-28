// SPDX-License-Identifier: BUSL-1.1
//! Install page handler.

use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

/// Install page template.
#[derive(Template)]
#[template(path = "install.html")]
pub struct InstallTemplate {
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
}

impl_template_response!(InstallTemplate);

/// Install page - CLI installation and enrollment instructions.
/// GET /install
#[allow(clippy::unused_async)]
pub async fn install_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let has_downloads = state.config.cli_download_macos.is_some()
        || state.config.cli_download_linux.is_some()
        || state.config.cli_download_windows.is_some();

    InstallTemplate {
        has_downloads,
        download_macos: state.config.cli_download_macos.clone(),
        download_linux: state.config.cli_download_linux.clone(),
        download_windows: state.config.cli_download_windows.clone(),
    }
}
