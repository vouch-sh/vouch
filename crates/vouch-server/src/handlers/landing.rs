// SPDX-License-Identifier: BUSL-1.1
//! Landing page handler for user discovery.

use crate::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

/// Landing page template.
#[derive(Template)]
#[template(path = "landing.html")]
pub struct LandingTemplate {
    pub server_url: String,
    pub org_name: String,
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
}

impl IntoResponse for LandingTemplate {
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

/// Landing page showing enrollment instructions.
/// GET /
#[allow(clippy::unused_async)]
pub async fn landing_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let has_downloads = state.config.cli_download_macos.is_some()
        || state.config.cli_download_linux.is_some()
        || state.config.cli_download_windows.is_some();

    LandingTemplate {
        server_url: state.config.verification_base_url.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        has_downloads,
        download_macos: state.config.cli_download_macos.clone(),
        download_linux: state.config.cli_download_linux.clone(),
        download_windows: state.config.cli_download_windows.clone(),
    }
}
