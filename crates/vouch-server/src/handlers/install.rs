// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Install page handler.

use crate::handlers::session::{AuthContext, get_auth_context};
use crate::infra::i18n::PageContext;
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// Install page template.
#[derive(Template)]
#[template(path = "install.html")]
pub(crate) struct InstallTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
    /// Server URL for enrollment commands.
    pub server_url: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(InstallTemplate);

/// Install page - CLI installation and enrollment instructions.
/// GET /install
pub(crate) async fn install_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;

    let has_downloads = state.config().cli_download_macos.is_some()
        || state.config().cli_download_linux.is_some()
        || state.config().cli_download_windows.is_some();

    InstallTemplate {
        page: PageContext::current(),
        has_downloads,
        download_macos: state.config().cli_download_macos.clone(),
        download_linux: state.config().cli_download_linux.clone(),
        download_windows: state.config().cli_download_windows.clone(),
        server_url: state.config().base_url.clone(),
        auth,
    }
}
