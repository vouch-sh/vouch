// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Home page handler.
//!
//! The home page shows the landing/enrollment page with
//! "Sign in with identity provider", CLI instructions, and download links.
//! If the user is already authenticated, it shows a "Manage Security Keys"
//! button instead.

use crate::handlers::HasVersion;
use crate::handlers::session::{AuthContext, get_auth_context};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// One entry in the landing-page IdP picker list.
pub struct IdpListEntry {
    pub display_name: String,
    pub svg_icon: String,
    pub start_url: String,
}

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
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Configured upstream IdPs; rendered as one button per entry.
    /// Empty when no upstream IdP is configured.
    pub idps: Vec<IdpListEntry>,
}

impl_template_response!(HomeTemplate);

/// Home page showing enrollment instructions.
/// GET /
pub async fn home_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;

    let has_downloads = state.config().cli_download_macos.is_some()
        || state.config().cli_download_linux.is_some()
        || state.config().cli_download_windows.is_some();

    let idps: Vec<IdpListEntry> = state
        .idps()
        .iter()
        .map(|idp| IdpListEntry {
            display_name: idp.display_name.clone(),
            svg_icon: idp.svg_icon.to_string(),
            start_url: format!("/enroll/start/{}", idp.slug),
        })
        .collect();

    HomeTemplate {
        server_url: state.config().base_url.clone(),
        org_name: state.config().get_org_display_name().to_string(),
        has_downloads,
        download_macos: state.config().cli_download_macos.clone(),
        download_linux: state.config().cli_download_linux.clone(),
        download_windows: state.config().cli_download_windows.clone(),
        auth,
        idps,
    }
}
