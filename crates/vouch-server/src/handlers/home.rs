// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Home page handler.
//!
//! The home page shows the landing/enrollment page with
//! "Sign in with identity provider", CLI instructions, and download links.
//! If the user is already authenticated, it shows a "Manage Security Keys"
//! button instead.

use crate::handlers::session::{AuthContext, get_auth_context};
use crate::infra::i18n::PageContext;
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// A single identity provider entry for the sign-in button list.
pub(crate) struct IdpEntry {
    /// Operator-chosen slug.
    pub id: String,
    /// Display name for the button (e.g., "Google", "Microsoft").
    pub display_name: String,
    /// Inline SVG icon markup.
    pub svg_icon: String,
}

/// Build a chooser-friendly entry list from configured upstream IdPs.
///
/// Preserves `VOUCH_IDPS` order. Used by the landing page and by the
/// "select identity provider" chooser shown when more than one IdP is
/// configured.
#[must_use]
pub(crate) fn build_idp_entries(idps: &[crate::services::idp::ConfiguredIdp]) -> Vec<IdpEntry> {
    idps.iter()
        .map(|idp| {
            let brand = idp.brand();
            IdpEntry {
                id: idp.id().to_string(),
                display_name: brand.display_name().to_string(),
                svg_icon: brand.svg_icon().to_string(),
            }
        })
        .collect()
}

/// Home page template.
#[derive(Template)]
#[template(path = "landing.html")]
pub(crate) struct HomeTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub server_url: String,
    pub org_name: String,
    pub has_downloads: bool,
    pub download_macos: Option<String>,
    pub download_linux: Option<String>,
    pub download_windows: Option<String>,
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// All configured identity providers for multi-button sign-in UI.
    pub idp_entries: Vec<IdpEntry>,
}

impl_template_response!(HomeTemplate);

/// Home page showing enrollment instructions.
/// GET /
pub(crate) async fn home_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;

    let has_downloads = state.config().cli_download_macos.is_some()
        || state.config().cli_download_linux.is_some()
        || state.config().cli_download_windows.is_some();

    let idp_entries = build_idp_entries(&state.idps);

    HomeTemplate {
        page: PageContext::current(),
        server_url: state.config().base_url.clone(),
        org_name: state.config().get_org_display_name().to_string(),
        has_downloads,
        download_macos: state.config().cli_download_macos.clone(),
        download_linux: state.config().cli_download_linux.clone(),
        download_windows: state.config().cli_download_windows.clone(),
        auth,
        idp_entries,
    }
}
