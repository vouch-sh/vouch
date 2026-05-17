// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Home page handler.
//!
//! The home page shows the landing/enrollment page with
//! "Sign in with identity provider", CLI instructions, and download links.
//! If the user is already authenticated, it shows a "Manage Security Keys"
//! button instead.

use crate::handlers::HasVersion;
use crate::handlers::session::{AuthContext, get_auth_context};
use crate::services::idp::IdpBrand;
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// A single identity provider entry for the sign-in button list.
pub struct IdpEntry {
    /// Operator-chosen slug or empty string for SAML.
    pub id: String,
    /// Display name for the button (e.g., "Google", "Microsoft").
    pub display_name: String,
    /// Inline SVG icon markup.
    pub svg_icon: String,
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
    /// All configured identity providers for multi-button sign-in UI.
    pub idp_entries: Vec<IdpEntry>,
}

impl_template_response!(HomeTemplate);

/// Home page showing enrollment instructions.
/// GET /
pub async fn home_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;

    let has_downloads = state.config().cli_download_macos.is_some()
        || state.config().cli_download_linux.is_some()
        || state.config().cli_download_windows.is_some();

    let mut idp_entries: Vec<IdpEntry> = state
        .oidc_providers
        .values()
        .map(|p| {
            let brand = IdpBrand::from_issuer(&p.provider.issuer);
            IdpEntry {
                id: p.id.clone(),
                display_name: brand.display_name().to_string(),
                svg_icon: brand.svg_icon().to_string(),
            }
        })
        .collect();

    if let Some(saml) = state.upstream_saml.as_ref() {
        let brand = IdpBrand::from_entity_id(saml.entity_id());
        idp_entries.push(IdpEntry {
            id: String::new(),
            display_name: brand.display_name().to_string(),
            svg_icon: brand.svg_icon().to_string(),
        });
    }

    HomeTemplate {
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
