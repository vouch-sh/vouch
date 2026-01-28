// SPDX-License-Identifier: BUSL-1.1
//! Documentation pages handler.

use crate::AppState;
use crate::impl_template_response;
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

/// Documentation index page template.
#[derive(Template)]
#[template(path = "docs/index.html")]
pub struct DocsIndexTemplate {
    /// Organization name for branding.
    pub org_name: String,
}

impl_template_response!(DocsIndexTemplate);

/// AWS setup documentation page template.
#[derive(Template)]
#[template(path = "docs/aws.html")]
pub struct DocsAwsTemplate {
    /// The OIDC provider URL (verification_base_url).
    pub provider_url: String,
    /// The RP ID (domain) for the OIDC provider.
    pub rp_id: String,
    /// Organization name for branding.
    pub org_name: String,
}

impl_template_response!(DocsAwsTemplate);

/// GitHub setup documentation page template.
#[derive(Template)]
#[template(path = "docs/github.html")]
pub struct DocsGithubTemplate {
    /// Organization name for branding.
    pub org_name: String,
    /// Whether the GitHub App is configured on this server.
    pub github_configured: bool,
    /// Server URL for the connect link.
    pub server_url: String,
}

impl_template_response!(DocsGithubTemplate);

/// Documentation index page.
/// GET /docs
#[allow(clippy::unused_async)]
pub async fn docs_index_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    DocsIndexTemplate {
        org_name: state.config.get_org_display_name().to_string(),
    }
}

/// AWS setup documentation page.
/// GET /docs/aws
#[allow(clippy::unused_async)]
pub async fn aws_setup_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    DocsAwsTemplate {
        provider_url: state.config.verification_base_url.clone(),
        rp_id: state.config.rp_id.clone(),
        org_name: state.config.get_org_display_name().to_string(),
    }
}

/// GitHub setup documentation page.
/// GET /docs/github
#[allow(clippy::unused_async)]
pub async fn github_setup_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    DocsGithubTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        github_configured: state.github_app.is_some(),
        server_url: state.config.verification_base_url.clone(),
    }
}
