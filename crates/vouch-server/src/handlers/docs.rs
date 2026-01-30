// SPDX-License-Identifier: BUSL-1.1
//! Documentation pages handler.

use crate::AppState;
use crate::handlers::common::{AuthContext, get_auth_context};
use crate::impl_template_response;
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// Documentation index page template.
#[derive(Template)]
#[template(path = "docs/index.html")]
pub struct DocsIndexTemplate {
    /// Organization name for branding.
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
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
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsAwsTemplate);

/// GCP setup documentation page template.
#[derive(Template)]
#[template(path = "docs/gcp.html")]
pub struct DocsGcpTemplate {
    /// The OIDC provider URL (verification_base_url).
    pub provider_url: String,
    /// The RP ID (domain) for the OIDC provider.
    pub rp_id: String,
    /// Organization name for branding.
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsGcpTemplate);

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
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsGithubTemplate);

/// Getting Started documentation page template.
#[derive(Template)]
#[template(path = "docs/getting-started.html")]
pub struct DocsGettingStartedTemplate {
    /// Organization name for branding.
    pub org_name: String,
    /// Server URL for enrollment commands.
    pub server_url: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsGettingStartedTemplate);

/// Application Integration documentation page template.
#[derive(Template)]
#[template(path = "docs/applications.html")]
pub struct DocsApplicationsTemplate {
    /// The OIDC provider URL (verification_base_url).
    pub provider_url: String,
    /// Organization name for branding.
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsApplicationsTemplate);

/// SSH Certificates documentation page template.
#[derive(Template)]
#[template(path = "docs/ssh.html")]
pub struct DocsSshTemplate {
    /// The OIDC provider URL (verification_base_url).
    pub provider_url: String,
    /// Organization name for branding.
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsSshTemplate);

/// Kubernetes setup documentation page template.
#[derive(Template)]
#[template(path = "docs/kubernetes.html")]
pub struct DocsKubernetesTemplate {
    /// The OIDC provider URL (verification_base_url).
    pub provider_url: String,
    /// Organization name for branding.
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(DocsKubernetesTemplate);

/// Documentation index page.
/// GET /docs
pub async fn docs_index_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsIndexTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// AWS setup documentation page.
/// GET /docs/aws
pub async fn aws_setup_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsAwsTemplate {
        provider_url: state.config.verification_base_url.clone(),
        rp_id: state.config.rp_id.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// GCP setup documentation page.
/// GET /docs/gcp
pub async fn gcp_setup_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsGcpTemplate {
        provider_url: state.config.verification_base_url.clone(),
        rp_id: state.config.rp_id.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// GitHub setup documentation page.
/// GET /docs/github
pub async fn github_setup_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsGithubTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        github_configured: state.github_app.is_some(),
        server_url: state.config.verification_base_url.clone(),
        auth,
    }
}

/// Getting Started documentation page.
/// GET /docs/getting-started
pub async fn getting_started_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsGettingStartedTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        server_url: state.config.verification_base_url.clone(),
        auth,
    }
}

/// Application Integration documentation page.
/// GET /docs/applications
pub async fn applications_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsApplicationsTemplate {
        provider_url: state.config.verification_base_url.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// SSH Certificates documentation page.
/// GET /docs/ssh
pub async fn ssh_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsSshTemplate {
        provider_url: state.config.verification_base_url.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// Kubernetes setup documentation page.
/// GET /docs/kubernetes
pub async fn kubernetes_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    DocsKubernetesTemplate {
        provider_url: state.config.verification_base_url.clone(),
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}
