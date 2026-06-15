// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integrations page handler.
//!
//! Shows available integrations and their connection status:
//! - GitHub (org-wide, requires org membership)
//! - AWS (org-wide config, per-user setup)
//! - SSH (per-user, CLI setup)
//! - EKS (via AWS IAM and EKS Access Entries)

use crate::db;
use crate::handlers::session::{
    AuthContext, extract_session_from_cookie, get_resource_auth_context,
};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

// ============================================================================
// Templates
// ============================================================================

/// Integrations page template.
#[derive(Template)]
#[template(path = "integrations.html")]
pub(crate) struct IntegrationsTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Whether the server has GitHub App configured.
    pub github_configured: bool,
    /// Connected GitHub accounts (for org members).
    pub github_accounts: Vec<String>,
    /// SSH CA public key in OpenSSH format (None if SSH CA not configured).
    pub ssh_ca_public_key: Option<String>,
}

impl_template_response!(IntegrationsTemplate);

// ============================================================================
// Handlers
// ============================================================================

/// GET /integrations - Show integrations page.
pub(crate) async fn integrations_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    // Redirect unauthenticated users to enrollment
    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }

    // Check if GitHub App is configured on the server
    let github_configured = state.github_app.is_some();

    // Get SSH CA public key (None means SSH CA is not configured)
    let ssh_ca_public_key = state.ssh_ca.as_ref().and_then(|ca| ca.public_key().ok());

    // Fetch session + user once for org-scoped lookups
    let org_context = if auth.has_org {
        match extract_session_from_cookie(&state, &jar).await {
            Ok(session) => match db::get_user_by_id(&state.store, &session.sub).await {
                Ok(Some(user)) => user.org_id.clone().map(|org_id| (user, org_id)),
                Ok(None) => {
                    tracing::error!("Session user not found: {}", session.sub);
                    None
                }
                Err(e) => {
                    tracing::error!("Failed to load user for integrations page: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::error!("Failed to extract session for integrations page: {e}");
                None
            }
        }
    } else {
        None
    };

    // Get connected GitHub accounts if user has an org
    let github_accounts = if let Some((ref _user, ref org_id)) = org_context {
        match db::get_github_installations_by_org(&state.store, org_id).await {
            Ok(installations) => installations
                .into_iter()
                .map(|i| i.github_account_login)
                .collect(),
            Err(e) => {
                tracing::error!("Failed to get GitHub installations for org {org_id}: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    IntegrationsTemplate {
        auth,
        github_configured,
        github_accounts,
        ssh_ca_public_key,
    }
    .into_response()
}
