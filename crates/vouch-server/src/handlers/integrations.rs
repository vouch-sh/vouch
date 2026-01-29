// SPDX-License-Identifier: BUSL-1.1
//! Integrations page handler.
//!
//! Shows available integrations and their connection status:
//! - GitHub (org-wide, requires org membership)
//! - AWS (per-user, CLI setup)
//! - SSH (per-user, CLI setup)
//! - Kubernetes (coming soon)

use crate::db;
use crate::handlers::common::{AuthContext, get_auth_context};
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
pub struct IntegrationsTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Whether the server has GitHub App configured.
    pub github_configured: bool,
    /// Connected GitHub accounts (for org members).
    pub github_accounts: Vec<String>,
}

impl_template_response!(IntegrationsTemplate);

// ============================================================================
// Handlers
// ============================================================================

/// GET /integrations - Show integrations page.
pub async fn integrations_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let auth = get_auth_context(&state, &jar).await;

    // Redirect unauthenticated users to enrollment
    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }

    // Check if GitHub App is configured on the server
    let github_configured = state.github_app.is_some();

    // Get connected GitHub accounts if user has an org
    let github_accounts = if auth.has_org {
        // We need to get the user's org_id to fetch installations
        if let Ok(session) =
            crate::handlers::common::extract_session_from_cookie(&state, &jar).await
        {
            if let Ok(Some(user)) = db::get_user_by_id(&state.db, &session.claims.sub).await {
                if let Some(org_id) = &user.org_id {
                    db::get_github_installations_by_org(&state.db, org_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|i| i.github_account_login)
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    IntegrationsTemplate {
        auth,
        github_configured,
        github_accounts,
    }
    .into_response()
}
