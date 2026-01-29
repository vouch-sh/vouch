// SPDX-License-Identifier: BUSL-1.1
//! Legal pages handler (privacy policy and terms of service).

use crate::handlers::common::{AuthContext, get_auth_context};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// Privacy policy page template.
#[derive(Template)]
#[template(path = "privacy.html")]
pub struct PrivacyTemplate {
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(PrivacyTemplate);

/// Terms of service page template.
#[derive(Template)]
#[template(path = "terms.html")]
pub struct TermsTemplate {
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(TermsTemplate);

/// Privacy policy page.
/// GET /privacy
pub async fn privacy_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    PrivacyTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}

/// Terms of service page.
/// GET /terms
pub async fn terms_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    TermsTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}
