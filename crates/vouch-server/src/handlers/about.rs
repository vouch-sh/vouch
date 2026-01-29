// SPDX-License-Identifier: BUSL-1.1
//! About page handler.

use crate::handlers::common::{AuthContext, get_auth_context};
use crate::{AppState, impl_template_response};
use askama::Template;
use axum::extract::State;
use axum::response::IntoResponse;
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

/// About page template.
#[derive(Template)]
#[template(path = "about.html")]
pub struct AboutTemplate {
    pub org_name: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

impl_template_response!(AboutTemplate);

/// About page.
/// GET /about
pub async fn about_page(State(state): State<Arc<AppState>>, jar: CookieJar) -> impl IntoResponse {
    let auth = get_auth_context(&state, &jar).await;
    AboutTemplate {
        org_name: state.config.get_org_display_name().to_string(),
        auth,
    }
}
