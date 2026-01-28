// SPDX-License-Identifier: BUSL-1.1
//! About page handler.

use crate::{AppState, impl_template_response};
use askama::Template;
use axum::extract::State;
use axum::response::IntoResponse;
use std::sync::Arc;

/// About page template.
#[derive(Template)]
#[template(path = "about.html")]
pub struct AboutTemplate {
    pub org_name: String,
}

impl_template_response!(AboutTemplate);

/// About page.
/// GET /about
#[allow(clippy::unused_async)]
pub async fn about_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    AboutTemplate {
        org_name: state.config.get_org_display_name().to_string(),
    }
}
