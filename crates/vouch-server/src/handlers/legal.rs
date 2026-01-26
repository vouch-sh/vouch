//! Legal pages handler (privacy policy and terms of service).

use crate::AppState;
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

/// Privacy policy page template.
#[derive(Template)]
#[template(path = "privacy.html")]
pub struct PrivacyTemplate {
    pub org_name: String,
}

impl IntoResponse for PrivacyTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Terms of service page template.
#[derive(Template)]
#[template(path = "terms.html")]
pub struct TermsTemplate {
    pub org_name: String,
}

impl IntoResponse for TermsTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Privacy policy page.
/// GET /privacy
#[allow(clippy::unused_async)]
pub async fn privacy_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    PrivacyTemplate {
        org_name: state.config.get_org_display_name().to_string(),
    }
}

/// Terms of service page.
/// GET /terms
#[allow(clippy::unused_async)]
pub async fn terms_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    TermsTemplate {
        org_name: state.config.get_org_display_name().to_string(),
    }
}
