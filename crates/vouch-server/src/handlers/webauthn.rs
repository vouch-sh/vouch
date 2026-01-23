//! WebAuthn ceremony pages
//!
//! These serve HTML pages that run the WebAuthn ceremony in the browser.
//! The CLI opens these URLs, user completes auth, then CLI polls for completion.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize)]
pub struct AuthQuery {
    code: String,
}

/// Registration page - creates new credential
pub async fn register_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthQuery>,
) -> Result<Html<String>, StatusCode> {
    // TODO: Validate code exists and is pending

    let html = include_str!("../../templates/register.html")
        .replace("{{CODE}}", &query.code)
        .replace("{{RP_ID}}", &state.config.rp_id);

    Ok(Html(html))
}

/// Login page - authenticates with existing credential  
pub async fn login_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthQuery>,
) -> Result<Html<String>, StatusCode> {
    // TODO: Validate code exists and is pending

    let html = include_str!("../../templates/login.html")
        .replace("{{CODE}}", &query.code)
        .replace("{{RP_ID}}", &state.config.rp_id);

    Ok(Html(html))
}
