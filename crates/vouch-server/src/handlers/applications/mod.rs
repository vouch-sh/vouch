// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth Application Registration handlers.
//!
//! This module implements the self-service portal for developers to register
//! OAuth applications that can integrate with Vouch.

mod api;
mod types;
mod validate;
mod web;

use crate::AppState;
use crate::db;
use aws_lc_rs::rand as aws_rand;
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::extract_session_from_cookie;
use super::session::AuthContext;

// Re-export handler functions used by the router.
pub(crate) use api::{
    add_secret_api, create_application_api, delete_application_api, delete_secret_api,
    get_application_api, list_applications_api, list_secrets_api, revoke_tokens_api,
    update_application_api,
};
pub(crate) use web::{
    add_secret_form, create_application_form, create_application_page, delete_application_form,
    delete_secret_form, detail_application_page, list_applications_page, update_application_form,
};

// ============================================================================
// Constants
// ============================================================================

/// Length of generated client secrets in bytes.
const SECRET_LENGTH: usize = 32;

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a secure random client secret.
///
/// # Panics
/// Panics if the system RNG fails.
#[expect(
    clippy::expect_used,
    reason = ".expect on aws_rand::fill is acceptable: RNG failure is fatal at startup"
)]
pub(crate) fn generate_client_secret() -> String {
    let mut bytes = [0u8; SECRET_LENGTH];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    format!("vouch_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Extract auth context from cookie for web UI.
///
/// Returns `Some(AuthContext)` if a valid session exists, `None` otherwise.
async fn extract_auth_from_cookie(state: &AppState, jar: &CookieJar) -> Option<AuthContext> {
    // Use shared cookie extraction
    let session = extract_session_from_cookie(state, jar).await.ok()?;

    // Get user info
    let user = db::get_user_by_id(&state.store, &session.sub)
        .await
        .ok()??;

    Some(AuthContext {
        authenticated: true,
        user_id: Some(session.sub),
        user_email: Some(user.email),
        has_org: user.org_id.is_some(),
        is_org_admin: user.is_org_admin,
    })
}

/// Parse redirect URIs from form input (newline or comma separated).
fn parse_redirect_uris(input: &str) -> Vec<String> {
    input
        .lines()
        .flat_map(|line| line.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse resource URIs from form input (newline or comma separated).
/// Returns an empty vec if the input is `None` or empty.
fn parse_resource_uris(input: Option<&str>) -> Vec<String> {
    match input {
        Some(s) if !s.trim().is_empty() => s
            .lines()
            .flat_map(|line| line.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Validate that all redirect URIs are valid URLs with proper schemes.
///
/// Per RFC 8252 Section 7.3 and RFC 9700 Section 4.1.3:
/// - `http://` is only allowed for loopback addresses (`localhost`, `127.0.0.1`, `[::1]`)
/// - `https://` is required for all other hosts
///
/// Returns `Ok(())` if all URIs are valid, or `Err` with a list of invalid URIs.
fn validate_redirect_uris(uris: &[String]) -> Result<(), Vec<String>> {
    let invalid: Vec<String> = uris
        .iter()
        .filter(|uri| {
            match url::Url::parse(uri) {
                Ok(parsed) => {
                    match parsed.scheme() {
                        "https" => false, // HTTPS is always valid
                        "http" => {
                            // RFC 8252 Section 7.3: HTTP only for loopback
                            let host = parsed.host_str().unwrap_or("");
                            !matches!(host, "localhost" | "127.0.0.1" | "[::1]")
                        }
                        _ => true, // Other schemes are not allowed
                    }
                }
                Err(_) => true,
            }
        })
        .cloned()
        .collect();

    if invalid.is_empty() {
        Ok(())
    } else {
        Err(invalid)
    }
}
