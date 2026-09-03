// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth Application Registration handlers.
//!
//! This module implements the self-service portal for developers to register
//! OAuth applications that can integrate with Vouch.

mod api;
mod types;
mod validate;
mod web;

use crate::db;
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Re-export handler functions used by the router.
pub(crate) use types::ApplicationUnauthorizedTemplate;

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

/// Validate that all post-logout redirect URIs are valid URLs with proper schemes.
///
/// Mirrors [`validate_redirect_uris`] rules (https or loopback http) and additionally
/// rejects URIs that carry a fragment component, which would conflict with the
/// redirect appended `state` parameter on the final redirect. Enforces a maximum
/// of [`db::MAX_POST_LOGOUT_REDIRECT_URIS`] entries, matching the RFC 7591 cap.
///
/// Returns `Ok(())` if all URIs are valid, or `Err` with a list of invalid URIs.
pub(crate) fn validate_post_logout_redirect_uris(uris: &[String]) -> Result<(), Vec<String>> {
    if uris.len() > db::MAX_POST_LOGOUT_REDIRECT_URIS {
        return Err(vec![format!(
            "Too many post_logout_redirect_uris: maximum is {}",
            db::MAX_POST_LOGOUT_REDIRECT_URIS
        )]);
    }

    let invalid: Vec<String> = uris
        .iter()
        .filter(|uri| !db::is_valid_post_logout_redirect_uri_str(uri))
        .cloned()
        .collect();

    if invalid.is_empty() {
        Ok(())
    } else {
        Err(invalid)
    }
}

/// Validate every redirect URI for a client of this type.
///
/// Delegates to [`db::validate_redirect_uri`], the single rule shared with
/// dynamic client registration, so the two paths cannot accept different sets.
///
/// Returns `Ok(())` if all URIs are valid, or `Err` listing the invalid ones.
/// The rejection reason is deliberately not folded into these strings: the
/// page states the whole rule (`apps-invalid-redirect-uris`), so a per-URI
/// reason would need a catalog entry per `RedirectUriError` variant to say
/// what the one sentence already says. Dynamic client registration, which
/// answers in JSON, does report the reason.
fn validate_redirect_uris(
    uris: &[String],
    application_type: db::OAuthClientType,
) -> Result<(), Vec<String>> {
    let invalid: Vec<String> = uris
        .iter()
        .filter_map(|uri| {
            db::validate_redirect_uri(uri, application_type)
                .err()
                .map(|_| uri.clone())
        })
        .collect();

    if invalid.is_empty() {
        Ok(())
    } else {
        Err(invalid)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;

    /// A deactivated user whose session has not yet been swept must be turned
    /// away by the web UI, matching `get_resource_auth_context` on the API path.
    #[tokio::test]
    async fn deactivated_user_cookie_is_unauthenticated() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "deactivated-web@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/applications", &[("Cookie", &cookie)]).await;
        assert_eq!(
            resp.status,
            axum::http::StatusCode::OK,
            "active user with a valid cookie must reach the portal"
        );

        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let resp = http_get_full(&app, "/applications", &[("Cookie", &cookie)]).await;
        assert!(
            resp.body.contains("Unauthorized") || resp.status.is_client_error(),
            "deactivated user must be refused even while the session still exists: {}",
            resp.status
        );
    }

    /// Client secrets outlive the session that mints them, so the portal is
    /// closed to a session that never ran a key ceremony.
    #[tokio::test]
    async fn bootstrap_session_cannot_reach_the_applications_portal() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "bootstrap-apps@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                verification: TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/applications", &[("Cookie", &cookie)]).await;
        assert!(
            resp.status.is_redirection(),
            "an unverified session must be sent to assert, got {}",
            resp.status
        );
        assert_eq!(
            resp.headers
                .get("location")
                .expect("redirect location")
                .to_str()
                .expect("ascii location"),
            "/login"
        );

        let resp = crate::test_utils::http_post_form_full(
            &app,
            "/applications/new",
            "name=evil&redirect_uris=https://evil.example.com/cb",
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;
        assert!(
            resp.status.is_redirection(),
            "an unverified session must not register an application, got {}",
            resp.status
        );
    }
}
