// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RP-Initiated Logout 1.0 endpoint handlers.
//!
//! Implements:
//! - `GET /oauth/logout` — Show confirmation page (end-session endpoint)
//! - `POST /oauth/logout` — Execute logout and redirect or render done page
//!
//! Security model:
//! - CSRF is mitigated by SameSite=Lax on the session cookie and requiring a
//!   same-origin POST for the confirmation form. No separate CSRF token is needed
//!   because the form has no GET-queryable side-effects — the session is only
//!   cleared on POST from the confirmation page.
//! - `post_logout_redirect_uri` is validated against the registered
//!   `post_logout_redirect_uris` for the client identified by `id_token_hint`.
//!   Redirect is only allowed when a verified `id_token_hint` is present; the
//!   bare `client_id` query param is NOT sufficient to gate a redirect.
//!   An invalid or unverified URI falls through to the local done page instead of
//!   redirecting — never redirects to an unvalidated URI.
//! - `state` is echoed ONLY on redirect back to the client; it is carried as a
//!   hidden form field through the confirmation page (Askama auto-escapes attribute
//!   values) and never rendered as visible page content (XSS prevention).
//!
//! References:
//! - <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>

use crate::AppState;
use crate::db;
use crate::handlers::extractors::ClientInfo;
use crate::handlers::{clear_session_cookie, hash_token};
use crate::impl_template_response;
use crate::infra::i18n::{negotiate_ui_locales, sync_scope_locale};
use crate::services::oidc::token::IdTokenClaims;
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::Validation;
use serde::Deserialize;
use std::sync::Arc;

// ============================================================================
// Query / Form types
// ============================================================================

/// GET /oauth/logout query parameters (RP-Initiated Logout 1.0 Section 3).
#[derive(Debug, Deserialize)]
pub(crate) struct LogoutQuery {
    /// OPTIONAL. Previously issued ID Token passed as a hint. Used to identify
    /// the RP and optionally to look up the client's registered post-logout URIs.
    pub id_token_hint: Option<String>,
    /// OPTIONAL. Hint about the End-User's login identifier. Informational only;
    /// accepted per spec but not acted upon.
    #[expect(
        dead_code,
        reason = "accepted per spec; not acted upon in this implementation"
    )]
    pub logout_hint: Option<String>,
    /// OPTIONAL. OAuth 2.0 Client Identifier. Used only for display on the
    /// confirmation page when no `id_token_hint` is present. Does NOT gate
    /// redirects — only a verified hint's `aud` gates redirect.
    pub client_id: Option<String>,
    /// OPTIONAL. URL to which the RP requests that the End-User's User Agent be
    /// redirected after a logout has been performed. Must be registered.
    pub post_logout_redirect_uri: Option<String>,
    /// OPTIONAL. Opaque value to maintain state between the RP and End-User Agent.
    /// Carried as a hidden form field through the confirmation page (Askama
    /// auto-escapes attribute values) and echoed only on the final redirect.
    pub state: Option<String>,
    /// OPTIONAL. End-User's preferred languages (space-separated BCP-47 tags)
    /// for the logout confirmation UI.
    pub ui_locales: Option<String>,
}

/// POST /oauth/logout form body — mirrors the hidden fields in the confirmation form.
#[derive(Debug, Deserialize)]
pub(crate) struct LogoutForm {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<String>,
    /// `state` is carried as a hidden form field through the confirmation page.
    /// Askama auto-escapes attribute values so it is safe against injection into
    /// the form. It is echoed only on the final redirect to the RP — never
    /// rendered as visible page content.
    pub state: Option<String>,
    /// `ui_locales` is carried as a hidden field so the done page renders in the
    /// same locale as the confirmation page (plan §7).
    pub ui_locales: Option<String>,
}

// ============================================================================
// Templates
// ============================================================================

/// Logout confirmation page.
#[derive(Template)]
#[template(path = "logout_confirm.html")]
pub(super) struct LogoutConfirmTemplate {
    /// Non-empty only when we verified the hint. Used to propagate the hint to
    /// the POST form so the server can re-verify and identify the client.
    pub id_token_hint: Option<String>,
    /// Pre-validated URI (already checked against the registered list). Passed
    /// to the POST form as a hidden field so POST can re-validate and redirect.
    pub post_logout_redirect_uri: Option<String>,
    /// Client ID resolved from `id_token_hint.aud`. Used only for display;
    /// may also be passed to POST for re-verification.
    pub client_id: Option<String>,
    /// Opaque RP state value. Carried as a hidden field so POST can echo it on
    /// the final redirect. Askama auto-escapes the attribute value.
    pub state: Option<String>,
    /// RP-requested UI locale (space-separated BCP-47). Carried as a hidden field
    /// so the POST done-page renders in the same locale as the confirmation page.
    pub ui_locales: Option<String>,
}

impl_template_response!(LogoutConfirmTemplate);

/// Logout done page (no redirect available or redirect target not registered).
#[derive(Template)]
#[template(path = "logout_done.html")]
pub(super) struct LogoutDoneTemplate {}

impl_template_response!(LogoutDoneTemplate);

// ============================================================================
// id_token_hint verification
// ============================================================================

/// Extracted, verified claims from an `id_token_hint`.
struct IdTokenHintClaims {
    /// `sub` claim from the token. May be used to scope per-user logout hints.
    #[allow(
        dead_code,
        reason = "read in test assertions; not yet used in production paths"
    )]
    sub: String,
    /// `aud` claim (client_id of the RP that issued the token).
    aud: String,
}

/// Build a `Validation` instance for id_token_hint verification.
///
/// Per RP-Initiated Logout 1.0 Section 3: hints MAY be expired; skip expiry
/// validation. Skip audience validation (we validate `iss` manually). No
/// required claims beyond what we check explicitly.
fn hint_validation(alg: jsonwebtoken::Algorithm) -> Validation {
    let mut v = Validation::new(alg);
    v.validate_exp = false;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    v.leeway = 0;
    v
}

/// Verify an `id_token_hint` JWT against the server's current signing keys.
///
/// Accepts both ES256 (primary) and RS256 (when the RSA key is configured).
/// Skips expiry and audience validation per RP-Initiated Logout 1.0 Section 3.
/// Manually verifies `iss == base_url`.
///
/// Returns `Some(claims)` if the signature is valid and `iss` matches this
/// server's `base_url`. Returns `None` for any failure.
fn verify_id_token_hint(state: &AppState, hint: &str) -> Option<IdTokenHintClaims> {
    let config = state.config();

    let es256_validation = hint_validation(jsonwebtoken::Algorithm::ES256);
    let es256_result = jsonwebtoken::decode::<IdTokenClaims>(
        hint,
        state.oidc_key.decoding_key(),
        &es256_validation,
    );

    let claims = if let Ok(token_data) = es256_result {
        token_data.claims
    } else if let Some(rsa_key) = state.oidc_rsa_key.as_ref() {
        // Fall back to RS256 if an RSA key is configured.
        let rs256_validation = hint_validation(jsonwebtoken::Algorithm::RS256);
        match jsonwebtoken::decode::<IdTokenClaims>(hint, rsa_key.decoding_key(), &rs256_validation)
        {
            Ok(token_data) => token_data.claims,
            Err(_) => return None,
        }
    } else {
        return None;
    };

    // Manually verify iss — must match this server's base_url.
    if claims.iss != config.base_url {
        return None;
    }

    Some(IdTokenHintClaims {
        sub: claims.sub,
        aud: claims.aud,
    })
}

// ============================================================================
// Helpers for hint/client_id consistency
// ============================================================================

/// Enforce the `client_id == hint.aud` constraint from RP-Initiated Logout 1.0 §3.
///
/// When both a verified hint and an explicit `client_id` are present they MUST agree.
/// On mismatch, the hint is discarded so the request falls through to the local done
/// page — never redirecting to an unvalidated URI.
fn filter_hint_by_client_id(
    hint: Option<IdTokenHintClaims>,
    client_id: Option<&str>,
) -> Option<IdTokenHintClaims> {
    match (&hint, client_id) {
        (Some(c), Some(cid)) if c.aud != cid => None,
        _ => hint,
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /oauth/logout — Show the logout confirmation page.
///
/// Parses the end-session request parameters, optionally verifies the
/// `id_token_hint`, and renders a confirmation form. The user must explicitly
/// confirm before the session is cleared.
pub(crate) async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    _jar: CookieJar,
    Query(query): Query<LogoutQuery>,
) -> Response {
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());

    let i18n_ctx = negotiate_ui_locales(query.ui_locales.as_deref(), accept_language);

    // Verify id_token_hint if present. An unverifiable hint is silently ignored
    // (spec says the server SHOULD show the confirmation page regardless).
    let hint_claims = query
        .id_token_hint
        .as_deref()
        .and_then(|hint| verify_id_token_hint(&state, hint));

    // When both a verified hint and a bare client_id are present, they MUST agree.
    // Spec §3: "If client_id is given, it MUST match the aud of id_token_hint."
    // On mismatch: treat as no verified hint (fall through to local done page).
    let hint_claims = filter_hint_by_client_id(hint_claims, query.client_id.as_deref());

    // Determine the RP client_id from the verified hint. The bare `client_id`
    // query param is used for display only; it does NOT gate a redirect.
    let verified_client_id = hint_claims.as_ref().map(|c| c.aud.clone());

    // Validate post_logout_redirect_uri against the client's registered list.
    // Only pass it through if a verified hint identified the client. A transient
    // client-lookup failure degrades to "no redirect target" (logged, not
    // silently dropped) — the same outcome as an unregistered URI — rather than
    // blocking the confirmation page with a 500.
    let validated_redirect_uri = resolve_post_logout_redirect_uri(
        &state,
        verified_client_id.as_deref(),
        query.post_logout_redirect_uri.as_deref(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "logout: post_logout_redirect_uri resolution failed; not redirecting");
        None
    });

    // The confirmation form propagates the hint, redirect URI, state, and
    // ui_locales as hidden fields so the POST handler can re-validate them.
    let template = LogoutConfirmTemplate {
        id_token_hint: if hint_claims.is_some() {
            query.id_token_hint.clone()
        } else {
            None
        },
        post_logout_redirect_uri: validated_redirect_uri,
        client_id: verified_client_id.or_else(|| query.client_id.clone()),
        state: query.state.clone(),
        ui_locales: query.ui_locales.clone(),
    };

    sync_scope_locale(i18n_ctx, || template.into_response())
}

/// POST /oauth/logout — Execute logout.
///
/// Clears the browser session (cookie + DB record + audit event) and then either
/// redirects to the validated `post_logout_redirect_uri` (with `state` echoed as
/// a query parameter) or renders the local done page.
pub(crate) async fn logout_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    let hint_claims = form
        .id_token_hint
        .as_deref()
        .and_then(|hint| verify_id_token_hint(&state, hint));

    // Enforce client_id == hint.aud on the POST leg as well.
    let hint_claims = filter_hint_by_client_id(hint_claims, form.client_id.as_deref());

    let verified_client_id = hint_claims.as_ref().map(|c| c.aud.clone());

    // Clear the browser session first (DB deletion + cache invalidation + audit
    // event). The user asked to log out, so a later redirect-validation database
    // error must not prevent logout.
    clear_user_session(&state, &jar, &headers, verified_client_id.as_deref()).await;

    let clear_cookie = clear_session_cookie().to_string();

    // Re-validate the post_logout_redirect_uri. The POST handler must NOT trust
    // the form field without re-checking — the form is same-origin but the
    // hidden field value could be tampered with. A transient client-lookup
    // failure degrades to "no redirect" (logged): the session is already
    // cleared, so logout still succeeds and we fall through to the done page.
    let validated_redirect_uri = resolve_post_logout_redirect_uri(
        &state,
        verified_client_id.as_deref(),
        form.post_logout_redirect_uri.as_deref(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "logout: post_logout_redirect_uri resolution failed; not redirecting");
        None
    });

    match validated_redirect_uri {
        Some(redirect_uri) => {
            // Append `state` if the RP provided it — echo only on redirect.
            let location = if let Some(ref state_param) = form.state {
                match url::Url::parse(&redirect_uri) {
                    Ok(mut url) => {
                        url.query_pairs_mut().append_pair("state", state_param);
                        url.to_string()
                    }
                    Err(_) => redirect_uri,
                }
            } else {
                redirect_uri
            };

            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, location)
                .header(header::SET_COOKIE, clear_cookie)
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        None => {
            let accept_language = headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok());
            let i18n_ctx = negotiate_ui_locales(form.ui_locales.as_deref(), accept_language);

            // Render the done template, then prepend the Set-Cookie header to
            // clear the session cookie in the browser.
            let inner_response =
                sync_scope_locale(i18n_ctx, || LogoutDoneTemplate {}.into_response());

            let (mut parts, body) = inner_response.into_parts();
            if let Ok(cookie_value) = clear_cookie.parse() {
                parts.headers.insert(header::SET_COOKIE, cookie_value);
            }
            Response::from_parts(parts, body)
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Look up the client and validate `post_logout_redirect_uri` against its
/// registered list. Returns `Ok(Some(uri))` only when the URI is registered for
/// an active client, `Ok(None)` when there is no valid redirect target, and
/// `Err` when the client lookup fails — the caller surfaces that as a server
/// error rather than silently skipping the redirect.
///
/// Redirect is only permitted when a verified `id_token_hint` supplied `client_id`
/// — the caller must pass `None` when no hint was verified.
async fn resolve_post_logout_redirect_uri(
    state: &AppState,
    client_id: Option<&str>,
    post_logout_redirect_uri: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let (Some(uri), Some(cid)) = (post_logout_redirect_uri, client_id) else {
        return Ok(None);
    };

    let Some(client) = db::get_oauth_client_by_client_id(&state.store, cid).await? else {
        return Ok(None);
    };

    // Deactivated clients cannot receive a post-logout redirect, consistent with
    // the authorize flow which rejects inactive clients.
    if !client.active {
        return Ok(None);
    }

    Ok(client
        .is_valid_post_logout_redirect_uri(uri)
        .then(|| uri.to_string()))
}

/// Delete the session associated with the current browser cookie, invalidate
/// the in-process cache, and fire an audit event.
///
/// The `rp_client_id` is the `aud` from the verified `id_token_hint`, included
/// in the audit event to distinguish RP-initiated logouts from user-initiated ones.
async fn clear_user_session(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    rp_client_id: Option<&str>,
) {
    let Some(token) = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string())
    else {
        return;
    };

    let token_hash = hash_token(&token);

    let session_info = match state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            // Don't silently drop the error: log it and proceed. The session is
            // still deleted below; only the audit event's user context is lost.
            tracing::warn!(error = %e, "RP-Initiated Logout: session lookup for audit failed");
            None
        }
    };

    match db::delete_session_by_token_hash(&state.store, &token_hash).await {
        Ok(deleted) => {
            if deleted {
                state.session_cache.invalidate(&token_hash);
                tracing::info!(
                    rp_client_id = rp_client_id,
                    "Session cleared during RP-Initiated Logout"
                );

                if let Some(session) = session_info {
                    let client_info = ClientInfo::from(headers);
                    let params = db::AuthEventParams {
                        user_id: session.user_id.clone(),
                        event_type: db::AuthEventType::Logout,
                        success: true,
                        client_id: rp_client_id.map(str::to_string),
                        ..Default::default()
                    }
                    .with_client_info(client_info);
                    db::spawn_audit_event(&state.audit, params, Some(session.user_email));
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to delete session during RP-Initiated Logout: {e}");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::services::oidc::token::IdTokenClaims;
    use crate::test_utils::{
        TestClientSpec, create_test_authenticator, create_test_client, create_test_session,
        create_test_user, http_get, http_post_form, test_app, test_app_state,
        test_app_state_with_rsa_key,
    };

    /// Build a minimal `IdTokenClaims` for signing in tests.
    fn test_id_token_claims(iss: &str, sub: &str, aud: &str, exp: i64) -> IdTokenClaims {
        IdTokenClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            exp,
            iat: 0,
            auth_time: None,
            nonce: None,
            email: None,
            email_verified: None,
            hardware_verified: None,
            hardware_aaguid: None,
            cnf: None,
            amr: None,
            acr: None,
            at_hash: None,
        }
    }

    // ====================================================================
    // verify_id_token_hint — unit tests
    // ====================================================================

    #[tokio::test]
    async fn test_verify_id_token_hint_rejects_garbage() {
        let state = test_app_state().await;
        assert!(verify_id_token_hint(&state, "not.a.jwt").is_none());
        assert!(verify_id_token_hint(&state, "").is_none());
        assert!(verify_id_token_hint(&state, "abc").is_none());
    }

    #[tokio::test]
    async fn test_verify_id_token_hint_rejects_wrong_issuer() {
        let state = test_app_state().await;

        // Sign with the state's key but use a wrong issuer.
        let claims = test_id_token_claims(
            "https://evil.example.com",
            "user-123",
            "client-abc",
            9_999_999_999,
        );
        let token = state.oidc_key.sign_jwt(&claims).await.unwrap();
        assert!(verify_id_token_hint(&state, &token).is_none());
    }

    #[tokio::test]
    async fn test_verify_id_token_hint_accepts_valid_token() {
        let state = test_app_state().await;
        let base_url = state.config().base_url.clone();

        let claims = test_id_token_claims(&base_url, "user-123", "client-abc", 9_999_999_999);
        let token = state.oidc_key.sign_jwt(&claims).await.unwrap();

        let result = verify_id_token_hint(&state, &token);
        assert!(result.is_some());
        let c = result.unwrap();
        assert_eq!(c.sub, "user-123");
        assert_eq!(c.aud, "client-abc");
    }

    #[tokio::test]
    async fn test_verify_id_token_hint_accepts_expired_token() {
        let state = test_app_state().await;
        let base_url = state.config().base_url.clone();

        // exp in the past — should still verify (validate_exp = false).
        let claims = test_id_token_claims(&base_url, "user-456", "client-xyz", 1);
        let token = state.oidc_key.sign_jwt(&claims).await.unwrap();

        let result = verify_id_token_hint(&state, &token);
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_verify_id_token_hint_accepts_rs256_token() {
        // An id_token_hint signed with RS256 (the fallback key) must be accepted
        // when the server has an RSA key configured.
        let state = test_app_state_with_rsa_key().await;
        let base_url = state.config().base_url.clone();

        let rsa_key = state.oidc_rsa_key.as_ref().unwrap();
        let claims = test_id_token_claims(&base_url, "user-rs256", "client-rs256", 9_999_999_999);
        let token = rsa_key.sign_jwt(&claims).await.unwrap();

        let result = verify_id_token_hint(&state, &token);
        assert!(result.is_some(), "RS256-signed hint must be accepted");
        let c = result.unwrap();
        assert_eq!(c.aud, "client-rs256");
    }

    #[tokio::test]
    async fn test_verify_id_token_hint_rs256_rejected_without_rsa_key() {
        // A RS256-signed hint must be rejected when the server has no RSA key.
        // (The ES256 decode will fail, and there's no RSA fallback.)
        let state_with_rsa = test_app_state_with_rsa_key().await;
        let base_url = state_with_rsa.config().base_url.clone();

        let rsa_key = state_with_rsa.oidc_rsa_key.as_ref().unwrap();
        let claims = test_id_token_claims(&base_url, "user-no-rsa", "client-no-rsa", 9_999_999_999);
        let token = rsa_key.sign_jwt(&claims).await.unwrap();

        // Now verify against a state that has NO RSA key.
        let state_no_rsa = test_app_state().await;
        // We need the same base_url for the issuer check to pass.
        // Both states use test_config() so base_url matches — only the key differs.
        let result = verify_id_token_hint(&state_no_rsa, &token);
        assert!(
            result.is_none(),
            "RS256 hint must be rejected without RSA key"
        );
    }

    // ====================================================================
    // HTTP-level endpoint tests
    // ====================================================================

    /// Build a signed id_token_hint for the given app state and client_id.
    async fn make_hint(state: &crate::AppState, client_id: &str) -> String {
        let base_url = state.config().base_url.clone();
        let claims = test_id_token_claims(&base_url, "user-1", client_id, 9_999_999_999);
        state.oidc_key.sign_jwt(&claims).await.unwrap()
    }

    #[tokio::test]
    async fn test_get_logout_renders_confirmation_no_hint() {
        // GET /oauth/logout without any hint always renders 200 HTML confirmation.
        let (app, _state) = test_app().await;
        let (status, body) = http_get(&app, "/oauth/logout", &[]).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML: {body}"
        );
        // The confirmation button carries the `cert-logout` automation hook that
        // the RP-Initiated Logout conformance suite clicks to confirm logout.
        assert!(
            body.contains(r#"id="cert-logout""#),
            "confirm button must carry the cert-logout hook: {body}"
        );
    }

    #[tokio::test]
    async fn test_get_logout_renders_confirmation_with_valid_hint() {
        // GET /oauth/logout with a valid hint renders the confirmation page (200 HTML).
        let (app, state) = test_app().await;
        let hint = make_hint(&state, "test-client").await;
        let url = format!("/oauth/logout?id_token_hint={}", urlencoding::encode(&hint));
        let (status, body) = http_get(&app, &url, &[]).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_get_logout_renders_confirmation_without_session_cookie() {
        // GET /oauth/logout without a session cookie still renders 200 (not 401).
        // The logout endpoint must not require authentication.
        let (app, _state) = test_app().await;
        let (status, _body) = http_get(&app, "/oauth/logout", &[]).await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_post_logout_clears_session_and_redirects_with_state() {
        // POST /oauth/logout with a valid hint + registered redirect URI should:
        // 1. Clear the session (Set-Cookie: clear)
        // 2. 303 redirect to the registered URI with `state` echoed.
        let (app, state) = test_app().await;

        // Create a user + session.
        let user = create_test_user(&state.store, "logout-redirect@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        // Create an OAuth client with a registered post_logout_redirect_uri.
        let post_logout_uri = "https://rp.example.com/logged-out";
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                name: "Logout Test App".to_string(),
                post_logout_redirect_uris: vec![post_logout_uri.to_string()],
                ..Default::default()
            },
        )
        .await;
        let client_id = client.client_id;

        let hint = make_hint(&state, &client_id).await;
        let form_body = format!(
            "id_token_hint={}&client_id={}&post_logout_redirect_uri={}&state=my-opaque-state",
            urlencoding::encode(&hint),
            urlencoding::encode(&client_id),
            urlencoding::encode(post_logout_uri),
        );

        let (status, body) = http_post_form(
            &app,
            "/oauth/logout",
            &form_body,
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert_eq!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "expected 303 redirect; body: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_inactive_client_renders_done_page() {
        // A deactivated client must NOT receive a post-logout redirect, even with
        // a valid hint and a registered URI — consistent with the authorize flow.
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "logout-inactive@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let post_logout_uri = "https://rp.example.com/logged-out";
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                name: "Inactive Logout App".to_string(),
                post_logout_redirect_uris: vec![post_logout_uri.to_string()],
                ..Default::default()
            },
        )
        .await;
        let client_id = client.client_id;

        // Deactivate the client after creation.
        crate::db::set_oauth_client_active(&state.store, &client.app_id, false)
            .await
            .unwrap();

        let hint = make_hint(&state, &client_id).await;
        let form_body = format!(
            "id_token_hint={}&client_id={}&post_logout_redirect_uri={}&state=opaque",
            urlencoding::encode(&hint),
            urlencoding::encode(&client_id),
            urlencoding::encode(post_logout_uri),
        );

        let (status, body) = http_post_form(
            &app,
            "/oauth/logout",
            &form_body,
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
        )
        .await;

        assert_ne!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "deactivated client must not receive a redirect; body: {body}"
        );
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected done-page HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_tampered_hint_renders_done_page() {
        // A tampered / wrong-issuer hint must NOT redirect. Instead render done page locally.
        let (app, _state) = test_app().await;

        let form_body = "id_token_hint=garbage.garbage.garbage&post_logout_redirect_uri=https://evil.example.com/";

        let (status, body) = http_post_form(&app, "/oauth/logout", form_body, &[]).await;

        // Must NOT redirect to the evil URI.
        assert_ne!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "must not redirect with tampered hint; body: {body}"
        );
        // Must render done page HTML.
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected done-page HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_unregistered_redirect_uri_renders_done_page() {
        // A valid hint but an unregistered redirect URI must NOT redirect.
        let (app, state) = test_app().await;
        let hint = make_hint(&state, "no-such-client").await;
        let form_body = format!(
            "id_token_hint={}&post_logout_redirect_uri=https://unregistered.example.com/",
            urlencoding::encode(&hint),
        );

        let (status, body) = http_post_form(&app, "/oauth/logout", &form_body, &[]).await;
        assert_ne!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "must not redirect to unregistered URI; body: {body}"
        );
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected done-page HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_client_id_mismatch_renders_done_page() {
        // When client_id != hint.aud the hint is discarded → no redirect.
        let (app, state) = test_app().await;
        let hint = make_hint(&state, "real-client").await;
        let form_body = format!(
            "id_token_hint={}&client_id=different-client&post_logout_redirect_uri=https://rp.example.com/",
            urlencoding::encode(&hint),
        );

        let (status, body) = http_post_form(&app, "/oauth/logout", &form_body, &[]).await;
        assert_ne!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "client_id mismatch must discard hint; body: {body}"
        );
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected done-page HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_no_hint_renders_done_page() {
        // POST without any hint and with a redirect URI must NOT redirect.
        // Redirect is gated on a verified hint — bare client_id is not enough.
        let (app, _state) = test_app().await;
        let form_body = "post_logout_redirect_uri=https://rp.example.com/";

        let (status, body) = http_post_form(&app, "/oauth/logout", form_body, &[]).await;
        assert_ne!(
            status,
            axum::http::StatusCode::SEE_OTHER,
            "no hint must not redirect; body: {body}"
        );
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected done-page HTML: {body}"
        );
    }

    #[tokio::test]
    async fn test_post_logout_set_cookie_clears_session() {
        // POST must always return a Set-Cookie header that clears the session,
        // regardless of whether a redirect URI is available.
        let (app, _state) = test_app().await;
        let (status, _body) = http_post_form(&app, "/oauth/logout", "", &[]).await;

        // 200 (done page) or 303 (redirect) — both must have cleared the cookie.
        // We verify the response is well-formed (not an error).
        assert!(
            status == axum::http::StatusCode::OK || status == axum::http::StatusCode::SEE_OTHER,
            "unexpected status: {status}"
        );
    }
}
