// SPDX-License-Identifier: BUSL-1.1
//! Shared test helpers and re-exported imports for OIDC test modules.

pub(super) use crate::db;
pub(super) use crate::services::oidc::authorization::{
    AuthorizationCodeParams, CodeChallengeMethod, issue_authorization_code,
};
pub(super) use crate::services::oidc::scope::ScopeSet;
pub(super) use crate::test_utils::*;
pub(super) use aws_lc_rs::digest::SHA256;
pub(super) use axum::http::StatusCode;
pub(super) use base64::Engine;
pub(super) use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Create an authorization code and exchange it at `/oauth/token` to get an access token.
/// Returns `(access_token, id_token)`.
pub(super) async fn issue_oauth_access_token(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
) -> (String, String) {
    issue_oauth_access_token_with_scope(app, state, user, auth_id, client, "openid email").await
}

/// Create an authorization code with a specific scope and exchange it at `/oauth/token`.
/// Uses the real `issue_authorization_code()` service function to exercise the full
/// code path including server-side code storage for single-use enforcement.
/// Returns `(access_token, id_token)`.
pub(super) async fn issue_oauth_access_token_with_scope(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
    scope: &str,
) -> (String, String) {
    use crate::services::oidc::authorization::{AuthorizationCodeParams, issue_authorization_code};

    let scope_set = ScopeSet::parse(scope);

    let code_params = AuthorizationCodeParams {
        client_id: &client.client_id,
        redirect_uri: "https://example.com/callback",
        user_id: &user.id,
        email: &user.email,
        authenticator_id: auth_id,
        aaguid: None,
        scope: &scope_set,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        resource: None,
        acr_values: None,
    };

    let code = issue_authorization_code(state, code_params)
        .await
        .expect("Failed to issue authorization code");

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange should succeed: {}",
        body
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();
    let id_token = response["id_token"]
        .as_str()
        .expect("id_token present")
        .to_string();

    (access_token, id_token)
}

/// Decode a JWT payload (middle part) without signature verification.
pub(super) fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert!(parts.len() >= 2, "JWT should have at least 2 parts");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("Valid base64");
    serde_json::from_slice(&payload).expect("Valid JSON")
}

/// Compute SHA-256 of `input` and encode as base64url (no padding).
pub(super) fn sha256_base64url(input: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&SHA256, input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}
