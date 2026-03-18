// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Core 1.0 Section 5.3 — UserInfo + RFC 6750 WWW-Authenticate tests.

use super::helpers::*;

// ========================================================================
// UserInfo Endpoint Tests (OIDC Core 1.0 Section 5.3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_requires_bearer_token() {
    // OIDC Core 1.0 Section 5.3.1: UserInfo requires bearer token
    let (app, _state) = test_app().await;

    // No token
    let (status, body) = http_get(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_token");

    // Invalid token format
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_returns_sub_claim() {
    // OIDC Core 1.0 Section 5.3.2: Response must include 'sub' claim
    let (app, state) = test_app().await;

    // Create a test user and OAuth access token session (includes email scope)
    let user = create_test_user(&state.store, "userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        userinfo.get("sub").is_some(),
        "UserInfo must contain 'sub' claim"
    );
    // OAuth access token created with ScopeSet::all() includes email scope
    assert_eq!(
        userinfo["email"].as_str(),
        Some("userinfo@example.com"),
        "Email should be present when email scope is granted"
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token() {
    // Invalid token should return 401
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_token");
}

// ========================================================================
// WWW-Authenticate Header Tests (RFC 6750 Section 3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_401_includes_www_authenticate() {
    // RFC 6750 Section 3: 401 responses MUST include WWW-Authenticate header
    let (app, _state) = test_app().await;

    // No token — should get 401 with WWW-Authenticate
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.starts_with("Bearer"),
        "WWW-Authenticate should use Bearer scheme, got: {}",
        www_auth_str
    );
    assert!(
        www_auth_str.contains("error="),
        "WWW-Authenticate should include error parameter, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token_includes_www_authenticate() {
    // RFC 6750 Section 3.1: invalid_token error with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.contains("invalid_token"),
        "WWW-Authenticate should include invalid_token error, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_unsupported_scheme_includes_www_authenticate() {
    // RFC 6750 Section 3: Unsupported auth scheme should return 401 with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.starts_with("Bearer"),
        "WWW-Authenticate should use Bearer scheme"
    );
}
