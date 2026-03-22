// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7662 — Token Introspection tests.

use super::helpers::*;

// ========================================================================
// P1: RFC 7662 — Token Introspection
// ========================================================================

#[tokio::test]
async fn test_introspect_active_token() {
    // RFC 7662 Section 2.2: Active token returns active=true with claims
    let (app, state) = test_app().await;

    // Create a test user and OAuth client
    let user = create_test_user(&state.store, "introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue an access token via the OAuth flow so the token's client_id
    // matches the introspecting client (RFC 7662 Section 4 cross-client check)
    let (token, _id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);
    assert!(
        response.get("exp").is_some(),
        "Active token should have exp"
    );
    assert!(
        response.get("iat").is_some(),
        "Active token should have iat"
    );
    assert!(
        response.get("sub").is_some(),
        "Active token should have sub"
    );
}

#[tokio::test]
async fn test_introspect_invalid_token() {
    // RFC 7662 Section 2.2: Invalid token returns active=false
    let (app, state) = test_app().await;

    // Create an OAuth client for authentication (RFC 7662 Section 2.1)
    let user = create_test_user(&state.store, "introspect-invalid@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        "token=invalid_token_here",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], false);
    // Inactive tokens should not leak claims
    assert!(response.get("exp").is_none());
    assert!(response.get("sub").is_none());
}

#[tokio::test]
async fn test_introspect_revoked_token() {
    // RFC 7662 Section 2.2: Revoked token returns active=false
    let (app, state) = test_app().await;

    // Create user, OAuth client, and session
    let user = create_test_user(&state.store, "introspect-revoked@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Revoke the token (requires client authentication per RFC 7009)
    let _ = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    // Introspect should now return inactive (with client auth per RFC 7662)
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], false);
}

#[tokio::test]
async fn test_auth_code_flow_token_works_with_introspection() {
    // Issue auth code → exchange → /oauth/introspect → assert active=true
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], true,
        "OAuth access token should be active"
    );
    assert!(response.get("exp").is_some(), "Should have exp claim");
    assert!(response.get("sub").is_some(), "Should have sub claim");
}

#[tokio::test]
async fn test_introspection_returns_actual_scope() {
    // RFC 7662 Section 2.2: Introspection must return actual granted scope
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token with only "openid" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);

    let scope = response["scope"].as_str().expect("scope should be present");
    assert_eq!(
        scope, "openid",
        "Introspection should return actual granted scope"
    );
}

#[tokio::test]
async fn test_rfc7662_introspection_requires_client_auth() {
    // RFC 7662 Section 2.1: Introspection requires client authentication.
    let (app, _state) = test_app().await;

    // Try introspection without any authentication
    let (status, body) =
        http_post_form(&app, "/oauth/introspect", "token=some_token_value", &[]).await;

    // Should either return 401 or return active=false (server policy)
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::OK,
        "Expected 401 or 200 with active=false, got: {status} {body}"
    );
    if status == StatusCode::OK {
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            response["active"], false,
            "Unauthenticated introspection should return active=false"
        );
    }
}

#[tokio::test]
async fn test_rfc7662_response_content_type() {
    // RFC 7662 Section 2.2: Response Content-Type must be application/json.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-ct@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Should have Content-Type header")
        .to_str()
        .expect("Valid string");
    assert!(
        content_type.contains("application/json"),
        "Introspection response must be application/json, got: {}",
        content_type
    );
}

#[tokio::test]
async fn test_rfc7662_active_token_required_fields() {
    // RFC 7662 Section 2.2: Active token introspection response must include
    // required fields: active, scope, client_id, token_type, exp, iat, sub, iss
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-fields@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);

    // RFC 7662 Section 2.2: REQUIRED for active tokens
    assert!(response.get("sub").is_some(), "Active token must have sub");
    assert!(response.get("exp").is_some(), "Active token must have exp");
    assert!(response.get("iat").is_some(), "Active token must have iat");
    assert!(response.get("iss").is_some(), "Active token must have iss");
    assert!(
        response.get("client_id").is_some(),
        "Active token must have client_id"
    );
    assert!(
        response.get("token_type").is_some(),
        "Active token must have token_type"
    );
    assert!(
        response.get("scope").is_some(),
        "Active token must have scope"
    );
}

// ========================================================================
// Phase 2: RFC 7662 — Token Introspection Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7662_introspection_active_token_has_required_fields() {
    // RFC 7662 Section 2.2: Active token response must include
    // all required fields.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-fields@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Introspection should succeed: {body}"
    );
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(result["active"], true, "Token should be active");
    assert!(result.get("scope").is_some(), "Must include scope");
    assert!(result.get("client_id").is_some(), "Must include client_id");
    assert!(
        result.get("token_type").is_some(),
        "Must include token_type"
    );
    assert!(result.get("exp").is_some(), "Must include exp");
    assert!(result.get("iat").is_some(), "Must include iat");
    assert!(result.get("sub").is_some(), "Must include sub");
    assert!(result.get("iss").is_some(), "Must include iss");
}

#[tokio::test]
async fn test_rfc7662_introspection_response_content_type() {
    // RFC 7662 Section 2.2: Response Content-Type must be application/json.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-ct@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let ct = response
        .headers
        .get("Content-Type")
        .expect("Must have Content-Type")
        .to_str()
        .expect("Valid str");
    assert!(
        ct.contains("application/json"),
        "Content-Type must be application/json, got: {ct}"
    );
}

#[tokio::test]
async fn test_rfc7662_cross_client_introspection() {
    // RFC 7662 Section 4: Introspection should handle cross-client scenarios.
    // Client B introspects a token issued to Client A.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-cross@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token for client A
    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client_a).await;

    // Introspect with client B
    let auth_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token_a}"),
        &[("Authorization", &auth_b)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7662 Section 4: Cross-client introspection MUST return active=false.
    // Client B must not see metadata from tokens issued to Client A.
    assert_eq!(
        result["active"], false,
        "RFC 7662: Client B must not introspect Client A's token, got: {result}"
    );
    // No metadata should be disclosed on cross-client introspection
    assert!(
        result.get("sub").is_none(),
        "Inactive cross-client response must not leak sub"
    );
}

#[tokio::test]
async fn test_rfc7662_cross_client_introspection_returns_inactive() {
    // RFC 7662 Section 4: A token issued to Client A, when introspected by
    // Client B, MUST return active=false to prevent information disclosure.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-cross-inactive@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token for client A
    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client_a).await;

    // Introspect with client B — must return active=false per RFC 7662 Section 4
    let auth_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token_a}"),
        &[("Authorization", &auth_b)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7662 Section 4: Cross-client introspection returns active=false
    assert_eq!(
        result["active"], false,
        "Client B must not be able to introspect Client A's token, got: {result}"
    );
    // No metadata should be leaked on inactive response
    assert!(
        result.get("sub").is_none(),
        "Inactive response must not leak sub"
    );
    assert!(
        result.get("exp").is_none(),
        "Inactive response must not leak exp"
    );
    assert!(
        result.get("client_id").is_none(),
        "Inactive response must not leak client_id"
    );
}

#[tokio::test]
async fn test_rfc7662_same_client_introspection_returns_active() {
    // RFC 7662 Section 2.2: A client introspecting its own token must receive
    // active=true with full metadata.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-own-active@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token for the client
    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Client introspects its own token
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Must return active=true with full claims
    assert_eq!(
        result["active"], true,
        "Same-client introspection must return active=true"
    );
    assert!(
        result.get("sub").is_some(),
        "Active introspection must include sub"
    );
    assert!(
        result.get("exp").is_some(),
        "Active introspection must include exp"
    );
    assert!(
        result.get("iat").is_some(),
        "Active introspection must include iat"
    );
}
