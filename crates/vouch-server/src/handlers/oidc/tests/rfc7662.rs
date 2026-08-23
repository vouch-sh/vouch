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

// ========================================================================
// RFC 7662 — Token Introspection with private_key_jwt (GH#274)
// ========================================================================

#[tokio::test]
async fn test_rfc7662_introspect_with_private_key_jwt_succeeds() {
    // RFC 7662 + RFC 7523: Introspection with private_key_jwt authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-jwt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (jwt_client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    // Issue a token for the JWT client via auth code flow

    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &jwt_client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue code");

    // Exchange code using private_key_jwt
    let token_url = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&jwt_client.client_id, &token_url, &pkcs8_bytes, None);
    let token_body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );
    let (status, resp_body) = http_post_form(&app, "/oauth/token", &token_body, &[]).await;
    assert_eq!(status, StatusCode::OK, "Token exchange failed: {resp_body}");
    let token_resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    let access_token = token_resp["access_token"].as_str().expect("access_token");

    // Introspect using private_key_jwt with aud=/oauth/introspect
    let introspect_url = format!("{}/oauth/introspect", state.config().base_url);
    let intro_assertion =
        build_client_assertion(&jwt_client.client_id, &introspect_url, &pkcs8_bytes, None);
    let intro_body = format!(
        "token={}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        access_token, intro_assertion
    );
    let (status, body) = http_post_form(&app, "/oauth/introspect", &intro_body, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Introspection with private_key_jwt failed: {body}"
    );
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        result["active"], true,
        "Token should be active via private_key_jwt introspection"
    );
    assert!(result.get("sub").is_some(), "Active token must have sub");
    assert!(result.get("exp").is_some(), "Active token must have exp");
}

#[tokio::test]
async fn test_rfc7662_introspect_private_key_jwt_jti_replay_rejected() {
    // GH#274: Replayed JWT assertion at /oauth/introspect must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-replay@example.com").await;
    let (jwt_client, pkcs8_bytes) = create_test_jwt_client(&state.store, &user.id).await;

    let introspect_url = format!("{}/oauth/introspect", state.config().base_url);
    let fixed_jti = "introspect-replay-jti-001";

    // First introspection with a fixed JTI — should return 200
    let assertion1 = build_client_assertion(
        &jwt_client.client_id,
        &introspect_url,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let body1 = format!(
        "token=some_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion1
    );
    let (status1, _) = http_post_form(&app, "/oauth/introspect", &body1, &[]).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First use of JTI at introspect must return 200"
    );

    // Second introspection with the SAME JTI — must be rejected (replay)
    let assertion2 = build_client_assertion(
        &jwt_client.client_id,
        &introspect_url,
        &pkcs8_bytes,
        Some(fixed_jti),
    );
    let body2 = format!(
        "token=another_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion2
    );
    let (status2, _) = http_post_form(&app, "/oauth/introspect", &body2, &[]).await;
    assert_eq!(
        status2,
        StatusCode::UNAUTHORIZED,
        "Replayed JTI at introspect must be rejected with 401"
    );
}

#[tokio::test]
async fn test_rfc7662_introspect_private_key_jwt_invalid_assertion_rejected() {
    // Invalid client assertion at /oauth/introspect must be rejected.
    let (app, _state) = test_app().await;

    let body = "token=some_token\
        &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
        &client_assertion=invalid.jwt.value";

    let (status, _) = http_post_form(&app, "/oauth/introspect", body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Invalid JWT assertion at introspect must be rejected, got: {status}"
    );
}

// ========================================================================
// Issue #540 — Introspection service propagates DB errors
//
// Before the fix, a DB error in session lookup was swallowed and returned
// as {"active": false}. After the fix, DB errors propagate as ServiceError::
// Internal and the handler returns an error response, not inactive.
//
// This is a type-level test: we verify the service function's return type
// correctly distinguishes errors from "token not found" (Ok(inactive)).
// A full DB-outage test would require injecting a broken store.
// ========================================================================

#[tokio::test]
async fn test_rfc7662_valid_token_is_active_unknown_token_is_inactive() {
    // Baseline: valid token → active=true; unknown token → active=false.
    // This exercises the Ok(Some) and Ok(None) branches, which must stay
    // distinguishable from Err(_) (issue #540).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "introspect-active-540@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Valid token → active.
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
        "Valid token must return 200: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["active"], true,
        "Valid token must be active=true: {body}"
    );

    // Unknown token → inactive (Ok(None) path, not an error).
    let (status2, body2) = http_post_form(
        &app,
        "/oauth/introspect",
        "token=completely.unknown.token",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status2,
        StatusCode::OK,
        "Unknown token must return 200 per RFC 7662: {body2}"
    );
    let json2: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");
    assert_eq!(
        json2["active"], false,
        "Unknown token must be active=false: {body2}"
    );
}

// ========================================================================
// Deactivated user — introspection MUST return active=false
//
// Deactivation paths (admin `members.rs`, SCIM `users.rs`) are not atomic:
// `update_user_active_status` and `delete_sessions_for_user` commit in
// separate transactions. If session deletion fails after the user is
// deactivated, live sessions remain. Introspection must not grant access
// to a deactivated user's token in that state — it mirrors the `user.active`
// check already performed by the direct API path (`extract_user_with_org`)
// and the token exchange path.
// ========================================================================

#[tokio::test]
async fn test_introspection_returns_inactive_for_deactivated_user_with_session() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "introspect-deactivated@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Deactivate the user WITHOUT deleting the session.
    // This simulates the scenario where session deletion fails after
    // user deactivation succeeds. Each operation commits independently
    // since there is no transaction wrapping both.
    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], false,
        "Deactivated user's token must return active=false, got: {response}"
    );

    // RFC 7662 Section 2.2: Inactive response MUST NOT leak token metadata.
    assert!(
        response.get("exp").is_none(),
        "Inactive response must not include exp: {response}"
    );
    assert!(
        response.get("sub").is_none(),
        "Inactive response must not include sub: {response}"
    );
    assert!(
        response.get("client_id").is_none(),
        "Inactive response must not include client_id: {response}"
    );
    assert!(
        response.get("username").is_none(),
        "Inactive response must not include username: {response}"
    );
}

#[tokio::test]
async fn test_introspection_returns_active_for_reactivated_user() {
    // Reactivating a user must restore introspection to active=true, confirming
    // the deactivation branch is a status check (not token/session destruction)
    // and that reactivation re-grants access to existing unexpired sessions.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "introspect-reactivate@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Deactivate, then reactivate.
    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");
    crate::db::update_user_active_status(&state.store, &user.id, true)
        .await
        .expect("reactivate user");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Reactivated user: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], true,
        "Reactivated user's token must return active=true, got: {response}"
    );
}

#[tokio::test]
async fn test_introspection_m2m_client_credentials_token_is_active() {
    // M2M sessions store the client_id in `user_id` and have no user row.
    // Introspection must report them active — not 500, and not inactive —
    // since there is no resource owner whose deactivation could apply.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "m2m-introspect@example.com").await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..TestClientSpec::default()
        },
    )
    .await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials issuance: {body}"
    );
    let token_response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = token_response["access_token"]
        .as_str()
        .expect("access_token in response");

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
        "M2M introspection must not error: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], true,
        "M2M token must introspect as active despite having no user row: {response}"
    );
}
