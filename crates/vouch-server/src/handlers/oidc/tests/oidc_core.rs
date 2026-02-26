// SPDX-License-Identifier: BUSL-1.1
//! OpenID Connect Core 1.0 — ID Token claims, scope filtering, nonce tests.

use super::helpers::*;

// ========================================================================
// P1: OIDC Core 1.0 — ID Token Claims
// ========================================================================

#[tokio::test]
async fn test_oidc_id_token_at_hash_claim() {
    // OIDC Core Section 3.1.3.6: When issued alongside access token,
    // ID token must include at_hash claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "at-hash@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let id_claims = decode_jwt_payload(&id_token);
    assert!(
        id_claims.get("at_hash").is_some(),
        "ID token must include at_hash when issued with access token"
    );
    let at_hash = id_claims["at_hash"].as_str().expect("at_hash is a string");
    assert!(!at_hash.is_empty(), "at_hash must not be empty");
}

#[tokio::test]
async fn test_oidc_id_token_nonce_echo() {
    // OIDC Core Section 3.1.2.1: Nonce from auth request must appear in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "nonce-echo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let test_nonce = "unique-nonce-value-12345";
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: Some(test_nonce),
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token present");
    let id_claims = decode_jwt_payload(id_token);

    assert_eq!(
        id_claims["nonce"].as_str(),
        Some(test_nonce),
        "ID token must echo the nonce from the authorization request"
    );
}

#[tokio::test]
async fn test_oidc_id_token_required_claims() {
    // OIDC Core Section 2: ID token must contain iss, sub, aud, exp, iat.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "id-token-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    assert!(claims.get("iss").is_some(), "ID token must have iss");
    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(claims.get("aud").is_some(), "ID token must have aud");
    assert!(claims.get("exp").is_some(), "ID token must have exp");
    assert!(claims.get("iat").is_some(), "ID token must have iat");
}

#[tokio::test]
async fn test_oidc_id_token_aud_contains_client_id() {
    // OIDC Core Section 2: Audience must include the requesting client_id.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "id-token-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    let aud = &claims["aud"];

    // aud can be a string or an array
    if let Some(aud_str) = aud.as_str() {
        assert_eq!(
            aud_str, client.client_id,
            "ID token aud must match client_id"
        );
    } else if let Some(aud_arr) = aud.as_array() {
        assert!(
            aud_arr
                .iter()
                .any(|a| a.as_str() == Some(&client.client_id)),
            "ID token aud array must include client_id"
        );
    } else {
        panic!("ID token aud must be a string or array");
    }
}

#[tokio::test]
async fn test_oidc_userinfo_sub_matches_id_token() {
    // OIDC Core Section 5.3.2: UserInfo sub must match ID token sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "userinfo-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Get sub from ID token
    let id_claims = decode_jwt_payload(&id_token);
    let id_sub = id_claims["sub"].as_str().expect("ID token has sub");

    // Get sub from UserInfo
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let userinfo_sub = userinfo["sub"].as_str().expect("UserInfo has sub");

    assert_eq!(id_sub, userinfo_sub, "UserInfo sub must match ID token sub");
}

#[tokio::test]
async fn test_oidc_scope_based_claim_filtering() {
    // OIDC Core Section 5.4: email scope adds email claims.
    // Request with "openid email" scope should include email in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "scope-filter@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue with "openid email" scope
    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
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
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token");
    let id_claims = decode_jwt_payload(id_token);

    // With email scope, ID token should include email
    assert!(
        id_claims.get("email").is_some(),
        "ID token should include email when email scope is granted"
    );
}

// ========================================================================
// Phase 2: OpenID Connect Core 1.0 — Additional Tests
// ========================================================================

#[tokio::test]
async fn test_oidc_id_token_all_required_claims() {
    // OIDC Core 1.0 Section 2: ID Token must contain required claims.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "idtoken-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);

    assert!(claims.get("iss").is_some(), "ID token must have iss");
    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(claims.get("aud").is_some(), "ID token must have aud");
    assert!(claims.get("exp").is_some(), "ID token must have exp");
    assert!(claims.get("iat").is_some(), "ID token must have iat");
}

#[tokio::test]
async fn test_oidc_id_token_audience_includes_client_id() {
    // OIDC Core 1.0 Section 2: ID Token aud MUST include the client_id.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "idtoken-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    let aud = claims.get("aud").expect("ID token must have aud");

    // aud can be a string or array
    let aud_contains_client = if let Some(aud_str) = aud.as_str() {
        aud_str == client.client_id
    } else if let Some(aud_arr) = aud.as_array() {
        aud_arr
            .iter()
            .any(|v| v.as_str() == Some(&client.client_id))
    } else {
        false
    };
    assert!(
        aud_contains_client,
        "ID token aud must contain client_id '{}', got: {aud}",
        client.client_id
    );
}

#[tokio::test]
async fn test_oidc_id_token_at_hash() {
    // OIDC Core 1.0 Section 3.1.3.6: When issued alongside access token,
    // ID token should include at_hash.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "idtoken-athash@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);

    // at_hash is REQUIRED when the ID Token is issued from the Authorization Endpoint
    // with an access_token via the Implicit flow, but OPTIONAL in Authorization Code flow.
    // Check if present (good practice even in code flow).
    if let Some(at_hash) = claims.get("at_hash") {
        assert!(at_hash.is_string(), "at_hash should be a string if present");
    }
    // Not asserting presence since it's optional in authorization code flow
}

#[tokio::test]
async fn test_oidc_userinfo_sub_consistent_with_id_token() {
    // OIDC Core 1.0 Section 5.3.2: UserInfo sub must match ID token sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "userinfo-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Get UserInfo
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "UserInfo should succeed: {body}");
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Decode ID token sub
    let id_claims = decode_jwt_payload(&id_token);
    let id_sub = id_claims["sub"].as_str().expect("ID token sub");
    let userinfo_sub = userinfo["sub"].as_str().expect("UserInfo sub");

    assert_eq!(userinfo_sub, id_sub, "UserInfo sub must match ID token sub");
}

#[tokio::test]
async fn test_oidc_scope_based_claims_email() {
    // OIDC Core 1.0 Section 5.4: email scope adds email claims.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue with "openid email" scope
    let (access_token, _) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid email")
            .await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "UserInfo should succeed: {body}");
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        userinfo.get("email").is_some(),
        "email scope should provide email claim"
    );
}

#[tokio::test]
async fn test_oidc_nonce_echo_in_id_token() {
    // OIDC Core 1.0 Section 3.1.2.1: Nonce from auth request appears in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "nonce-echo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let nonce_value = "test-nonce-abc123";
    let scope_set = ScopeSet::parse("openid");

    // Issue code with nonce
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: Some(nonce_value),
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
        },
    )
    .await
    .expect("Failed to issue code with nonce");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token present");

    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims.get("nonce").and_then(|n| n.as_str()),
        Some(nonce_value),
        "ID token nonce must echo the auth request nonce"
    );
}
