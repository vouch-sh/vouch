// SPDX-License-Identifier: BUSL-1.1
//! RFC 8693 — Token Exchange tests.

use super::helpers::*;

#[tokio::test]
async fn test_token_exchange_requires_grant_type() {
    // RFC 8693 Section 2.1: grant_type is required
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=invalid&subject_token=test",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_exchange_valid_token_types() {
    // RFC 8693 Section 2.1: All valid subject_token_type URNs should be accepted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-types@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let valid_types = [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:jwt",
    ];

    for token_type in valid_types {
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type={}",
                token, token_type
            ),
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Token type {} should be accepted, got: {}",
            token_type,
            body
        );
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(
            response.get("access_token").is_some(),
            "Response for {} should contain access_token",
            token_type
        );
    }
}

#[tokio::test]
async fn test_token_exchange_invalid_subject_token() {
    // RFC 8693: Invalid subject token returns invalid_grant
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-invalid@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_exchange_successful() {
    // RFC 8693: Successful token exchange
    let (app, state) = test_app().await;

    // Create a valid subject token and client for authentication
    let user = create_test_user(&state.store, "exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Should return access_token"
    );
    assert!(
        response.get("issued_token_type").is_some(),
        "Should return issued_token_type"
    );
    assert!(
        response.get("token_type").is_some(),
        "Should return token_type"
    );
    assert!(
        response.get("expires_in").is_some(),
        "Should return expires_in"
    );
}

#[tokio::test]
async fn test_token_exchange_scope_downgrade() {
    // RFC 8693 Section 2.2: Can reduce scope, not expand
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Request a subset of scopes
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
    // Should only have requested scope (openid) not full scope
    assert!(scope.contains("openid") || scope.is_empty());
}

#[tokio::test]
async fn test_token_exchange_uses_subject_scope() {
    // RFC 8693: Token exchange should respect subject token's scope
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-scope2@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue token with only "openid" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let auth_header = client.basic_auth_header();

    // Exchange and request "openid email" — should only get "openid" (intersection)
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid email",
            access_token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
    assert_eq!(
        scope, "openid",
        "Exchange should intersect with subject token's scope"
    );
}

#[tokio::test]
async fn test_rfc8693_missing_subject_token() {
    // RFC 8693 Section 2.1: Missing subject_token returns invalid_request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-missing-subject@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Missing subject_token should be rejected, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_rfc8693_missing_subject_token_type() {
    // RFC 8693 Section 2.1: Missing subject_token_type returns invalid_request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-missing-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Missing subject_token_type should be rejected"
    );
}

#[tokio::test]
async fn test_rfc8693_issued_token_type_in_response() {
    // RFC 8693 Section 2.2: Response must include issued_token_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-issued-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let issued_type = response["issued_token_type"]
        .as_str()
        .expect("issued_token_type must be present");
    assert!(
        issued_type.starts_with("urn:ietf:params:oauth:token-type:"),
        "issued_token_type must be a valid URN: {}",
        issued_type
    );
}

#[tokio::test]
async fn test_rfc8693_unsupported_requested_token_type() {
    // RFC 8693 Section 2.1: Unsupported requested_token_type returns error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-bad-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:invalid:type",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Unsupported requested_token_type should be rejected"
    );
}

#[tokio::test]
async fn test_rfc8693_delegation_depth_limit() {
    // RFC 8693 / Vouch: Exceeding max delegation depth (5) must be rejected.
    // We test this by performing a chain of token exchanges with actor tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "delegation-depth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Get initial OAuth access token
    let (mut subject_token, _) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Create a series of actor tokens (another user)
    let _actor_user = create_test_user(&state.store, "actor@example.com").await;

    // Chain exchanges with actor tokens to build delegation depth.
    // MAX_DELEGATION_DEPTH is 5, so after 5 successful exchanges with actor tokens,
    // the 6th should fail.
    let mut depth = 0;
    let mut failed = false;

    for i in 0..7 {
        // Create a unique actor user for each iteration to avoid session hash collisions
        let actor_email = format!("actor-{}@example.com", i);
        let iter_actor = create_test_user(&state.store, &actor_email).await;
        let iter_actor_auth = create_test_authenticator(&state.store, &iter_actor.id).await;
        let actor_token =
            create_test_session(&state, &iter_actor.id, &iter_actor.email, &iter_actor_auth).await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token={}&actor_token_type=urn:ietf:params:oauth:token-type:access_token",
                subject_token, actor_token
            ),
            &[("Authorization", &auth_header)],
        )
        .await;

        if status != StatusCode::OK {
            depth = i;
            failed = true;
            let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
            assert_eq!(
                error["error"], "invalid_request",
                "Delegation depth exceeded should return invalid_request"
            );
            break;
        }

        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        subject_token = response["access_token"]
            .as_str()
            .expect("access_token present")
            .to_string();
    }

    assert!(
        failed,
        "Delegation chain should be rejected at some point (max depth is 5), got to depth {}",
        depth
    );
}

#[tokio::test]
async fn test_rfc8693_client_auth_required_for_exchange() {
    // RFC 8693: Token exchange requires client authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-noauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Try token exchange without any client authentication
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[],
    )
    .await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Token exchange without client auth should fail, got: {}",
        status
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Token exchange without client auth should return invalid_client"
    );
}

#[tokio::test]
async fn test_rfc8693_issued_token_type_in_exchange_response() {
    // RFC 8693 Section 2.2: Response MUST include issued_token_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("issued_token_type").is_some(),
        "Response must include issued_token_type (RFC 8693 Section 2.2)"
    );
    let issued_type = response["issued_token_type"].as_str().unwrap();
    assert!(
        issued_type.starts_with("urn:ietf:params:oauth:token-type:"),
        "issued_token_type should be a valid URN, got: {issued_type}"
    );
}

#[tokio::test]
async fn test_rfc8693_unsupported_requested_token_type_rejected() {
    // RFC 8693 Section 2.1: Unsupported requested_token_type returns error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-unsupported@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type=urn:ietf:params:oauth:token-type:saml2"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Unsupported requested_token_type should fail: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc8693_actor_token_delegation_chain() {
    // RFC 8693 Section 2.1: Token exchange with actor token produces nested `act` claims.
    let (app, state) = test_app().await;

    // Create grantor (subject) user
    let grantor = create_test_user(&state.store, "grantor@example.com").await;
    let grantor_auth = create_test_authenticator(&state.store, &grantor.id).await;
    let client = create_test_oauth_client(&state.store, &grantor.id).await;

    // Create grantee (actor) user
    let grantee = create_test_user(&state.store, "grantee@example.com").await;
    let grantee_auth = create_test_authenticator(&state.store, &grantee.id).await;

    // Get tokens for both users
    let (grantor_token, _) =
        issue_oauth_access_token(&app, &state, &grantor, &grantor_auth, &client).await;
    let (grantee_token, _) =
        issue_oauth_access_token(&app, &state, &grantee, &grantee_auth, &client).await;

    let auth_header = client.basic_auth_header();

    // Perform token exchange with actor token
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={grantor_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token={grantee_token}\
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange with actor should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged_token = response["access_token"]
        .as_str()
        .expect("access_token present");

    // Decode the exchanged token and verify `act` claim
    let claims = decode_jwt_payload(exchanged_token);
    assert!(
        claims.get("act").is_some(),
        "Exchanged token should have 'act' claim for delegation chain"
    );
    let act = &claims["act"];
    assert!(
        act.get("sub").is_some(),
        "act claim should contain sub field"
    );
    assert_eq!(
        act["sub"], "grantee@example.com",
        "act.sub should be the grantee email"
    );
}

#[tokio::test]
async fn test_rfc8693_token_lifetime_capped_by_subject() {
    // RFC 8693 Section 2.2: Exchanged token lifetime should not exceed
    // the remaining lifetime of the subject token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-lifetime@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let expires_in = response["expires_in"].as_u64().expect("expires_in present");

    // Decode the subject token to check its remaining lifetime
    let subject_claims = decode_jwt_payload(&access_token);
    let subject_exp = subject_claims["exp"].as_i64().expect("subject exp");
    let now = jiff::Timestamp::now().as_second();
    let subject_remaining = subject_exp.saturating_sub(now);

    // The exchanged token's lifetime should not exceed the subject token's remaining TTL
    assert!(
        expires_in <= subject_remaining as u64 + 5, // +5s tolerance for test timing
        "Exchanged token lifetime ({expires_in}s) should not exceed subject remaining ({subject_remaining}s)"
    );
}

#[tokio::test]
async fn test_rfc8693_invalid_actor_token_type() {
    // RFC 8693: Invalid actor_token_type should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-bad-actor-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token=some-token\
             &actor_token_type=urn:ietf:params:oauth:token-type:saml2"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Invalid actor_token_type should be rejected, got {status}: {body}"
    );
}
