// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    // RFC 8693 §2.2.2: "If the request itself is not valid or if either the
    // 'subject_token' or 'actor_token' are invalid for any reason, or are
    // unacceptable based on policy, the authorization server MUST construct
    // an error response, as specified in Section 5.2 of [RFC6749]. The value
    // of the 'error' parameter MUST be the 'invalid_request' error code."
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
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_exchange_successful() {
    // RFC 8693: Successful token exchange
    let (app, state) = test_app().await;

    // Create a valid subject token and client for authentication
    let user = create_test_user(&state.store, "exchange@example.com").await;
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

    // The exchange writes a token_exchange audit event for the subject user.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["token_exchange".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "one exchange -> one audit event");
    assert_eq!(events[0].user_id.as_deref(), Some(user.id.as_str()));
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("event data JSON");
    assert_eq!(data["event_type"], "token_issued");
    assert_eq!(data["client_id"], client.client_id);
    assert_eq!(
        data["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
}

#[tokio::test]
async fn test_token_exchange_scope_downgrade() {
    // RFC 8693 Section 2.2: Can reduce scope, not expand
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-scope@example.com").await;
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
    // RFC 6749 §5.2: invalid_request covers a request "missing a required
    // parameter". Pairing subject_token with subject_token_type is what makes
    // this reachable — an absent token used to reach the decoder as an empty
    // string and be reported as an invalid token instead.
    assert_eq!(
        error["error"], "invalid_request",
        "Missing subject_token should be rejected as invalid_request, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_rfc8693_missing_subject_token_type() {
    // RFC 8693 Section 2.1: Missing subject_token_type returns invalid_request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-missing-type@example.com").await;
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
        let actor_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &iter_actor.id,
                email: &iter_actor.email,
                auth_id: Some(&iter_actor_auth),
                ..Default::default()
            },
        )
        .await;

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
async fn test_rfc8693_requested_token_type_jwt_rejected() {
    // RFC 8693 Section 2.1: `jwt` is accepted as a subject_token_type but is
    // not a type this server issues, so requesting it is rejected rather than
    // silently substituted with an access token (Section 2.2.1 requires
    // `issued_token_type` to name what was actually issued).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-jwt-requested@example.com").await;
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
             &requested_token_type=urn:ietf:params:oauth:token-type:jwt"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "requested_token_type=jwt should be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
    assert!(
        error["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("Unsupported requested_token_type")),
        "description should name the parameter: {body}"
    );
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
        expires_in <= u64::try_from(subject_remaining).unwrap_or(0) + 5, // +5s tolerance for test timing
        "Exchanged token lifetime ({expires_in}s) should not exceed subject remaining ({subject_remaining}s)"
    );
}

#[tokio::test]
async fn test_rfc8693_self_delegation_rejected() {
    // Self-delegation (actor == subject) must be rejected to prevent
    // unlimited session generation from a single authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "self-delegate@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue a token for the same user
    let (user_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    // Use the same user's token as both subject and actor
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={user_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token={user_token}\
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Self-delegation should be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
    assert!(
        error["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("Self-delegation")),
        "Error should mention self-delegation, got: {body}"
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

#[tokio::test]
async fn test_rfc8693_actor_token_type_without_actor_token_rejected() {
    // RFC 8693 §2.1: actor_token_type "is REQUIRED when the `actor_token`
    // parameter is present in the request but MUST NOT be included otherwise."
    // That MUST NOT binds the client, so rejecting is our choice — taken so a
    // client that mislabels its request learns about it instead of receiving a
    // token with the parameter silently dropped.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-lone-actor-type@example.com").await;
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
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request", "{body}");
}

#[tokio::test]
async fn test_rfc8693_actor_token_without_actor_token_type_rejected() {
    // RFC 8693 §2.1: actor_token_type is REQUIRED when actor_token is present.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exchange-untyped-actor@example.com").await;
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
             &actor_token=some-token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request", "{body}");
}

#[tokio::test]
async fn test_rfc8693_deactivated_subject_user_rejected() {
    // GH#275: Deactivated user cannot exchange tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "deactivated-exchange@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Deactivate the user after creating the session
    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // RFC 8693 §2.2.2: a subject token "unacceptable based on policy"
    // (deactivated user) MUST yield the invalid_request error code.
    assert_eq!(error["error"], "invalid_request");
}

// ========================================================================
// requested_token_type = id_token (Workload Identity Federation)
//
// When the client asks for an ID token, the server mints a clean OIDC ID
// token (ES256) instead of an RFC 9068 access token. This is the assertion
// used by `vouch credential anthropic|openai|k8s`. The ID token is never
// persisted as a session and carries only the standard OIDC claim set.
// ========================================================================

const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

#[tokio::test]
async fn test_rfc8693_id_token_request_returns_clean_id_token() {
    // requested_token_type=id_token mints an OIDC ID token whose claims match
    // the subject user, and reports the ID-token issued type with a Bearer
    // token_type (ID tokens are not sender-constrained).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-basic@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(
        response["issued_token_type"], ID_TOKEN_TYPE,
        "issued_token_type must report id_token"
    );
    // RFC 8693 §2.2.1: "If the issued token is not an access token or usable
    // as an access token, then the "token_type" value "N_A" is used to
    // indicate that an OAuth 2.0 "token_type" identifier is not applicable in
    // that context." The exchanged ID token is a federation assertion, not a
    // credential the client presents to this server.
    assert_eq!(
        response["token_type"], "N_A",
        "an exchanged ID token is not usable as an access token"
    );

    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);

    assert_eq!(
        claims["iss"], "https://test.example.com",
        "issuer is the Vouch base URL"
    );
    assert_eq!(claims["sub"], "wif-basic@example.com");
    assert_eq!(claims["email"], "wif-basic@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["hardware_verified"], true);
    assert!(
        claims["jti"].as_str().is_some_and(|j| !j.is_empty()),
        "ID token must carry a jti for replay prevention"
    );

    // The ID-token exchange writes a token_exchange audit event too.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["token_exchange".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "one exchange -> one audit event");
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("event data JSON");
    assert_eq!(data["issued_token_type"], ID_TOKEN_TYPE);
    assert!(
        data["scope"].is_null(),
        "ID tokens do not carry OAuth scope"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_audience_routing() {
    // RFC 8707: the requested audience becomes the ID token's `aud` claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-aud@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}\
             &audience=https://my-cluster.example.org"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["aud"], "https://my-cluster.example.org",
        "requested audience must become the aud claim"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_default_audience_is_issuer() {
    // With no audience requested, the ID token's `aud` falls back to the issuer.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-default-aud@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["aud"], "https://test.example.com",
        "aud defaults to the issuer when no audience is requested"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_lifetime_capped_at_default() {
    // The ID token lifetime is capped at the 600s federation ceiling even
    // though the subject token (an 8h session) has far more time remaining.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-ttl@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["expires_in"].as_u64().expect("expires_in present"),
        600,
        "ID token lifetime is capped at the federation ceiling"
    );

    // The exp claim should agree with the reported expires_in (within slop).
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    let exp = claims["exp"].as_i64().expect("exp present");
    let now = jiff::Timestamp::now().as_second();
    let remaining = exp.saturating_sub(now);
    assert!(
        (595..=605).contains(&remaining),
        "exp should be ~600s out, was {remaining}s"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_not_persisted_as_session() {
    // The minted ID token must not be stored as a session — it is a one-shot
    // federation assertion, never a replayable Vouch credential.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-nosession@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");

    let hash = crate::crypto::hash_token(id_token);
    let session = state
        .session_cache
        .get_session_by_token_hash(&state.store, &hash)
        .await
        .expect("session lookup");
    assert!(
        session.is_none(),
        "ID token must not be persisted as a session"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_carries_hardware_aaguid() {
    // The ID token surfaces the backing authenticator's AAGUID so relying
    // parties can pin a hardware model in their trust policy.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-aaguid@example.com").await;
    let aaguid = "ee882879-721c-4913-9775-3dfcce97072a";
    let auth_id = crate::db::create_authenticator(
        &state.store,
        &crate::db::CreateAuthenticatorParams {
            user_id: &user.id,
            user_email: &user.email,
            name: "YubiKey 5",
            credential_id: format!("cred-{}", uuid::Uuid::now_v7()).as_bytes(),
            public_key: &[0u8; 32],
            aaguid: Some(aaguid),
            user_handle: Some(user.id.as_bytes()),
            attestation_verified: true,
        },
    )
    .await
    .expect("create authenticator with aaguid");
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["hardware_aaguid"], aaguid,
        "ID token should carry the authenticator AAGUID"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_uses_session_aaguid_after_rotation() {
    // Regression for GH#431: the id_token must reflect the AAGUID captured at
    // session creation, not the user's *current* authenticator. Otherwise, a
    // user who rotates security keys retroactively invalidates the federation
    // claims of every still-live session.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-rotation@example.com").await;
    let original_aaguid = "ee882879-721c-4913-9775-3dfcce97072a";
    let auth_id = crate::db::create_authenticator(
        &state.store,
        &crate::db::CreateAuthenticatorParams {
            user_id: &user.id,
            user_email: &user.email,
            name: "YubiKey 5 (original)",
            credential_id: format!("cred-{}", uuid::Uuid::now_v7()).as_bytes(),
            public_key: &[0u8; 32],
            aaguid: Some(original_aaguid),
            user_handle: Some(user.id.as_bytes()),
            attestation_verified: true,
        },
    )
    .await
    .expect("create original authenticator");

    // Session captures the original AAGUID.
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // The invariant: the session-time snapshot survives
    // even when the original authenticator is no longer present. (We bypass
    // `delete_authenticator` because it cascades and removes the session
    // along with the key — the snapshot is what makes the issued claim
    // independent of *current* authenticator state at issuance time.)
    state
        .store
        .delete(&auth_id)
        .await
        .expect("delete authenticator without cascade");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["hardware_aaguid"], original_aaguid,
        "ID token must reflect the AAGUID captured at session creation, \
         not the user's current authenticator after rotation"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_carries_hd_for_org_user() {
    // A user in an organization gets the org's domain as the `hd` claim, so
    // relying parties can restrict federation to a corporate domain.
    let (app, state) = test_app().await;

    let org = create_test_org(&state.store, "example.com").await;
    let user = create_test_user_in_org(&state.store, "hduser@example.com", &org.id, false).await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "ID token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["hd"], "example.com",
        "ID token should carry the organization domain as hd"
    );
}

#[tokio::test]
async fn test_rfc8693_access_token_request_unaffected_by_id_token_branch() {
    // Regression guard: explicitly requesting an access token still mints an
    // RFC 9068 access token (issued type access_token), not an ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-regression@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Access token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["issued_token_type"], "urn:ietf:params:oauth:token-type:access_token",
        "default exchange must still issue an access token"
    );
    // An RFC 9068 access token is persisted as a session; the ID token is not.
    let access_token = response["access_token"]
        .as_str()
        .expect("access_token present");
    let hash = crate::crypto::hash_token(access_token);
    let session = state
        .session_cache
        .get_session_by_token_hash(&state.store, &hash)
        .await
        .expect("session lookup");
    assert!(
        session.is_some(),
        "exchanged access token must be persisted as a session"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_deactivated_user_rejected() {
    // The deactivation check runs before the ID-token fork, so a deactivated
    // user cannot mint a federation assertion either.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-deactivated@example.com").await;
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
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // RFC 8693 §2.2.2: a subject token "unacceptable based on policy"
    // (deactivated user) MUST yield the invalid_request error code.
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc8693_id_token_rejects_non_hardware_verified_subject() {
    // A non-hardware-verified subject token (e.g., an enrollment bootstrap
    // session created after upstream SSO but before FIDO2 registration) must
    // not be exchangeable for an ID token. The ID-token claim set hardcodes
    // `hardware_verified: true`, so allowing this exchange would launder a
    // pre-FIDO2 session into a federation assertion that downstream relying
    // parties trust as hardware-attested.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "wif-bootstrap@example.com").await;
    let token = crate::test_utils::create_test_session_with(
        &state,
        crate::test_utils::TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            verification: TestVerification::NotVerified,
            ..Default::default()
        },
    )
    .await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "access_denied");

    // Regression guard: the same subject token must still work for an
    // access-token exchange. The hardware gate is specific to ID-token
    // requests; access-token exchange preserves the original
    // `hardware_verified: false` claim (no laundering possible).
    let (status_at, body_at) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status_at,
        StatusCode::OK,
        "access-token exchange must remain available for non-hardware subjects: {body_at}"
    );
}

#[tokio::test]
async fn test_rfc8693_id_token_rejects_actor_token() {
    // The ID-token claim set has no `act` field, so honoring `actor_token`
    // for an ID-token request would silently drop the delegation chain.
    // Refuse the combination explicitly. The access-token path (without
    // `requested_token_type`) continues to honor `actor_token` as tested by
    // `test_rfc8693_actor_token_delegation_chain`.
    let (app, state) = test_app().await;

    let grantor = create_test_user(&state.store, "id-grantor@example.com").await;
    let grantor_auth = create_test_authenticator(&state.store, &grantor.id).await;
    let client = create_test_oauth_client(&state.store, &grantor.id).await;

    let grantee = create_test_user(&state.store, "id-grantee@example.com").await;
    let grantee_auth = create_test_authenticator(&state.store, &grantee.id).await;

    let (grantor_token, _) =
        issue_oauth_access_token(&app, &state, &grantor, &grantor_auth, &client).await;
    let (grantee_token, _) =
        issue_oauth_access_token(&app, &state, &grantee, &grantee_auth, &client).await;

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={grantor_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token={grantee_token}\
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

// ========================================================================
// Issue #550 — Deactivated actor user must be rejected
//
// When a token exchange carries an actor_token, the actor user's active
// flag must be checked symmetrically with the subject user check. A
// deactivated actor must produce an error, not a 200 with an act claim.
// ========================================================================

#[tokio::test]
async fn test_rfc8693_deactivated_actor_user_rejected() {
    // Regression for #550: deactivating the actor user after its session
    // was created must prevent it from being used in a token exchange.
    let (app, state) = test_app().await;

    let subject = create_test_user(&state.store, "actor-subject-550@example.com").await;
    let actor = create_test_user(&state.store, "actor-deactivated-550@example.com").await;
    let subject_auth = create_test_authenticator(&state.store, &subject.id).await;
    let actor_auth = create_test_authenticator(&state.store, &actor.id).await;
    let client = create_test_oauth_client(&state.store, &subject.id).await;

    // Issue tokens for both users before deactivation.
    let (subject_token, _) =
        issue_oauth_access_token(&app, &state, &subject, &subject_auth, &client).await;
    let (actor_token, _) =
        issue_oauth_access_token(&app, &state, &actor, &actor_auth, &client).await;

    // Deactivate the actor user.
    crate::db::update_user_active_status(&state.store, &actor.id, false)
        .await
        .expect("deactivate actor user");

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token={actor_token}\
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Deactivated actor must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // RFC 8693 §2.2.2: an actor token "unacceptable based on policy"
    // (deactivated user) MUST yield the invalid_request error code.
    assert_eq!(
        error["error"], "invalid_request",
        "Must return invalid_request for deactivated actor: {body}"
    );
    assert!(
        error["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("deactivated")),
        "Error description must mention deactivated: {body}"
    );
}

/// RFC 6749 Section 10.5: "the authorization server SHOULD attempt to revoke
/// all access tokens already granted based on the compromised authorization
/// code." An exchanged token derives its authority from the subject token, so
/// a token exchanged from an authorization-code token was granted based on
/// that code and must be revoked when the code is replayed — otherwise an
/// exchange launders a compromised code into a token that outlives it.
#[tokio::test]
async fn test_token_exchange_inherits_the_subject_s_authorization_code() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "exchange-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Redeem an authorization code, then exchange the resulting token.
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;
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
    assert_eq!(status, StatusCode::OK, "code exchange failed: {body}");
    let subject_token =
        serde_json::from_str::<serde_json::Value>(&body).expect("Valid JSON")["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token exchange failed: {body}");
    let exchanged =
        serde_json::from_str::<serde_json::Value>(&body).expect("Valid JSON")["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();

    // A session from a grant with no single-use code must survive the replay.
    let unrelated = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let (status, _) = http_post_form(
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
        StatusCode::BAD_REQUEST,
        "the replayed code must be denied"
    );

    for (token, label) in [
        (&subject_token, "the subject token"),
        (&exchanged, "the exchanged token"),
    ] {
        let (status, _) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} must be revoked with the replayed code"
        );
    }
    assert_token_alive(&app, &unrelated, "a session from a grant with no code").await;
}

// ========================================================================
// Actor token session lookup — error propagation parity with the subject
// token lookup (issue #540 pattern).
//
// The actor session lookup must distinguish:
//   * Ok(None) — session missing/revoked → `invalid_request` (RFC 8693 §2.2.2)
//   * Err(_)   — store failure          → `ServiceError::Internal` (500)
//
// The `Ok(None)` arm is exercised here by issuing a real actor token and
// deleting its backing session before the exchange. The `Err` arm is not
// reachable end-to-end via `state.db.close()`: with the pool closed the
// handler's client-auth lookup, the subject session lookup, and the
// subject's (uncached) `db::get_user_by_id` all run before the actor
// session lookup and would surface a 500 first. The isolated `Err`-arm
// regression test uses the test-only `SessionCache::inject_fault` seam so
// only the actor token hash faults while the subject path keeps the open
// pool (see `test_rfc8693_actor_session_store_error_returns_internal`).
// ========================================================================

/// A validly-decoded actor token whose backing session has been removed
/// must produce `invalid_request` ("Actor token session not found or
/// revoked") per RFC 8693 §2.2.2, not a 500. Exercises the `Ok(None)` arm
/// of the actor session lookup — the same call site whose `Err` handling
/// the fix tightens.
#[tokio::test]
async fn test_rfc8693_actor_session_not_found_returns_invalid_request() {
    let (app, state) = test_app().await;

    // Subject (grantor) with a stored, valid access token.
    let grantor = create_test_user(&state.store, "actor-notfound-grantor@example.com").await;
    let grantor_auth = create_test_authenticator(&state.store, &grantor.id).await;
    let client = create_test_oauth_client(&state.store, &grantor.id).await;
    let (grantor_token, _) =
        issue_oauth_access_token(&app, &state, &grantor, &grantor_auth, &client).await;

    // Grantee (actor): issue a real token, then delete its backing session so
    // the actor session lookup returns `Ok(None)`.
    let grantee = create_test_user(&state.store, "actor-notfound-grantee@example.com").await;
    let grantee_auth = create_test_authenticator(&state.store, &grantee.id).await;
    let (grantee_token, _) =
        issue_oauth_access_token(&app, &state, &grantee, &grantee_auth, &client).await;

    let grantee_hash = crate::crypto::hash_token(&grantee_token);
    state.session_cache.invalidate(&grantee_hash);
    db::delete_session_by_token_hash(&state.store, &grantee_hash)
        .await
        .expect("delete actor session");

    let auth_header = client.basic_auth_header();
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
        StatusCode::BAD_REQUEST,
        "missing actor session must return invalid_request, got: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "missing actor session must report invalid_request: {body}"
    );
    assert!(
        error["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("Actor token session not found or revoked")),
        "error_description must name the actor session: {body}"
    );
}

/// Regression: a *store failure* during the actor token session lookup must
/// surface as `500 Internal Server Error`, not `invalid_grant`.
///
/// `state.db.close()` cannot isolate this branch: with the pool closed the
/// handler's client-auth lookup, the subject session lookup, and the subject
/// user lookup all run first and would return 500 via the subject path. Instead
/// we use the test-only `SessionCache::inject_fault` seam to make the actor
/// token hash fail with a store error while every other lookup uses the live,
/// open pool.
///
/// Against the pre-fix `!matches!(.., Ok(Some(_)))` code this returns the
/// OAuth error for a missing session (the bug); against the fixed
/// `.map_err(Internal)?.ok_or_else(..)?` code it returns 500. This is the
/// only test that discriminates the fix from the bug.
#[tokio::test]
async fn test_rfc8693_actor_session_store_error_returns_internal() {
    let (app, state) = test_app().await;

    // Distinct subject (grantor) and actor (grantee) users.
    let grantor = create_test_user(&state.store, "actor-fault-grantor@example.com").await;
    let grantor_auth = create_test_authenticator(&state.store, &grantor.id).await;
    let client = create_test_oauth_client(&state.store, &grantor.id).await;
    let (grantor_token, _) =
        issue_oauth_access_token(&app, &state, &grantor, &grantor_auth, &client).await;

    let grantee = create_test_user(&state.store, "actor-fault-grantee@example.com").await;
    let grantee_auth = create_test_authenticator(&state.store, &grantee.id).await;
    let (grantee_token, _) =
        issue_oauth_access_token(&app, &state, &grantee, &grantee_auth, &client).await;

    // Fault only the actor session lookup; the subject path keeps using the
    // open pool and succeeds.
    let grantee_hash = crate::crypto::hash_token(&grantee_token);
    state.session_cache.inject_fault(grantee_hash);

    let auth_header = client.basic_auth_header();
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
        StatusCode::INTERNAL_SERVER_ERROR,
        "store failure during actor session lookup must return 500, not an \
         OAuth token error; got: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_ne!(
        error["error"], "invalid_request",
        "DB error must not be reported as invalid_request: {body}"
    );
    assert_ne!(
        error["error"], "invalid_grant",
        "DB error must not be reported as invalid_grant: {body}"
    );
}
