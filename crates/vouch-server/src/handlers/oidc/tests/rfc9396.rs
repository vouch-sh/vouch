// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9396 — OAuth 2.0 Rich Authorization Requests tests.

use super::helpers::*;

// ---------------------------------------------------------------------------
// Section 2: authorization_details parameter in authorization request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authorization_details_in_token_response() {
    // RFC 9396 Section 7: Token response MUST include the effective
    // authorization_details when they were granted during authorization.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"payment_initiation","amount":100}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue_authorization_code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Token exchange failed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // RFC 9396 Section 7: authorization_details MUST be in the response
    let ad = resp
        .get("authorization_details")
        .expect("authorization_details must be in token response");
    assert!(ad.is_array(), "authorization_details must be a JSON array");
    let arr = ad.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["type"], "payment_initiation");
    assert_eq!(arr[0]["amount"], 100);
}

#[tokio::test]
async fn test_no_authorization_details_omitted_from_response() {
    // When no authorization_details were granted, the field should be
    // omitted from the token response (skip_serializing_if).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-none@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
            authorization_details: None,
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Token exchange failed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        resp.get("authorization_details").is_none(),
        "authorization_details should be omitted when not granted"
    );
}

// ---------------------------------------------------------------------------
// Section 6: Token request downscoping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_token_request_downscoping_subset_accepted() {
    // RFC 9396 Section 6: Client may send a subset of authorization_details
    // at the token endpoint to downscope.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-down@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let granted: serde_json::Value =
        serde_json::from_str(r#"[{"type":"a","v":1},{"type":"b","v":2}]"#).unwrap();
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
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: Some(&granted),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    // Downscope to just one entry
    let requested = r#"[{"type":"a","v":1}]"#;
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}\
             &redirect_uri={}\
             &authorization_details={}",
            code,
            "https://example.com/callback",
            urlencoding::encode(requested),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Downscoping should succeed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let ad = resp["authorization_details"].as_array().unwrap();
    assert_eq!(ad.len(), 1, "Should have downscoped to 1 entry");
    assert_eq!(ad[0]["type"], "a");
}

#[tokio::test]
async fn test_token_request_downscoping_non_subset_rejected() {
    // RFC 9396 Section 6: If requested authorization_details is not a
    // subset, the server MUST reject with invalid_authorization_details.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-nonsubset@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let granted: serde_json::Value = serde_json::from_str(r#"[{"type":"a","v":1}]"#).unwrap();
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
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: Some(&granted),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    // Request something not in the granted set
    let requested = r#"[{"type":"b","v":99}]"#;
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}\
             &redirect_uri={}\
             &authorization_details={}",
            code,
            "https://example.com/callback",
            urlencoding::encode(requested),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(err["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn test_token_request_ad_when_none_granted_rejected() {
    // RFC 9396: If authorization_details was not granted during
    // authorization, sending it at the token endpoint is an error.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-nongrant@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
        },
    )
    .await
    .expect("issue code");

    let requested = r#"[{"type":"payment"}]"#;
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}\
             &redirect_uri={}\
             &authorization_details={}",
            code,
            "https://example.com/callback",
            urlencoding::encode(requested),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(err["error"], "invalid_authorization_details");
}

// ---------------------------------------------------------------------------
// Section 5: Validation of authorization_details parameter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_invalid_authorization_details_json() {
    // RFC 9396 Section 2: authorization_details must be valid JSON.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-invalid@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let ad_value: serde_json::Value = serde_json::from_str(r#"[{"type":"a"}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    // Send invalid JSON at token endpoint
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}\
             &redirect_uri={}\
             &authorization_details={}",
            code,
            "https://example.com/callback",
            urlencoding::encode("not-valid-json"),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(err["error"], "invalid_authorization_details");
}

#[tokio::test]
async fn test_authorization_details_must_be_array() {
    // RFC 9396 Section 2: authorization_details MUST be a JSON array.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-notarray@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let ad_value: serde_json::Value = serde_json::from_str(r#"[{"type":"a"}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    // Send a JSON object instead of an array
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}\
             &redirect_uri={}\
             &authorization_details={}",
            code,
            "https://example.com/callback",
            urlencoding::encode(r#"{"type":"a"}"#),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(err["error"], "invalid_authorization_details");
}

// ---------------------------------------------------------------------------
// Section 9.2: Introspection includes authorization_details
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_introspection_includes_authorization_details() {
    // RFC 9396 Section 9.2: Token introspection MUST include
    // authorization_details if they were granted.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-intro@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"credential","format":"jwt_vc"}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Token exchange failed: {body}");
    let token_resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let access_token = token_resp["access_token"].as_str().unwrap();

    // Introspect the token
    let (intro_status, intro_body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(intro_status, StatusCode::OK);
    let intro: serde_json::Value = serde_json::from_str(&intro_body).expect("valid JSON");
    assert_eq!(intro["active"], true);

    let intro_ad = intro
        .get("authorization_details")
        .expect("introspection must include authorization_details");
    assert!(intro_ad.is_array());
    let arr = intro_ad.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["type"], "credential");
    assert_eq!(arr[0]["format"], "jwt_vc");
}

#[tokio::test]
async fn test_introspection_omits_ad_when_not_granted() {
    // When no authorization_details were granted, introspection should
    // not include the field.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-intro-no@example.com").await;
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
    assert_eq!(status, StatusCode::OK);
    let intro: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(intro["active"], true);
    assert!(
        intro.get("authorization_details").is_none(),
        "authorization_details should be absent when not granted"
    );
}

// ---------------------------------------------------------------------------
// Token exchange inherits and narrows authorization_details
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_token_exchange_inherits_authorization_details() {
    // RFC 9396: Token exchange inherits authorization_details from the
    // subject token's session.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-exch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"api_access","actions":["read"]}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Token exchange failed: {body}");
    let token_resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let access_token = token_resp["access_token"].as_str().unwrap();

    // Exchange the token
    let (exch_status, exch_body) = http_post_form(
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

    assert_eq!(
        exch_status,
        StatusCode::OK,
        "Token exchange failed: {exch_body}"
    );
    let exch_resp: serde_json::Value = serde_json::from_str(&exch_body).expect("valid JSON");
    let exch_ad = exch_resp
        .get("authorization_details")
        .expect("exchanged token must inherit authorization_details");
    assert!(exch_ad.is_array());
    assert_eq!(exch_ad.as_array().unwrap().len(), 1);
    assert_eq!(exch_ad[0]["type"], "api_access");
}

#[tokio::test]
async fn test_token_exchange_narrows_authorization_details() {
    // RFC 9396 Section 6: Token exchange can narrow authorization_details.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-exch-narrow@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"x","v":1},{"type":"y","v":2}]"#).unwrap();
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
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token_resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let access_token = token_resp["access_token"].as_str().unwrap();

    // Narrow to just one entry during exchange
    let narrowed = r#"[{"type":"x","v":1}]"#;
    let (exch_status, exch_body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &authorization_details={}",
            urlencoding::encode(narrowed),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        exch_status,
        StatusCode::OK,
        "Narrowing should succeed: {exch_body}"
    );
    let exch_resp: serde_json::Value = serde_json::from_str(&exch_body).expect("valid JSON");
    let ad = exch_resp["authorization_details"].as_array().unwrap();
    assert_eq!(ad.len(), 1);
    assert_eq!(ad[0]["type"], "x");
}

#[tokio::test]
async fn test_token_exchange_narrow_non_subset_rejected() {
    // RFC 9396: Narrowing to a non-subset must fail.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-exch-reject@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value = serde_json::from_str(r#"[{"type":"x"}]"#).unwrap();
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
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token_resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let access_token = token_resp["access_token"].as_str().unwrap();

    // Try to narrow to something not in the original set
    let bad = r#"[{"type":"z"}]"#;
    let (exch_status, exch_body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &authorization_details={}",
            urlencoding::encode(bad),
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(exch_status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&exch_body).expect("valid JSON");
    assert_eq!(err["error"], "invalid_authorization_details");
}

// ---------------------------------------------------------------------------
// Multiple entries and combined scope + authorization_details
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_authorization_detail_entries() {
    // RFC 9396 Section 2: Multiple typed detail objects are valid.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-multi@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"payment","amount":50},{"type":"account_info","actions":["list"]},{"type":"payment","amount":200}]"#,
    )
    .unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Should accept multiple entries");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let ad = resp["authorization_details"].as_array().unwrap();
    assert_eq!(ad.len(), 3, "All 3 entries should be preserved");
}

#[tokio::test]
async fn test_scope_and_authorization_details_coexist() {
    // RFC 9396 Section 3: scope and authorization_details can be
    // used independently and in combination.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-combo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"payment","amount":100}]"#).unwrap();
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
            authorization_details: Some(&ad_value),
            auth_time: None,
        },
    )
    .await
    .expect("issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // Both scope and authorization_details should be present
    assert!(resp.get("scope").is_some(), "scope should be present");
    assert!(
        resp.get("authorization_details").is_some(),
        "authorization_details should be present"
    );
}

// ---------------------------------------------------------------------------
// Size limit enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authorization_details_size_limit_at_token_endpoint() {
    // The token endpoint should reject oversized authorization_details.
    let (app, _state) = test_app().await;

    let big = format!(r#"[{{"type":"x","data":"{}"}}]"#, "a".repeat(9000));
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code=x\
             &authorization_details={}",
            urlencoding::encode(&big),
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_authorization_details",
        "Should reject oversized authorization_details"
    );
}
