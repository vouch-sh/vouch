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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&granted),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&granted),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;

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

    let ad_value: serde_json::Value = serde_json::from_str(r#"[{"type":"a"}]"#).unwrap();
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let ad_value: serde_json::Value = serde_json::from_str(r#"[{"type":"a"}]"#).unwrap();
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            authorization_details: Some(&ad_value),
            ..Default::default()
        },
    )
    .await;

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

// ---------------------------------------------------------------------------
// Section 6: client_credentials grant — authorization_details and resource
//
// RFC 9396 §6 explicitly covers the client_credentials grant: the AS checks
// the request against "the client's policy … in case of grant type
// client_credentials" and, if not allowed, "refuses the request with the
// error code invalid_authorization_details". Before the fix, the server
// silently discarded `authorization_details` (and `resource`) for this grant,
// issuing a full-policy token with a 200 and no `authorization_details` member.
// The fix plumbs both parameters through `ClientCredentialsParams` and fails
// closed: `authorization_details` is parsed and rejected, and `resource` is
// validated against the client's registered `resource_uris` allowlist
// (RFC 8707 §2, which applies to all grant types).
// ---------------------------------------------------------------------------

/// Create a client registered for the `client_credentials` grant.
async fn machine_client(state: &std::sync::Arc<crate::AppState>, email: &str) -> TestOAuthClient {
    let user = create_test_user(&state.store, email).await;
    create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Machine Client".to_string(),
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await
}

/// Create a client registered for `client_credentials` with a `resource_uris`
/// allowlist containing `resource_uri`.
async fn machine_client_with_resources(
    state: &std::sync::Arc<crate::AppState>,
    email: &str,
    resource_uris: Vec<String>,
) -> TestOAuthClient {
    let user = create_test_user(&state.store, email).await;
    create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Machine Client".to_string(),
            grant_types: Some(vec!["client_credentials".to_string()]),
            resource_uris,
            ..Default::default()
        },
    )
    .await
}

#[tokio::test]
async fn test_client_credentials_authorization_details_rejected() {
    // RFC 9396 §6: The client_credentials grant is explicitly covered by
    // RFC 9396. No per-client authorization-details policy exists yet, so
    // the server fails closed: a request carrying `authorization_details`
    // is rejected with `invalid_authorization_details` rather than silently
    // issuing a full-policy token.
    let (app, state) = test_app().await;
    let client = machine_client(&state, "cc-ad@example.com").await;

    let ad = r#"[{"type":"payment_initiation","actions":["initiate"]}]"#;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&authorization_details={}",
            urlencoding::encode(ad),
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "client_credentials with authorization_details must be rejected: {body}"
    );
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_authorization_details",
        "error must be invalid_authorization_details: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_malformed_authorization_details_rejected() {
    // RFC 9396 §5: "The AS MUST refuse to process any unknown authorization
    // details type or authorization details not conforming to the respective
    // type definition." Malformed JSON must be rejected with
    // `invalid_authorization_details` — the same error the authorization_code
    // and token-exchange grants produce for the same input. Before the fix,
    // the client_credentials grant never parsed the value at all, so even
    // malformed JSON was silently accepted with a 200.
    let (app, state) = test_app().await;
    let client = machine_client(&state, "cc-ad-malformed@example.com").await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&authorization_details={}",
            urlencoding::encode("not-valid-json"),
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed authorization_details must be rejected: {body}"
    );
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_authorization_details",
        "error must be invalid_authorization_details for malformed JSON: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_authorization_details_non_array_rejected() {
    // RFC 9396 §2: authorization_details MUST be a JSON array. A JSON object
    // is rejected with `invalid_authorization_details` on the authorization_code
    // grant; the client_credentials grant must produce the same error.
    let (app, state) = test_app().await;
    let client = machine_client(&state, "cc-ad-obj@example.com").await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&authorization_details={}",
            urlencoding::encode(r#"{"type":"payment"}"#),
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_authorization_details",
        "non-array authorization_details must be rejected: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_without_authorization_details_succeeds() {
    // No regression: a client_credentials request without authorization_details
    // still succeeds and the response omits the authorization_details member.
    let (app, state) = test_app().await;
    let client = machine_client(&state, "cc-no-ad@example.com").await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials should succeed: {body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        resp.get("authorization_details").is_none(),
        "authorization_details should be omitted when not requested: {body}"
    );
    assert!(
        resp.get("access_token").is_some(),
        "access_token must be present: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_resource_sets_audience() {
    // RFC 8707 §2: The `resource` parameter applies to all grant types.
    // A registered resource URI on a client_credentials request sets the
    // audience of the issued token, narrowing it from the default self
    // audience.
    let (app, state) = test_app().await;
    let resource_uri = "https://api.example.com";
    let client = machine_client_with_resources(
        &state,
        "cc-resource@example.com",
        vec![resource_uri.to_string()],
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!("grant_type=client_credentials&resource={resource_uri}",),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials with registered resource should succeed: {body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let access_token = resp["access_token"].as_str().expect("access_token");

    // The issued token's `aud` claim must match the requested resource.
    let claims = decode_jwt_payload(access_token);
    let aud = claims
        .get("aud")
        .expect("access token should have aud claim");
    let aud_str = aud.as_str().unwrap_or_default();
    assert_eq!(
        aud_str, resource_uri,
        "access token aud should match the registered resource indicator"
    );
}

#[tokio::test]
async fn test_client_credentials_unregistered_resource_rejected() {
    // RFC 8707 §2: A `resource` parameter that is not on the client's
    // registered `resource_uris` allowlist must be rejected with
    // `invalid_target` — the same chokepoint the token-exchange grant uses.
    let (app, state) = test_app().await;
    let client = machine_client_with_resources(
        &state,
        "cc-resource-unregistered@example.com",
        vec!["https://api.example.com".to_string()],
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&resource={}",
            "https://unregistered.example.com",
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unregistered resource must be rejected: {body}"
    );
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_target",
        "error must be invalid_target for unregistered resource: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_invalid_resource_uri_rejected() {
    // RFC 8707 §2: The resource parameter must be an absolute URI without a
    // fragment. A syntactically invalid URI is rejected with `invalid_target`.
    let (app, state) = test_app().await;
    let client = machine_client_with_resources(
        &state,
        "cc-resource-invalid@example.com",
        vec!["https://api.example.com".to_string()],
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials&resource=not-a-valid-uri",
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid resource URI must be rejected: {body}"
    );
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_target",
        "error must be invalid_target for invalid resource URI: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_resource_with_fragment_rejected() {
    // RFC 8707 §2: The resource URI MUST NOT contain a fragment component.
    let (app, state) = test_app().await;
    let client = machine_client_with_resources(
        &state,
        "cc-resource-fragment@example.com",
        vec!["https://api.example.com".to_string()],
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&resource={}",
            urlencoding::encode("https://api.example.com#fragment"),
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "resource URI with fragment must be rejected: {body}"
    );
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_target",
        "error must be invalid_target for resource URI with fragment: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_without_resource_succeeds_no_regression() {
    // No regression: a client_credentials request without a `resource`
    // parameter still succeeds and the token carries the default audience
    // (the client_id), not a narrowed one.
    let (app, state) = test_app().await;
    let client = machine_client_with_resources(
        &state,
        "cc-no-resource@example.com",
        vec!["https://api.example.com".to_string()],
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials without resource should succeed: {body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        resp.get("access_token").is_some(),
        "access_token must be present: {body}"
    );
}

#[tokio::test]
async fn test_client_credentials_authorization_details_size_limit() {
    // The global 8192-byte size gate on authorization_details (applied
    // before grant dispatch) must reject oversized values with
    // invalid_authorization_details for client_credentials requests.
    let (app, state) = test_app().await;
    let client = machine_client(&state, "cc-ad-size@example.com").await;

    let big = format!(r#"[{{"type":"x","data":"{}"}}]"#, "a".repeat(9000));
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=client_credentials&authorization_details={}",
            urlencoding::encode(&big),
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let err: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        err["error"], "invalid_authorization_details",
        "Should reject oversized authorization_details for client_credentials: {body}"
    );
}
