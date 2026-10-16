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

    let ad_value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os_version":"pi-100"}]"#,
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

    assert_eq!(status, StatusCode::OK, "Token exchange failed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // RFC 9396 Section 7: authorization_details MUST be in the response
    let ad = resp
        .get("authorization_details")
        .expect("authorization_details must be in token response");
    assert!(ad.is_array(), "authorization_details must be a JSON array");
    let arr = ad.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["os_version"], "pi-100");
    assert_eq!(arr[0]["posture_version"], 1);
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
        serde_json::from_str(r#"[{"type":"device_posture","posture_version":1,"os_version":"a1"},{"type":"device_posture","posture_version":1,"os_version":"b2"}]"#).unwrap();

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
    let requested = r#"[{"type":"device_posture","posture_version":1,"os_version":"a1"}]"#;
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
    assert_eq!(ad[0]["os_version"], "a1");
}

#[tokio::test]
async fn test_token_request_downscoping_non_subset_rejected() {
    // RFC 9396 Section 6: If requested authorization_details is not a
    // subset, the server MUST reject with invalid_authorization_details.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-nonsubset@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let granted: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os_version":"a1"}]"#,
    )
    .unwrap();

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
    let requested = r#"[{"type":"device_posture","posture_version":1,"os_version":"b99"}]"#;
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

    let requested = r#"[{"type":"device_posture","posture_version":1,"os_version":"payment"}]"#;
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

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"device_posture","posture_version":1,"os_version":"a"}]"#)
            .unwrap();
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

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"device_posture","posture_version":1,"os_version":"a"}]"#)
            .unwrap();
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
            urlencoding::encode(
                r#"{"type":"device_posture","posture_version":1,"os_version":"a"}"#
            ),
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

    let ad_value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os_version":"credential"}]"#,
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
    assert_eq!(arr[0]["os_version"], "credential");
    assert_eq!(arr[0]["type"], "device_posture");
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

    let ad_value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os_version":"api"}]"#,
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
    assert_eq!(exch_ad[0]["os_version"], "api");
}

#[tokio::test]
async fn test_token_exchange_narrows_authorization_details() {
    // RFC 9396 Section 6: Token exchange can narrow authorization_details.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-exch-narrow@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"device_posture","posture_version":1,"os_version":"x1"},{"type":"device_posture","posture_version":1,"os_version":"y2"}]"#).unwrap();

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
    let narrowed = r#"[{"type":"device_posture","posture_version":1,"os_version":"x1"}]"#;
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
    assert_eq!(ad[0]["os_version"], "x1");
}

#[tokio::test]
async fn test_token_exchange_narrow_non_subset_rejected() {
    // RFC 9396: Narrowing to a non-subset must fail.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-exch-reject@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let ad_value: serde_json::Value =
        serde_json::from_str(r#"[{"type":"device_posture","posture_version":1,"os_version":"x"}]"#)
            .unwrap();

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
    let bad = r#"[{"type":"device_posture","posture_version":1,"os_version":"z"}]"#;
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
        r#"[{"type":"device_posture","posture_version":1,"os_version":"pay50"},{"type":"device_posture","posture_version":1,"os_version":"acct"},{"type":"device_posture","posture_version":1,"os_version":"pay200"}]"#,
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

    let ad_value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os_version":"pay100"}]"#,
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

    let big = format!(
        r#"[{{"type":"device_posture","posture_version":1,"os_version":"{}"}}]"#,
        "a".repeat(9000)
    );
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
// Section 6: grants with no authorization details to grant
// ---------------------------------------------------------------------------

// RFC 9396 §6: the AS checks requested authorization details against "the
// client's policy (in case of grant type client_credentials)"; "Otherwise, the
// AS refuses the request with the error code invalid_authorization_details".
// No client policy grants any, so the request is refused rather than issued a
// token that silently omits what was asked for.
#[tokio::test]
async fn test_client_credentials_authorization_details_refused() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-cc@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let details = r#"[{"type":"device_posture","posture_version":1}]"#;
    let (status, json) = client_credentials_request(
        &app,
        &client,
        &format!("&authorization_details={}", urlencoding::encode(details)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["error"], "invalid_authorization_details", "{json}");
    assert!(json.get("access_token").is_none(), "{json}");
}

// RFC 9396 §5: malformed details are reported as such on the refusing grant
// too, before the grant-level refusal.
#[tokio::test]
async fn test_client_credentials_malformed_authorization_details_refused() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-cc-bad@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, json) =
        client_credentials_request(&app, &client, "&authorization_details=not-json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["error"], "invalid_authorization_details", "{json}");
    let description = json["error_description"].as_str().unwrap_or_default();
    assert!(
        description.contains("JSON"),
        "the description must name the parse failure, not the grant refusal: {description}"
    );
}

// The grant still issues when the parameter is absent.
#[tokio::test]
async fn test_client_credentials_without_authorization_details_issues() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-cc-none@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, json) = client_credentials_request(&app, &client, "").await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json.get("authorization_details").is_none(), "{json}");
}

// RFC 9396 §5: "The AS MUST refuse to process any unknown authorization
// details type". Pinned at a grant that otherwise accepts the parameter.
#[tokio::test]
async fn test_token_exchange_unknown_authorization_details_type_refused() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-unknown@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let unknown = r#"[{"type":"payment_initiation","amount":100}]"#;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &authorization_details={}",
            urlencoding::encode(unknown),
        ),
        &[("Authorization", client.basic_auth_header().as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["error"], "invalid_authorization_details", "{body}");
}

// RFC 6749 §5.2: "Values for the "error_description" parameter MUST NOT
// include characters outside the set %x20-21 / %x23-5B / %x5D-7E." The serde
// message for an unknown enum value quotes it, and must not reach the wire.
#[tokio::test]
async fn test_authorization_details_error_description_is_rfc6749_charset() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "ad-charset@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let details = r#"[{"type":"device_posture","posture_version":1,"mdm":["acme"]}]"#;
    let (status, json) = client_credentials_request(
        &app,
        &client,
        &format!("&authorization_details={}", urlencoding::encode(details)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    let description = json["error_description"].as_str().expect("description");
    assert!(description.contains("acme"), "{description}");
    assert!(
        description
            .chars()
            .all(|c| (' '..='~').contains(&c) && c != '"' && c != '\\'),
        "error_description outside RFC 6749 §5.2's set: {description}"
    );
}
