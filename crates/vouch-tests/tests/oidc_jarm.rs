// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for JARM (JWT Secured Authorization Response Mode) JWT construction
//! in `services/oidc/jarm.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use serde_json::Value;
use vouch_server::db::{self, JwsAlgorithm, OAuthClient};
use vouch_server::services::oidc::jarm::{build_jarm_error_jwt, build_jarm_success_jwt};
use vouch_server::test_utils;
use vouch_tests::TestHarness;

async fn load_client(harness: &TestHarness, client_id: &str) -> OAuthClient {
    db::get_oauth_client_by_client_id(&harness.state.store, client_id)
        .await
        .expect("query oauth client")
        .expect("oauth client exists")
}

/// Decode a JWT's header and payload as JSON without verifying the signature.
fn decode_jwt_unverified(jwt: &str) -> (Value, Value) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have three parts: {jwt}");

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("decode header");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("decode payload");

    let header: Value = serde_json::from_slice(&header_bytes).expect("parse header json");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("parse payload json");

    (header, payload)
}

/// Build an OAuth client with the given JARM alg override.
async fn client_with_alg(
    harness: &TestHarness,
    user_id: &str,
    alg: Option<JwsAlgorithm>,
) -> OAuthClient {
    let tc = test_utils::create_test_oauth_client(&harness.state.store, user_id).await;
    let mut client = load_client(harness, &tc.client_id).await;
    client.authorization_signed_response_alg = alg;
    client
}

#[tokio::test]
async fn success_jwt_defaults_to_es256_when_alg_unset() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("jarm-default@example.com")
        .await
        .expect("create user");
    let client = client_with_alg(&harness, &user.id, None).await;

    let jwt = build_jarm_success_jwt(&harness.state, &client, "auth-code-1", Some("xyzzy"))
        .await
        .expect("build success jwt");

    let (header, payload) = decode_jwt_unverified(&jwt);
    assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
    assert_eq!(
        payload.get("iss").and_then(Value::as_str),
        Some(harness.state.config().base_url.as_str())
    );
    assert_eq!(
        payload.get("aud").and_then(Value::as_str),
        Some(client.client_id.as_str())
    );
    assert_eq!(
        payload.get("code").and_then(Value::as_str),
        Some("auth-code-1")
    );
    assert_eq!(payload.get("state").and_then(Value::as_str), Some("xyzzy"));
    assert!(payload.get("exp").and_then(Value::as_i64).is_some());
}

#[tokio::test]
async fn success_jwt_omits_state_when_none() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("jarm-nostate@example.com")
        .await
        .expect("create user");
    let client = client_with_alg(&harness, &user.id, Some(JwsAlgorithm::Es256)).await;

    let jwt = build_jarm_success_jwt(&harness.state, &client, "auth-code-2", None)
        .await
        .expect("build success jwt");

    let (_header, payload) = decode_jwt_unverified(&jwt);
    assert!(payload.get("state").is_none(), "state should be absent");
}

#[tokio::test]
async fn rs256_without_rsa_key_returns_error() {
    // The default `TestHarness` builds `AppState` without an RSA signing key,
    // so any client that opts into RS256 JARM must surface a clear error.
    let harness = TestHarness::new().await;

    let user = harness
        .create_user("jarm-rs256@example.com")
        .await
        .expect("create user");
    let client = client_with_alg(&harness, &user.id, Some(JwsAlgorithm::Rs256)).await;

    let err = build_jarm_success_jwt(&harness.state, &client, "code", None)
        .await
        .expect_err("rs256 without rsa key must fail");
    assert!(
        err.to_string().contains("RSA"),
        "error should mention missing RSA key, got: {err}"
    );

    let err = build_jarm_error_jwt(
        &harness.state,
        &client,
        "invalid_request",
        Some("bad request"),
        None,
    )
    .await
    .expect_err("rs256 error path must also fail");
    assert!(err.to_string().contains("RSA"));
}

#[tokio::test]
async fn error_jwt_carries_error_claims() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("jarm-err@example.com")
        .await
        .expect("create user");
    let client = client_with_alg(&harness, &user.id, None).await;

    let jwt = build_jarm_error_jwt(
        &harness.state,
        &client,
        "invalid_scope",
        Some("unknown scope"),
        Some("abc"),
    )
    .await
    .expect("build error jwt");

    let (header, payload) = decode_jwt_unverified(&jwt);
    assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
    assert_eq!(
        payload.get("error").and_then(Value::as_str),
        Some("invalid_scope")
    );
    assert_eq!(
        payload.get("error_description").and_then(Value::as_str),
        Some("unknown scope")
    );
    assert_eq!(payload.get("state").and_then(Value::as_str), Some("abc"));
}

#[tokio::test]
async fn error_jwt_omits_optional_fields() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("jarm-err-min@example.com")
        .await
        .expect("create user");
    let client = client_with_alg(&harness, &user.id, None).await;

    let jwt = build_jarm_error_jwt(&harness.state, &client, "access_denied", None, None)
        .await
        .expect("build minimal error jwt");

    let (_header, payload) = decode_jwt_unverified(&jwt);
    assert_eq!(
        payload.get("error").and_then(Value::as_str),
        Some("access_denied")
    );
    assert!(payload.get("error_description").is_none());
    assert!(payload.get("state").is_none());
}
