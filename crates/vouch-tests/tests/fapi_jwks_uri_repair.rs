// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A console update to a FAPI private_key_jwt client is judged on the key
//! material the client holds after the update. RFC 7592 §2.2: values "MUST
//! replace, not augment, the values previously associated with this client",
//! so a submitted jwks_uri replaces a stored inline JWKS.
#![expect(
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
)]

use vouch_server::db::{self, FapiProfile, TokenEndpointAuthMethod};
use vouch_server::test_utils::{
    self, TEST_JWK_EC_X, TEST_JWK_EC_Y, TEST_JWK_RSA_N, TestClientSpec, TestJwks, TestOAuthClient,
};
use vouch_tests::TestHarness;

fn rs256_only_jwks() -> serde_json::Value {
    serde_json::json!({"keys": [{
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "legacy-rsa",
        "n": TEST_JWK_RSA_N, "e": "AQAB"
    }]})
}

fn es256_jwks() -> serde_json::Value {
    serde_json::json!({"keys": [{
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "ec",
        "x": TEST_JWK_EC_X, "y": TEST_JWK_EC_Y
    }]})
}

async fn setup(h: &TestHarness, email: &str, jwks: serde_json::Value) -> (TestOAuthClient, String) {
    let (user, _auth, token) = h.create_authenticated_user(email).await.expect("user");
    let client = test_utils::create_test_client(
        &h.state.store,
        &user.id,
        TestClientSpec {
            fapi_profile: Some(FapiProfile::Fapi2Security),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Custom(jwks),
            dpop_bound_access_tokens: true,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    (client, token)
}

async fn patch(
    h: &TestHarness,
    client: &TestOAuthClient,
    token: &str,
    body: serde_json::Value,
) -> (u16, String) {
    let resp = h
        .patch_json_authenticated(
            &format!("/api/v1/applications/{}", client.app_id),
            &body,
            token,
        )
        .await
        .expect("request");
    (
        resp.status,
        String::from_utf8_lossy(&resp.body).into_owned(),
    )
}

/// Control A: replacing the stale RS256-only inline set with a valid ES256
/// inline set succeeds — setup (stale FAPI client, auth, route) is valid.
#[tokio::test]
async fn control_inline_repair_succeeds() {
    let h = TestHarness::new().await;
    let (client, token) = setup(&h, "ctl-inline@example.com", rs256_only_jwks()).await;
    let (status, body) = patch(
        &h,
        &client,
        &token,
        serde_json::json!({"jwks": es256_jwks().to_string()}),
    )
    .await;
    assert_eq!(status, 200, "inline repair should succeed: {body}");
}

/// Control B: a FAPI client with a *valid* inline set may switch to a
/// jwks_uri — the URI itself is acceptable to the endpoint.
#[tokio::test]
async fn control_jwks_uri_switch_on_healthy_client_succeeds() {
    let h = TestHarness::new().await;
    let (client, token) = setup(&h, "ctl-uri@example.com", es256_jwks()).await;
    let (status, body) = patch(
        &h,
        &client,
        &token,
        serde_json::json!({"jwks_uri": "https://client.example/jwks.json"}),
    )
    .await;
    assert_eq!(status, 200, "jwks_uri switch on healthy client: {body}");
}

/// Case: switching the stale RS256-only FAPI client to a jwks_uri must
/// succeed — the update replaces the stored inline set (it is dropped by
/// compute_fapi_update_fields), so the old set must not be validated.
#[tokio::test]
async fn jwks_uri_repair_of_stale_fapi_client_succeeds() {
    let h = TestHarness::new().await;
    let (client, token) = setup(&h, "case-uri@example.com", rs256_only_jwks()).await;
    let (status, body) = patch(
        &h,
        &client,
        &token,
        serde_json::json!({"jwks_uri": "https://client.example/jwks.json"}),
    )
    .await;
    assert_eq!(
        status, 200,
        "PATCH {{jwks_uri}} on a FAPI private_key_jwt client whose stored inline JWKS is \
         RS256-only must succeed: the jwks_uri replaces the stored set. body: {body}"
    );
    let persisted = db::get_oauth_client_by_id(&h.state.store, &client.app_id)
        .await
        .expect("db")
        .expect("exists");
    assert!(persisted.keys.as_ref().and_then(|k| k.uri()).is_some());
}

/// An edit that submits no keys leaves the stored inline set in force, so a
/// FAPI client whose stored set has no FAPI-usable key is still refused.
#[tokio::test]
async fn metadata_edit_keeps_judging_the_stored_set() {
    let h = TestHarness::new().await;
    let (client, token) = setup(&h, "case-meta@example.com", rs256_only_jwks()).await;
    let (status, body) = patch(&h, &client, &token, serde_json::json!({"name": "Renamed"})).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("fapi_jwks_algorithm_unsupported"), "{body}");
}
