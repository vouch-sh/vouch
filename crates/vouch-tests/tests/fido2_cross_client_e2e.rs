// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end regression coverage for the FIDO2 assertion grant's
//! client-binding fix.
//!
//! Before the fix, the challenge state JWT carried no `client_id`, the
//! challenge endpoint was unauthenticated, and `exchange_fido2_assertion`
//! never compared the presenting client to the client that started the
//! ceremony. A captured `state` + `assertion` could therefore be redeemed
//! under any registered client that supports `fido2-assertion`, minting a
//! token with `sub = victim_user_id` and `aud`/`client_id =
//! attacker_client_id` — cross-client impersonation given a terminating
//! TLS-MITM position.
//!
//! These tests reproduce the attack end-to-end through the real HTTP layer
//! (open dynamic registration → challenge → CTAP2 assertion with the software
//! mock device → `/oauth/token`) and assert the FIXED behavior:
//!
//! - A cross-client redemption is rejected with `invalid_grant`.
//! - The rejected attempt does not consume the single-use state, so the
//!   legitimate client's subsequent redemption still succeeds (no denial of
//!   service from a "block-and-replay" MITM that submits first).
//! - The legitimate client's token is still minted with the correct,
//!   binding-bound claims (`sub = victim`, `aud`/`client_id = issuing client`,
//!   `hardware_verified = true`).
//!
//! The fix ships as a staged rollout: the challenge endpoint still accepts
//! an unauthenticated request — including the JSON `{}` body sent by CLI
//! versions built before this change — and mints a state JWT with no
//! `client_id`, which is redeemable by any registered client, exactly as
//! before the fix. `test_fido2_unauthenticated_legacy_challenge_still_works`
//! below covers that compatibility path.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, CreateAuthenticatorParams, TokenEndpointAuthMethod};
use vouch_server::test_utils::{
    self, TestClientSpec, TestJwks, TestOAuthClient, build_client_assertion,
};
use vouch_tests::{IntegrationMockDevice, TestHarness};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Generate an ES256 (P-256) key pair, returning (pkcs8_bytes, JWK public).
fn generate_es256_key() -> (Vec<u8>, serde_json::Value) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate ES256 key");
    let pkcs8 = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse ES256 key");
    let public_key_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&public_key_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&public_key_bytes[33..65]);
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": "test-key-1",
        "x": x,
        "y": y,
    });
    (pkcs8, jwk)
}

/// Open-register an attacker OAuth client via `POST /oauth/register` WITHOUT
/// a Bearer token (RFC 7591 open registration), configured for
/// `private_key_jwt` and the `fido2-assertion` grant with an inline JWKS
/// holding a freshly generated ES256 key. Returns `(client_id, pkcs8)` so
/// the test can sign `private_key_jwt` assertions for the attacker.
async fn register_attacker_client(harness: &TestHarness) -> (String, Vec<u8>) {
    let (pkcs8, jwk) = generate_es256_key();
    let body = serde_json::json!({
        "grant_types": ["urn:ietf:params:oauth:grant-type:fido2-assertion"],
        "response_types": [],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [jwk] },
        "client_name": "Attacker Client",
    });
    let resp = harness
        .post_json("/oauth/register", &body)
        .await
        .expect("open registration request");
    assert_eq!(
        resp.status,
        201,
        "Open registration must return 201: {}",
        resp.text().unwrap_or_default()
    );
    let json: serde_json::Value = resp.json().expect("Valid JSON");
    let client_id = json["client_id"]
        .as_str()
        .expect("client_id in registration response")
        .to_string();
    assert!(!client_id.is_empty(), "client_id must be non-empty");
    (client_id, pkcs8)
}

/// Register a mock FIDO2 device as an authenticator for a user in the DB.
async fn register_mock_device_in_db(
    harness: &TestHarness,
    user_id: &str,
    device: &IntegrationMockDevice,
    name: &str,
) {
    let user_handle = uuid::Uuid::parse_str(user_id)
        .expect("user_id must be a UUID")
        .as_bytes()
        .to_vec();
    db::create_authenticator(
        &harness.state.store,
        &CreateAuthenticatorParams {
            user_id,
            name,
            credential_id: &device.credential_id(),
            public_key: &device.inner_public_key_cose(),
            aaguid: None,
            user_handle: Some(&user_handle),
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("Failed to create authenticator for mock device");
}

/// A legitimately initiating OAuth client (the CLI's own registered client),
/// configured for `private_key_jwt` + `fido2-assertion` (the default
/// `grant_types` covers every grant) with an inline JWKS.
async fn create_legitimate_client(
    harness: &TestHarness,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8, jwk) = generate_es256_key();
    let client = test_utils::create_test_client(
        &harness.state.store,
        user_id,
        TestClientSpec {
            name: "Legitimate FIDO2 Client".to_string(),
            jwks: TestJwks::Custom(serde_json::json!({
                "keys": [jwk]
            })),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            ..Default::default()
        },
    )
    .await;
    (client, pkcs8)
}

/// Obtain a challenge + state JWT from `/oauth/fido2/challenge`,
/// authenticated as `client_id` via `private_key_jwt`.
async fn get_challenge(harness: &TestHarness, client_id: &str, pkcs8: &[u8]) -> (Vec<u8>, String) {
    let client_assertion = build_client_assertion(
        client_id,
        "https://test.example.com/oauth/token",
        pkcs8,
        None,
    );
    let body = format!(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}"
    );
    let resp = harness
        .post_form("/oauth/fido2/challenge", &body)
        .await
        .expect("challenge request");
    assert_eq!(
        resp.status,
        200,
        "challenge must succeed: {}",
        resp.text().unwrap_or_default()
    );
    let json: serde_json::Value = resp.json().expect("Valid JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(json["challenge"].as_str().expect("challenge"))
        .expect("base64url");
    let state = json["state"].as_str().expect("state").to_string();
    (challenge, state)
}

/// Obtain a challenge + state JWT from `/oauth/fido2/challenge` with no
/// client authentication at all — the JSON `{}` body the CLI sent before
/// this endpoint accepted `client_assertion` (see `vouch-cli`'s `login.rs`
/// before this fix).
async fn get_challenge_unauthenticated(harness: &TestHarness) -> (Vec<u8>, String) {
    let resp = harness
        .post_json("/oauth/fido2/challenge", &serde_json::json!({}))
        .await
        .expect("challenge request");
    assert_eq!(
        resp.status,
        200,
        "unauthenticated challenge must still succeed during the rollout: {}",
        resp.text().unwrap_or_default()
    );
    let json: serde_json::Value = resp.json().expect("Valid JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(json["challenge"].as_str().expect("challenge"))
        .expect("base64url");
    let state = json["state"].as_str().expect("state").to_string();
    (challenge, state)
}

/// Build the base64url-encoded `assertion` form parameter for `user_id`
/// signing `challenge` with `device`, referencing `state`.
fn build_assertion_param(
    device: &IntegrationMockDevice,
    challenge: &[u8],
    state: &str,
    user_id: &str,
) -> String {
    let auth_result = device
        .authenticate("test.example.com", challenge)
        .expect("mock device authentication");
    let user_handle = uuid::Uuid::parse_str(user_id)
        .expect("user_id must be a UUID")
        .as_bytes()
        .to_vec();
    let payload = serde_json::json!({
        "state": state,
        "credential_id": URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_result.authenticator_data),
        "signature": URL_SAFE_NO_PAD.encode(&auth_result.signature),
        "client_data_json": URL_SAFE_NO_PAD.encode(&auth_result.client_data_json),
        "user_handle": URL_SAFE_NO_PAD.encode(&user_handle),
    });
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("JSON encode"))
}

/// Redeem a FIDO2 assertion at `/oauth/token` authenticated as
/// `(client_id, pkcs8)`. Returns `(status, json_body)`.
async fn redeem_assertion(
    harness: &TestHarness,
    client_id: &str,
    pkcs8: &[u8],
    assertion: &str,
) -> (u16, serde_json::Value) {
    let client_assertion = build_client_assertion(
        client_id,
        "https://test.example.com/oauth/token",
        pkcs8,
        None,
    );
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
         &assertion={assertion}\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}"
    );
    let resp = harness
        .post_form("/oauth/token", &body)
        .await
        .expect("token request");
    let status = resp.status;
    let json: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Decode the payload of a JWT (used to inspect access-token claims).
fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert!(parts.len() >= 2, "access_token must be a JWT: {token}");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("JWT payload base64url");
    serde_json::from_slice(&payload).expect("JWT payload JSON")
}

// ── Tests ────────────────────────────────────────────────────────────────

/// A captured challenge+assertion cannot be redeemed under a different,
/// separately registered client. The attacker open-registers a
/// `private_key_jwt` × `fido2-assertion` client (RFC 7591, no Bearer),
/// captures the victim's `state` + `assertion`, and redeems under its own
/// client. The server must reject with `invalid_grant` and issue no token;
/// the legitimate victim can still redeem the same `state` + `assertion`
/// (the rejected attempt did not consume the single-use state).
#[tokio::test]
async fn test_fido2_cross_client_attacker_redeems_victim_assertion_rejected() {
    let harness = TestHarness::new().await;
    let victim = harness
        .create_user("victim-cross-client@example.com")
        .await
        .expect("create victim user");

    // Victim's registered authenticator + initiating client.
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &victim.id, &device, "Victim FIDO2 Key").await;
    let (victim_client, victim_pkcs8) = create_legitimate_client(&harness, &victim.id).await;

    // Attacker open-registers a separate client.
    let (attacker_client_id, attacker_pkcs8) = register_attacker_client(&harness).await;

    // Victim initiates the ceremony; the state is bound to the victim client.
    let (challenge, state) = get_challenge(&harness, &victim_client.client_id, &victim_pkcs8).await;
    let assertion = build_assertion_param(&device, &challenge, &state, &victim.id);

    // Attacker captures state+assertion and redeems under its OWN client.
    let (status, json) =
        redeem_assertion(&harness, &attacker_client_id, &attacker_pkcs8, &assertion).await;
    assert_eq!(
        status, 400,
        "Cross-client redemption must be rejected: {json}"
    );
    assert_eq!(
        json["error"], "invalid_grant",
        "Cross-client replay must return invalid_grant, got: {}",
        json["error"]
    );
    assert!(
        json.get("access_token").is_none(),
        "No access token must be issued on cross-client rejection: {json}"
    );

    // The legitimate victim can still redeem the same state+assertion: the
    // rejected cross-client attempt did not consume the single-use state.
    let (status_v, json_v) = redeem_assertion(
        &harness,
        &victim_client.client_id,
        &victim_pkcs8,
        &assertion,
    )
    .await;
    assert_eq!(status_v, 200, "victim redemption must succeed: {json_v}");
    let access_token = json_v["access_token"]
        .as_str()
        .expect("victim access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(claims["sub"], victim.id, "sub must be the victim: {claims}");
    assert_eq!(
        claims["client_id"].as_str(),
        Some(victim_client.client_id.as_str()),
        "client_id must be the victim's (issuing) client: {claims}"
    );
    assert_eq!(
        claims["aud"].as_str(),
        Some(victim_client.client_id.as_str()),
        "aud must default to the victim's client_id: {claims}"
    );
}

/// "Block-and-replay" timing: a TLS-MITM attacker withholds the victim's
/// `/oauth/token` request and submits its own first. The fix rejects the
/// attacker's first redemption (the state is bound to the victim's client),
/// so the victim's subsequently released request still succeeds — the
/// deterministic consume ordering the bug exploited no longer denies the
/// victim.
#[tokio::test]
async fn test_fido2_cross_client_block_and_replay_attacker_rejected_victim_succeeds() {
    let harness = TestHarness::new().await;
    let victim = harness
        .create_user("victim-block-replay@example.com")
        .await
        .expect("create victim user");
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &victim.id, &device, "Victim BR Key").await;
    let (victim_client, victim_pkcs8) = create_legitimate_client(&harness, &victim.id).await;
    let (attacker_client_id, attacker_pkcs8) = register_attacker_client(&harness).await;

    let (challenge, state) = get_challenge(&harness, &victim_client.client_id, &victim_pkcs8).await;
    let assertion = build_assertion_param(&device, &challenge, &state, &victim.id);

    // Attacker wins the ordering (submits first), but is rejected on binding.
    let (status_a, json_a) =
        redeem_assertion(&harness, &attacker_client_id, &attacker_pkcs8, &assertion).await;
    assert_eq!(
        status_a, 400,
        "attacker first redemption must be rejected: {json_a}"
    );
    assert_eq!(json_a["error"], "invalid_grant", "attacker: {json_a}");

    // Victim's withheld request, now released, succeeds.
    let (status_v, json_v) = redeem_assertion(
        &harness,
        &victim_client.client_id,
        &victim_pkcs8,
        &assertion,
    )
    .await;
    assert_eq!(
        status_v, 200,
        "victim redemption after attacker rejection must succeed: {json_v}"
    );
    assert!(
        json_v.get("access_token").is_some(),
        "victim must receive an access token: {json_v}"
    );
}

/// The legitimate FIDO2 grant (same client initiates and redeems) is
/// unchanged: a token is issued with `sub = user`, `aud`/`client_id =
/// issuing client`, and `hardware_verified = true`. Regression guard for the
/// happy path the cross-client tests pivot around.
#[tokio::test]
async fn test_fido2_same_client_grant_still_succeeds() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("fido2-happy@example.com")
        .await
        .expect("create user");
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &user.id, &device, "Happy Key").await;
    let (client, pkcs8) = create_legitimate_client(&harness, &user.id).await;

    let (challenge, state) = get_challenge(&harness, &client.client_id, &pkcs8).await;
    let assertion = build_assertion_param(&device, &challenge, &state, &user.id);

    let (status, json) = redeem_assertion(&harness, &client.client_id, &pkcs8, &assertion).await;
    assert_eq!(status, 200, "legitimate grant must succeed: {json}");
    let access_token = json["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(claims["sub"], user.id, "sub must be the user: {claims}");
    assert_eq!(
        claims["client_id"].as_str(),
        Some(client.client_id.as_str()),
        "client_id must be the issuing client: {claims}"
    );
    assert_eq!(
        claims["aud"].as_str(),
        Some(client.client_id.as_str()),
        "aud must default to the issuing client_id: {claims}"
    );
    assert_eq!(
        claims["hardware_verified"], true,
        "hardware_verified must be true: {claims}"
    );
}

/// A challenge issued to the victim's client cannot be redeemed by a client
/// that merely reuses the victim's `client_id` in its `private_key_jwt`
/// assertion without holding the victim's signing key: `authenticate_client_jwt`
/// verifies the assertion signature against the presented `client_id`'s JWKS,
/// so an attacker without the victim's private key fails at client auth
/// (`invalid_client`). This guards against a naive weakening where the
/// binding check alone is relied on without cryptographic client auth.
#[tokio::test]
async fn test_fido2_cross_client_attacker_cannot_spoof_victim_client_id() {
    let harness = TestHarness::new().await;
    let victim = harness
        .create_user("victim-spoof@example.com")
        .await
        .expect("create victim user");
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &victim.id, &device, "Victim Spoof Key").await;
    let (victim_client, _victim_pkcs8) = create_legitimate_client(&harness, &victim.id).await;
    let (_attacker_client_id, attacker_pkcs8) = register_attacker_client(&harness).await;

    let (challenge, state) =
        get_challenge(&harness, &victim_client.client_id, &_victim_pkcs8).await;
    let assertion = build_assertion_param(&device, &challenge, &state, &victim.id);

    // Attacker signs a private_key_jwt assertion with its OWN key but claims
    // iss/sub = the VICTIM's client_id. The server must reject: the victim's
    // JWKS does not contain the attacker's key.
    let forged_client_assertion = build_client_assertion(
        &victim_client.client_id,
        "https://test.example.com/oauth/token",
        &attacker_pkcs8,
        None,
    );
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
         &assertion={assertion}\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={forged_client_assertion}"
    );
    let resp = harness
        .post_form("/oauth/token", &body)
        .await
        .expect("token request");
    assert_eq!(
        resp.status,
        401,
        "Forged client_assertion must be rejected as invalid_client: {}",
        resp.text().unwrap_or_default()
    );
    let json: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        json["error"], "invalid_client",
        "spoofed client_id must return invalid_client, got: {}",
        json["error"]
    );
}

/// A challenge obtained with no client authentication at all (the JSON `{}`
/// body the CLI sent before this fix) mints a state JWT with no `client_id`,
/// so it is redeemable by any registered `fido2-assertion` client — the
/// exact pre-fix behavior, kept during this staged rollout for CLI
/// compatibility. The redeeming client here is registered separately from
/// whichever client (if any) the CLI would otherwise have used, which is the
/// point: with no `client_id` recorded on the challenge, there is nothing to
/// bind against.
#[tokio::test]
async fn test_fido2_unauthenticated_legacy_challenge_still_works() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("legacy-challenge@example.com")
        .await
        .expect("create user");
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &user.id, &device, "Legacy Key").await;
    let (client, pkcs8) = create_legitimate_client(&harness, &user.id).await;

    let (challenge, state) = get_challenge_unauthenticated(&harness).await;
    let assertion = build_assertion_param(&device, &challenge, &state, &user.id);

    let (status, json) = redeem_assertion(&harness, &client.client_id, &pkcs8, &assertion).await;
    assert_eq!(
        status, 200,
        "redemption of an unauthenticated-challenge state must still succeed: {json}"
    );
    let access_token = json["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(claims["sub"], user.id, "sub must be the user: {claims}");
    assert_eq!(
        claims["hardware_verified"], true,
        "hardware_verified must be true: {claims}"
    );
}
