// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end tests for Dogwood temporal policies over real audit history.
//!
//! Aggregation policies (`failed_login_burst`, `issuance_rate_limit`) gate
//! the FIDO2 assertion grant; recency/absence/correlation policies
//! (`token_exchange_step_up`, `logout_invalidates_exchange`,
//! `exchange_ip_consistency`) gate RFC 8693 token exchange — the WIF/agent
//! credential path, which arrives without a fresh hardware login.
//!
//! History is seeded through `AuditStore::insert_user_event_for_test`
//! (backdated rows), then the per-org engine replays it on first decision.
//! Each scenario uses its own harness so engine state never leaks between
//! tests. FIDO2 helper plumbing is duplicated from `fido2_posture_e2e.rs`
//! (test files are separate binaries).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, AuditEventKind, CreateAuthenticatorParams};
use vouch_server::test_utils::build_client_assertion;
use vouch_tests::{IntegrationMockDevice, TestHarness};

// ── Shared helpers ───────────────────────────────────────────────────────

/// Seed a backdated audit event for a user (the temporal history source).
async fn seed_event(
    harness: &TestHarness,
    kind: AuditEventKind,
    user_id: &str,
    secs_ago: i64,
    data: &str,
) {
    let ts = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().seconds(secs_ago))
        .expect("timestamp arithmetic");
    harness
        .state
        .audit
        .insert_user_event_for_test(kind, user_id, ts, data)
        .await
        .expect("seed audit event");
}

/// Assert an OAuth error response is a policy denial.
fn assert_access_denied(status: u16, json: &serde_json::Value, context: &str) {
    assert_eq!(status, 400, "{context}: expected denial. Response: {json}");
    assert_eq!(
        json["error"].as_str().unwrap_or(""),
        "access_denied",
        "{context}: expected access_denied. Response: {json}"
    );
}

// ── Token-exchange scenario harness ──────────────────────────────────────

/// Create an org (with the given active temporal slugs), a user in it, and
/// a directly-minted session token (no FIDO2 grant → no `login_success`
/// audit row — the "stale/absent login" starting point exchange policies
/// care about).
async fn exchange_scenario(
    slugs: &[&str],
    domain: &str,
    email: &str,
) -> (TestHarness, db::User, String, String) {
    let harness = TestHarness::new().await;
    let org = harness.create_org(domain).await.expect("create org");
    let user = harness
        .create_user_in_org(email, &org.id, false)
        .await
        .expect("create user");
    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        slugs.iter().map(ToString::to_string).collect(),
    )
    .await
    .expect("activate temporal slugs");
    let auth_id = harness
        .create_authenticator(&user.id)
        .await
        .expect("authenticator");
    let token = harness
        .create_session(&user.id, email, &auth_id)
        .await
        .expect("session token");
    let client = harness
        .create_oauth_client(&user.id)
        .await
        .expect("oauth client");
    let auth_header = client.basic_auth_header();
    (harness, user, token, auth_header)
}

async fn do_exchange(
    harness: &TestHarness,
    subject_token: &str,
    auth_header: &str,
) -> (u16, serde_json::Value) {
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={subject_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
    );
    let response = harness
        .post_form_with_auth("/oauth/token", &body, auth_header)
        .await
        .expect("post token exchange");
    let status = response.status;
    let json: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ── Token exchange: step-up recency ──────────────────────────────────────

/// No hardware login on record → exchange is denied.
#[tokio::test]
async fn test_exchange_step_up_denies_without_recent_login() {
    let (harness, _user, token, auth) = exchange_scenario(
        &["token_exchange_step_up"],
        "stepup-none.example.com",
        "stepup-none@example.com",
    )
    .await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_access_denied(status, &json, "exchange without any login history");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("Token Exchange Step-Up"),
        "denial must name the policy: {json}"
    );
}

/// A successful login 5 minutes ago satisfies the 15-minute window.
#[tokio::test]
async fn test_exchange_step_up_allows_with_fresh_login() {
    let (harness, user, token, auth) = exchange_scenario(
        &["token_exchange_step_up"],
        "stepup-fresh.example.com",
        "stepup-fresh@example.com",
    )
    .await;
    seed_event(&harness, AuditEventKind::LoginSuccess, &user.id, 300, "{}").await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_eq!(status, 200, "fresh login must allow exchange: {json}");
    assert!(
        json.get("access_token").is_some(),
        "exchange must issue a token: {json}"
    );
}

/// A login 30 minutes ago is outside the 15-minute window → denied.
#[tokio::test]
async fn test_exchange_step_up_denies_with_stale_login() {
    let (harness, user, token, auth) = exchange_scenario(
        &["token_exchange_step_up"],
        "stepup-stale.example.com",
        "stepup-stale@example.com",
    )
    .await;
    seed_event(&harness, AuditEventKind::LoginSuccess, &user.id, 1800, "{}").await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_access_denied(status, &json, "exchange with a 30-minute-old login");
}

/// Another user's fresh login must not satisfy this user's window
/// (per-principal history slicing).
#[tokio::test]
async fn test_exchange_step_up_ignores_other_users_logins() {
    let (harness, _user, token, auth) = exchange_scenario(
        &["token_exchange_step_up"],
        "stepup-other.example.com",
        "stepup-other@example.com",
    )
    .await;
    let org = harness
        .create_org("stepup-other2.example.com")
        .await
        .expect("org2");
    let other = harness
        .create_user_in_org("stepup-other-b@example.com", &org.id, false)
        .await
        .expect("other user");
    seed_event(&harness, AuditEventKind::LoginSuccess, &other.id, 60, "{}").await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_access_denied(status, &json, "another principal's login must not count");
}

// ── Token exchange: logout invalidates ───────────────────────────────────

/// login → logout → exchange is denied (the negated-left `since` idiom).
#[tokio::test]
async fn test_logout_invalidates_exchange_denies_after_logout() {
    let (harness, user, token, auth) = exchange_scenario(
        &["logout_invalidates_exchange"],
        "logout-deny.example.com",
        "logout-deny@example.com",
    )
    .await;
    seed_event(&harness, AuditEventKind::LoginSuccess, &user.id, 600, "{}").await;
    seed_event(&harness, AuditEventKind::Logout, &user.id, 300, "{}").await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_access_denied(status, &json, "exchange after logout");
}

/// logout → re-login → exchange is allowed again.
#[tokio::test]
async fn test_logout_invalidates_exchange_allows_after_relogin() {
    let (harness, user, token, auth) = exchange_scenario(
        &["logout_invalidates_exchange"],
        "logout-relogin.example.com",
        "logout-relogin@example.com",
    )
    .await;
    seed_event(&harness, AuditEventKind::Logout, &user.id, 600, "{}").await;
    seed_event(&harness, AuditEventKind::LoginSuccess, &user.id, 300, "{}").await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_eq!(
        status, 200,
        "re-login after logout must allow exchange: {json}"
    );
}

// ── Token exchange: IP consistency ───────────────────────────────────────

/// The test harness connects from 127.0.0.1; a login recorded from the
/// same address satisfies the correlation pin.
#[tokio::test]
async fn test_exchange_ip_consistency_allows_same_ip() {
    let (harness, user, token, auth) = exchange_scenario(
        &["exchange_ip_consistency"],
        "ip-same.example.com",
        "ip-same@example.com",
    )
    .await;
    seed_event(
        &harness,
        AuditEventKind::LoginSuccess,
        &user.id,
        300,
        r#"{"client_ip":"127.0.0.1"}"#,
    )
    .await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_eq!(status, 200, "same-IP login must allow exchange: {json}");
}

/// A login from a different network does not satisfy the pin → denied.
#[tokio::test]
async fn test_exchange_ip_consistency_denies_different_ip() {
    let (harness, user, token, auth) = exchange_scenario(
        &["exchange_ip_consistency"],
        "ip-diff.example.com",
        "ip-diff@example.com",
    )
    .await;
    seed_event(
        &harness,
        AuditEventKind::LoginSuccess,
        &user.id,
        300,
        r#"{"client_ip":"10.9.9.9"}"#,
    )
    .await;
    let (status, json) = do_exchange(&harness, &token, &auth).await;
    assert_access_denied(status, &json, "different-IP login must not satisfy the pin");
}

// ── FIDO2 grant: aggregation policies ────────────────────────────────────
//
// The helpers below are duplicated from fido2_posture_e2e.rs (separate
// test binaries cannot share modules without a support-crate refactor).

async fn create_jwt_client(
    harness: &TestHarness,
    user_id: &str,
) -> (vouch_server::test_utils::TestOAuthClient, Vec<u8>) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use vouch_server::test_utils::{TestClientSpec, TestJwks};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate ES256 key");
    let pkcs8 = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse ES256 key");
    let public_key_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&public_key_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&public_key_bytes[33..65]);
    let jwks = serde_json::json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "test-key-1", "x": x, "y": y }]
    });
    let client = vouch_server::test_utils::create_test_client(
        &harness.state.store,
        user_id,
        TestClientSpec {
            name: "Temporal E2E Client".to_string(),
            jwks: TestJwks::Custom(jwks),
            token_endpoint_auth_method: Some(
                vouch_server::db::TokenEndpointAuthMethod::PrivateKeyJwt,
            ),
            ..Default::default()
        },
    )
    .await;
    (client, pkcs8)
}

async fn register_mock_device_in_db(
    harness: &TestHarness,
    user_id: &str,
    user_email: &str,
    device: &IntegrationMockDevice,
) -> String {
    let user_handle = uuid::Uuid::parse_str(user_id)
        .expect("user_id must be a UUID")
        .as_bytes()
        .to_vec();
    db::create_authenticator(
        &harness.state.store,
        &CreateAuthenticatorParams {
            user_id,
            user_email,
            name: "Mock FIDO2 Key",
            credential_id: &device.credential_id(),
            public_key: &device.inner_public_key_cose(),
            aaguid: None,
            user_handle: Some(&user_handle),
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator for mock device")
}

async fn get_challenge(harness: &TestHarness) -> (Vec<u8>, String) {
    let response = harness
        .post_form("/oauth/fido2/challenge", "")
        .await
        .expect("Failed to get challenge");
    assert_eq!(response.status, 200);
    let resp: serde_json::Value = response.json().expect("Valid JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(resp["challenge"].as_str().expect("challenge"))
        .expect("challenge base64url");
    (
        challenge,
        resp["state"].as_str().expect("state").to_string(),
    )
}

/// Run the FIDO2 assertion grant (no posture — temporal-only orgs must not
/// demand posture data) and return (status, body).
async fn fido2_grant(
    harness: &TestHarness,
    device: &IntegrationMockDevice,
    user_id: &str,
    client: &vouch_server::test_utils::TestOAuthClient,
    pkcs8: &[u8],
) -> (u16, serde_json::Value) {
    let (challenge, state_jwt) = get_challenge(harness).await;
    let auth_result = device
        .authenticate("test.example.com", &challenge)
        .expect("Mock device authentication failed");
    let user_handle = uuid::Uuid::parse_str(user_id)
        .expect("user_id must be a UUID")
        .as_bytes()
        .to_vec();
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_result.authenticator_data),
        "signature": URL_SAFE_NO_PAD.encode(&auth_result.signature),
        "client_data_json": URL_SAFE_NO_PAD.encode(&auth_result.client_data_json),
        "user_handle": URL_SAFE_NO_PAD.encode(&user_handle),
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));
    let client_assertion = build_client_assertion(
        &client.client_id,
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
    let response = harness
        .post_form("/oauth/token", &body)
        .await
        .expect("Failed to post token");
    let status = response.status;
    let json: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Full FIDO2-grant scenario setup for aggregation policies.
async fn grant_scenario(
    slugs: &[&str],
    domain: &str,
    email: &str,
) -> (
    TestHarness,
    db::User,
    IntegrationMockDevice,
    vouch_server::test_utils::TestOAuthClient,
    Vec<u8>,
) {
    let harness = TestHarness::new().await;
    let org = harness.create_org(domain).await.expect("create org");
    let user = harness
        .create_user_in_org(email, &org.id, false)
        .await
        .expect("create user");
    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        slugs.iter().map(ToString::to_string).collect(),
    )
    .await
    .expect("activate slugs");
    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;
    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    (harness, user, device, client, pkcs8)
}

/// Five failed logins in the last ten minutes deny the FIDO2 grant.
#[tokio::test]
async fn test_failed_login_burst_denies_grant() {
    let (harness, user, device, client, pkcs8) = grant_scenario(
        &["failed_login_burst"],
        "burst-deny.example.com",
        "burst-deny@example.com",
    )
    .await;
    for i in 0..5_i64 {
        seed_event(
            &harness,
            AuditEventKind::LoginFailed,
            &user.id,
            120 + i,
            "{}",
        )
        .await;
    }
    let (status, json) = fido2_grant(&harness, &device, &user.id, &client, &pkcs8).await;
    assert_access_denied(status, &json, "5 failed logins in 10m");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("Failed Login Burst"),
        "denial must name the policy: {json}"
    );
}

/// Four failed logins stay under the threshold — the grant succeeds, and
/// no posture data is required for a temporal-only org.
#[tokio::test]
async fn test_failed_login_burst_under_threshold_allows_grant() {
    let (harness, user, device, client, pkcs8) = grant_scenario(
        &["failed_login_burst"],
        "burst-allow.example.com",
        "burst-allow@example.com",
    )
    .await;
    for i in 0..4_i64 {
        seed_event(
            &harness,
            AuditEventKind::LoginFailed,
            &user.id,
            120 + i,
            "{}",
        )
        .await;
    }
    let (status, json) = fido2_grant(&harness, &device, &user.id, &client, &pkcs8).await;
    assert_eq!(
        status, 200,
        "4 failures must stay under the burst cap: {json}"
    );
    assert!(
        json.get("access_token").is_some(),
        "must issue a token: {json}"
    );
}

/// Ten issuances in the last hour trip the rate limit.
#[tokio::test]
async fn test_issuance_rate_limit_denies_at_cap() {
    let (harness, user, device, client, pkcs8) = grant_scenario(
        &["issuance_rate_limit"],
        "rate-deny.example.com",
        "rate-deny@example.com",
    )
    .await;
    for i in 0..10_i64 {
        seed_event(
            &harness,
            AuditEventKind::OauthTokenIssued,
            &user.id,
            600 + i,
            "{}",
        )
        .await;
    }
    let (status, json) = fido2_grant(&harness, &device, &user.id, &client, &pkcs8).await;
    assert_access_denied(status, &json, "10 issuances in 1h");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("Issuance Rate Limit"),
        "denial must name the policy: {json}"
    );
}

/// Nine issuances stay under the cap; the tenth token is granted — and the
/// grant itself writes an `oauth_token_issued` row (the audit write added
/// for exactly this policy).
#[tokio::test]
async fn test_issuance_rate_limit_under_cap_allows_and_records() {
    let (harness, user, device, client, pkcs8) = grant_scenario(
        &["issuance_rate_limit"],
        "rate-allow.example.com",
        "rate-allow@example.com",
    )
    .await;
    for i in 0..9_i64 {
        seed_event(
            &harness,
            AuditEventKind::OauthTokenIssued,
            &user.id,
            600 + i,
            "{}",
        )
        .await;
    }
    let (status, json) = fido2_grant(&harness, &device, &user.id, &client, &pkcs8).await;
    assert_eq!(status, 200, "9 issuances must stay under the cap: {json}");

    // The successful grant recorded its own issuance.
    let rows = harness
        .state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["oauth_token_issued".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit");
    assert_eq!(
        rows.len(),
        10,
        "the FIDO2 grant must write an oauth_token_issued audit row"
    );
}
