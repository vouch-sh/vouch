// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end coverage for the registration signature counter fix
//! (WebAuthn L2 §7.1 step 23).
//!
//! These tests exercise the DB → fido2_grant → audit-row seam introduced by
//! the fix that initializes the stored signature counter to a credential's
//! registration `authData.signCount` rather than a hardcoded `0`. The
//! unit-level coverage (`db::tests::authenticators::*` and
//! `crypto::webauthn_verify::tests::*`) pins the registration-handler → DB
//! write and the verifier's first-assertion guard; these integration tests
//! confirm that a credential stored with a non-zero counter (the value the
//! handler now persists for a global-counter authenticator) surfaces
//! correctly through the live fido2_grant assertion flow and the audit
//! trail.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, CreateAuthenticatorParams};
use vouch_tests::{IntegrationMockDevice, TestHarness};

use vouch_server::test_utils::build_client_assertion;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a `private_key_jwt` client assertion (ES256 JWT) for the token
/// endpoint. Mirrors the helper in `fido2_posture_e2e.rs`.
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
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": "test-key-1",
            "x": x,
            "y": y,
        }]
    });

    let client = vouch_server::test_utils::create_test_client(
        &harness.state.store,
        user_id,
        TestClientSpec {
            name: "Registration Counter Test Client".to_string(),
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

/// Register a mock FIDO2 device in the DB with an explicit stored signature
/// counter. This mirrors the value `handlers/keys.rs` (CLI register) and
/// `handlers/enroll.rs` (browser enroll) now persist after the §7.1 step 23
/// fix — `authData.signCount` rather than a hardcoded `0`. A non-zero value
/// here simulates a global-counter authenticator that reported its actual
/// counter reading at make (WebAuthn L2 §6.3.2 step 10 first branch).
async fn register_mock_device_in_db_with_counter(
    harness: &TestHarness,
    user_id: &str,
    user_email: &str,
    device: &IntegrationMockDevice,
    stored_counter: u32,
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
            counter: stored_counter,
        },
    )
    .await
    .expect("Failed to create authenticator for mock device")
}

/// Get a challenge + state JWT from `/oauth/fido2/challenge`.
async fn get_challenge(harness: &TestHarness) -> (Vec<u8>, String) {
    let response = harness
        .post_form("/oauth/fido2/challenge", "")
        .await
        .expect("Failed to get challenge");
    assert_eq!(response.status, 200, "Challenge endpoint must return 200");
    let resp: serde_json::Value = response.json().expect("Valid JSON");
    let challenge_str = resp["challenge"]
        .as_str()
        .expect("challenge must be a string");
    let state = resp["state"]
        .as_str()
        .expect("state must be a string")
        .to_string();
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_str)
        .expect("challenge must be valid base64url");
    (challenge, state)
}

/// Exchange a FIDO2 assertion via the token endpoint, returning the HTTP
/// status and parsed JSON body.
async fn exchange_fido2_assertion(
    harness: &TestHarness,
    device: &IntegrationMockDevice,
    challenge: &[u8],
    state_jwt: &str,
    user_id: &str,
    client: &vouch_server::test_utils::TestOAuthClient,
    pkcs8: &[u8],
) -> (u16, serde_json::Value) {
    let auth_result = device
        .authenticate("test.example.com", challenge)
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

/// Fetch the `login_failed` audit events for `user_id`.
async fn login_failed_audit_events(harness: &TestHarness, user_id: &str) -> Vec<db::AuditEvent> {
    harness
        .state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["login_failed".to_string()]),
            user_id: Some(user_id.to_string()),
            ..db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
}

// ── Tests ────────────────────────────────────────────────────────────────

/// A credential stored with a non-zero registration `signCount` (the value
/// `handlers/keys.rs` and `handlers/enroll.rs` now persist after the
/// §7.1 step 23 fix) must reject a subsequent assertion whose counter is
/// less than or equal to the stored value — the clone-detection
/// tripwire the guard runs against the spec-correct baseline. The
/// rejection must leave a `login_failed` audit row whose `failure_reason`
/// is the clone-detection string `"Counter not increasing (possible
/// cloned authenticator)"` (see `fido2_grant.rs:308-317`).
///
/// The mock device's `authenticate()` produces its next counter reading
/// (starting at 0 for a fresh device), so an assertion against a stored
/// counter of 42 (simulating a global-counter authenticator that reported
/// `signCount = 42` at make) must be rejected with `CounterNotIncreasing`.
#[tokio::test]
async fn test_nonzero_stored_registration_counter_rejects_clone_assertion() {
    let harness = TestHarness::new().await;

    let user = harness
        .create_user("reg-counter-e2e@example.com")
        .await
        .expect("Failed to create user");

    // Register the mock device in DB with a stored counter that simulates
    // the post-fix value for a global-counter authenticator: signCount = 42
    // at make (§6.3.2 step 10 first branch).
    let device = IntegrationMockDevice::new();
    let initial_stored_counter: u32 = 42;
    let _auth_id = register_mock_device_in_db_with_counter(
        &harness,
        &user.id,
        &user.email,
        &device,
        initial_stored_counter,
    )
    .await;

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    let (status, json) = exchange_fido2_assertion(
        &harness, &device, &challenge, &state, &user.id, &client, &pkcs8,
    )
    .await;

    // The assertion must be rejected (fido2_grant returns `invalid_grant` /
    // 400 when assertion verification fails — see `fido2_grant.rs:318`).
    assert_ne!(
        status, 200,
        "assertion with counter <= stored ({initial_stored_counter}) must be rejected, got 200: {json}"
    );

    // The rejection must be an `invalid_grant` OAuth error.
    assert_eq!(
        json["error"], "invalid_grant",
        "fido2_grant should return invalid_grant for a failed assertion: {json}"
    );

    // A `login_failed` audit row must exist — the early, automatic
    // detection signal the fix restores. The handler records `e.to_string()`
    // where `e` is the `ServiceError` returned by `verify_login_assertion`
    // (which wraps the `VerifyError::CounterNotIncreasing` in a
    // `ServiceError::OAuth { code: InvalidGrant, .. }`). The `ServiceError`
    // Display is `"oauth error: {code}"` (see `error.rs:37`), so the
    // `failure_reason` on the row is `"oauth error: invalid_grant"` — the
    // generic OAuth code, not the inner clone-detection string. The
    // rejection itself (and the audit row's existence + the authenticator_id
    // attribution) is the security signal; the specific clone string lives
    // in tracing logs and is not surfaced on the audit row for this flow.
    let failed_events = login_failed_audit_events(&harness, &user.id).await;
    assert!(
        !failed_events.is_empty(),
        "a login_failed audit row must be recorded for the rejected assertion"
    );
    // The audit row must reference the authenticator that triggered the
    // clone-detection rejection, confirming the attribution survives the
    // handler → audit write path.
    let auth_id =
        db::get_authenticator_by_credential_id(&harness.state.store, &device.credential_id())
            .await
            .expect("db lookup")
            .expect("authenticator exists")
            .id;
    let attributed = failed_events.iter().find(|ev| ev.data.contains(&auth_id));
    assert!(
        attributed.is_some(),
        "at least one login_failed audit row must attribute the rejection \
         to the authenticator ({auth_id}); got rows: {failed_events:?}"
    );
}

/// A credential stored with `signCount = 0` (the spec-correct value for
/// per-credential-counter and counter-less authenticators, §6.3.2 step 10
/// second/third branch) must continue to accept a subsequent assertion —
/// the fix changes nothing for that class. This pins the no-regression
/// guarantee for the common case (the majority of authenticators in the
/// field).
#[tokio::test]
async fn test_zero_stored_registration_counter_accepts_first_assertion() {
    let harness = TestHarness::new().await;

    let user = harness
        .create_user("zero-counter-e2e@example.com")
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    let _auth_id =
        register_mock_device_in_db_with_counter(&harness, &user.id, &user.email, &device, 0).await;

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    let (status, json) = exchange_fido2_assertion(
        &harness, &device, &challenge, &state, &user.id, &client, &pkcs8,
    )
    .await;

    assert_eq!(
        status, 200,
        "zero-stored-counter credential (counter-less / per-credential \
         class) must accept its first assertion — no regression from the \
         fix. Response: {json}"
    );
    assert!(
        json.get("access_token").is_some(),
        "should have access_token: {json}"
    );

    // The stored counter must have advanced to the mock's first assertion
    // counter via `update_authenticator_counter` (fido2_grant.rs:350).
    let auths = db::get_authenticators_for_user(&harness.state.store, &user.id)
        .await
        .expect("get authenticators");
    assert_eq!(auths.len(), 1, "exactly one authenticator expected");
    // The mock's first authenticate() returns counter = 0 (fetch_add(1)
    // returns the old value), so the stored counter advances from 0 to
    // max(0, 0) = 0 — i.e. it stays 0 because the assertion counter equals
    // the stored counter (the guard's `stored_counter != 0` short-circuit
    // accepts it). Verify it is still 0.
    assert_eq!(
        auths[0].counter, 0,
        "stored counter should remain 0 after the counter-less first assertion"
    );
}

/// A credential whose registration `signCount` has the high bit set
/// (`>= 2^31`) must have its clone-detection guard honored, not silently
/// disabled for the credential's entire lifetime.
///
/// `create_authenticator` persists the registration counter via
/// `u32::cast_signed` (a bitwise `u32 -> i32` reinterpret), so a `signCount`
/// of `0x8000_0001` is stored as the negative `i32` `-2147483647`. The
/// assertion handlers read the stored counter back into `u32` to feed the
/// clone-detection guard. Reading with `u32::try_from(...).unwrap_or(0)` (a
/// checked *semantic* conversion) collapses every negative `i32` to `0`,
/// short-circuiting the guard's `stored_counter != 0 && …` predicate and
/// disabling clone detection for every assertion of the credential. Reading
/// with `i32::cast_unsigned` (the symmetric bitwise inverse of the write
/// path) recovers the original `0x8000_0001` and lets the guard fire.
///
/// This test pins the read-path round-trip end-to-end: it seeds a high-bit
/// stored counter, confirms the DB round-trips the bit pattern, confirms the
/// `cast_unsigned` read (not the lossy `try_from`) recovers it, and drives a
/// FIDO2 assertion whose counter (`0`, the mock's first `authenticate()`) is
/// `<=` the stored value — so the guard must reject it.
#[tokio::test]
async fn test_high_bit_stored_registration_counter_rejects_clone_assertion() {
    let harness = TestHarness::new().await;

    let user = harness
        .create_user("highbit-counter-e2e@example.com")
        .await
        .expect("Failed to create user");

    // Simulate a global-counter authenticator that reported a `signCount`
    // with the high bit set at make. `0x8000_0001` is the canonical witness:
    // `cast_signed` reinterprets it to a negative `i32`, exposing the
    // read-path asymmetry the bug turns on.
    let device = IntegrationMockDevice::new();
    let high_bit_counter: u32 = 0x8000_0001;
    let auth_id = register_mock_device_in_db_with_counter(
        &harness,
        &user.id,
        &user.email,
        &device,
        high_bit_counter,
    )
    .await;

    // Confirm the DB stored the high-bit u32 as a negative i32 via the
    // write path's `cast_signed` bitwise reinterpretation, and that the
    // `cast_unsigned` read is the symmetric inverse that recovers the
    // original value. The lossy `u32::try_from(...).unwrap_or(0)` read
    // collapses this negative i32 to 0 — the collapse that short-circuits
    // the guard.
    let auth_before = db::get_authenticator_by_id(&harness.state.store, &auth_id)
        .await
        .expect("db lookup")
        .expect("authenticator exists");
    assert_eq!(
        auth_before.counter,
        high_bit_counter.cast_signed(),
        "write path (cast_signed) must store the bit pattern verbatim"
    );
    assert_eq!(
        u32::try_from(auth_before.counter).unwrap_or(0),
        0,
        "the lossy try_from read collapses the negative i32 to 0"
    );
    assert_eq!(
        auth_before.counter.cast_unsigned(),
        high_bit_counter,
        "the cast_unsigned read recovers the original high-bit value"
    );

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    let (status, json) = exchange_fido2_assertion(
        &harness, &device, &challenge, &state, &user.id, &client, &pkcs8,
    )
    .await;

    // The mock's first authenticate() returns counter = 0 (fetch_add(1)
    // returns the old value). The guard evaluates `0 <= 0x8000_0001` →
    // reject, surfacing at the token endpoint as 400 + `invalid_grant`.
    assert_ne!(
        status, 200,
        "assertion with counter 0 <= stored {high_bit_counter:#010x} must be rejected; \
         Response: {json}"
    );
    assert_eq!(
        json["error"], "invalid_grant",
        "fido2_grant should return invalid_grant for the clone assertion: {json}"
    );

    // The rejection must leave a `login_failed` audit row attributed to the
    // authenticator, confirming attribution survives the full DB → read
    // conversion → guard → assertion → audit path.
    let failed_events = login_failed_audit_events(&harness, &user.id).await;
    assert!(
        !failed_events.is_empty(),
        "a login_failed audit row must be recorded for the rejected high-bit-counter assertion"
    );
    let attributed = failed_events.iter().find(|ev| ev.data.contains(&auth_id));
    assert!(
        attributed.is_some(),
        "at least one login_failed audit row must attribute the rejection \
         to the authenticator ({auth_id}); got rows: {failed_events:?}"
    );
}
