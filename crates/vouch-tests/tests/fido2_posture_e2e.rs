// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end FIDO2 assertion grant tests with device posture policies.
//!
//! These tests exercise the full `/oauth/fido2/challenge` → `/oauth/token`
//! (FIDO2 assertion grant) flow using the software `IntegrationMockDevice`,
//! with the OsRecency posture policy active. They verify that the bug fix
//! (comparing `os_build` instead of `os_version` for Windows) works
//! end-to-end through the real CEL evaluation path in `fido2_grant.rs`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, CreateAuthenticatorParams};
use vouch_tests::{IntegrationMockDevice, TestHarness};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a `private_key_jwt` client assertion (ES256 JWT) for the token endpoint.
fn build_client_assertion(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
    jti: Option<&str>,
) -> String {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)
        .expect("Failed to parse key");

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "test-key-1" });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 60,
        "jti": jti.map_or_else(|| uuid::Uuid::now_v7().to_string(), str::to_string)
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Create an OAuth client configured for `private_key_jwt` with inline JWKS.
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

    // Build JWKS from the public key
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
            name: "FIDO2 Grant Test Client".to_string(),
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

/// Register a mock FIDO2 device as an authenticator for a user in the DB.
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

/// Get a challenge + state JWT from the challenge endpoint.
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
    // Challenge is base64url-encoded
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_str)
        .expect("challenge must be valid base64url");
    (challenge, state)
}

/// Build the assertion payload and exchange it for an access token.
#[allow(clippy::too_many_arguments)]
async fn exchange_fido2_assertion(
    harness: &TestHarness,
    device: &IntegrationMockDevice,
    challenge: &[u8],
    state_jwt: &str,
    user_id: &str,
    client: &vouch_server::test_utils::TestOAuthClient,
    pkcs8: &[u8],
    authorization_details: Option<&str>,
) -> (u16, serde_json::Value) {
    // The mock device signs the assertion
    let auth_result = device
        .authenticate("test.example.com", challenge)
        .expect("Mock device authentication failed");

    // user_handle must be the UUID bytes of the user_id
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

    let mut body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
         &assertion={assertion}\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}"
    );
    if let Some(ad) = authorization_details {
        body.push_str(&format!(
            "&authorization_details={}",
            urlencoding::encode(ad)
        ));
    }

    let response = harness
        .post_form("/oauth/token", &body)
        .await
        .expect("Failed to post token");
    let status = response.status;
    let json: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Windows 11 24H2 with OsRecency active must successfully obtain a token.
///
/// Before the fix, the 4-component `os_version` ("10.0.26100.0") caused
/// `semver()` to error, which propagated through `||` and denied the grant.
/// After the fix, the policy compares `int(os_build) >= 26100`, which works.
#[tokio::test]
async fn test_fido2_grant_windows_24h2_os_recency_passes() {
    let harness = TestHarness::new().await;

    // Set up an org + user + authenticator
    let org = harness
        .create_org("windows-24h2.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("win-24h2@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    // Register the mock device in the DB
    let device = IntegrationMockDevice::new();
    let _auth_id = register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    // Activate the OsRecency preconfigured policy for this org
    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        vec!["os_recency".to_string()],
    )
    .await
    .expect("Failed to activate OsRecency");

    // Create a JWT client for private_key_jwt auth
    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;

    // Get a challenge
    let (challenge, state) = get_challenge(&harness).await;

    // Build Windows 11 24H2 posture (4-component os_version + os_build)
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "windows",
        "os_version": "10.0.26100.0",
        "os_build": "26100",
    }])
    .to_string();

    // Exchange the FIDO2 assertion with the posture data
    let (status, json) = exchange_fido2_assertion(
        &harness,
        &device,
        &challenge,
        &state,
        &user.id,
        &client,
        &pkcs8,
        Some(&posture_json),
    )
    .await;

    assert_eq!(
        status, 200,
        "Windows 11 24H2 FIDO2 grant with OsRecency must succeed. Response: {json}"
    );
    assert!(
        json.get("access_token").is_some(),
        "Should have access_token: {json}"
    );
}

/// Windows 11 23H2 (build 22631) with OsRecency active must be denied.
#[tokio::test]
async fn test_fido2_grant_windows_23h2_os_recency_denied() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("windows-23h2.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("win-23h2@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    let _auth_id = register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        vec!["os_recency".to_string()],
    )
    .await
    .expect("Failed to activate OsRecency");

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    // Windows 11 23H2 (build 22631) — below the 26100 threshold
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "windows",
        "os_version": "10.0.22631.0",
        "os_build": "22631",
    }])
    .to_string();

    let (status, json) = exchange_fido2_assertion(
        &harness,
        &device,
        &challenge,
        &state,
        &user.id,
        &client,
        &pkcs8,
        Some(&posture_json),
    )
    .await;

    assert_eq!(
        status, 400,
        "Windows 11 23H2 FIDO2 grant with OsRecency must be denied. Response: {json}"
    );
    let error = json["error"].as_str().unwrap_or("");
    assert!(
        error == "access_denied",
        "Expected access_denied, got: {error} (full: {json})"
    );
}

/// macOS 15 with OsRecency active must still pass (no regression).
#[tokio::test]
async fn test_fido2_grant_macos_15_os_recency_passes() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("macos-15.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("macos15@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    let _auth_id = register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        vec!["os_recency".to_string()],
    )
    .await
    .expect("Failed to activate OsRecency");

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    // macOS 15.3.1 posture — os_build is absent on macOS (not collected)
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "macos",
        "os_version": "15.3.1",
    }])
    .to_string();

    let (status, json) = exchange_fido2_assertion(
        &harness,
        &device,
        &challenge,
        &state,
        &user.id,
        &client,
        &pkcs8,
        Some(&posture_json),
    )
    .await;

    assert_eq!(
        status, 200,
        "macOS 15.3.1 FIDO2 grant with OsRecency must succeed (no regression). Response: {json}"
    );
    assert!(
        json.get("access_token").is_some(),
        "Should have access_token: {json}"
    );
}

/// FIDO2 grant with no posture data but OsRecency active must be denied
/// (posture data is required when policies are active).
#[tokio::test]
async fn test_fido2_grant_os_recency_no_posture_denied() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("no-posture.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("no-posture@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    let _auth_id = register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        vec!["os_recency".to_string()],
    )
    .await
    .expect("Failed to activate OsRecency");

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    // No authorization_details — posture data is required
    let (status, json) = exchange_fido2_assertion(
        &harness, &device, &challenge, &state, &user.id, &client, &pkcs8, None,
    )
    .await;

    assert_eq!(
        status, 400,
        "FIDO2 grant with OsRecency active but no posture data must be denied. Response: {json}"
    );
    let error = json["error"].as_str().unwrap_or("");
    assert!(
        error == "access_denied",
        "Expected access_denied, got: {error} (full: {json})"
    );
}
