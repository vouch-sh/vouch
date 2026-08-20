// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end FIDO2 assertion grant tests with device posture policies.
//!
//! These tests exercise the full `/oauth/fido2/challenge` → `/oauth/token`
//! (FIDO2 assertion grant) flow using the software `IntegrationMockDevice`,
//! with the OsRecency posture policy active. They verify that the bug fix
//! (comparing `os_build` instead of `os_version` for Windows) works
//! end-to-end through the policy gate in `fido2_grant.rs`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, CreateAuthenticatorParams};
use vouch_tests::{IntegrationMockDevice, TestHarness};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a `private_key_jwt` client assertion (ES256 JWT) for the token endpoint.
use vouch_server::test_utils::build_client_assertion;

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

/// Everything a FIDO2 assertion exchange needs, bundled so call sites read
/// as named fields instead of eight positional arguments.
struct AssertionExchange<'a> {
    harness: &'a TestHarness,
    device: &'a IntegrationMockDevice,
    challenge: &'a [u8],
    state_jwt: &'a str,
    user_id: &'a str,
    client: &'a vouch_server::test_utils::TestOAuthClient,
    pkcs8: &'a [u8],
    authorization_details: Option<&'a str>,
}

/// Build the assertion payload and exchange it for an access token.
async fn exchange_fido2_assertion(
    AssertionExchange {
        harness,
        device,
        challenge,
        state_jwt,
        user_id,
        client,
        pkcs8,
        authorization_details,
    }: AssertionExchange<'_>,
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
    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
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

    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
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

    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
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
    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: None,
    })
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

/// A successful FIDO2 grant records an `oauth_token_issued` audit event
/// carrying the user id and grant type.
#[tokio::test]
async fn test_fido2_grant_records_token_issued_audit_event() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("issued-audit@example.com")
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    let _auth_id = register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;
    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: None,
    })
    .await;
    assert_eq!(status, 200, "FIDO2 grant must succeed: {json}");

    let rows = harness
        .state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["oauth_token_issued".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(
        rows.len(),
        1,
        "the grant must write exactly one oauth_token_issued row"
    );
    assert!(
        rows[0].data.contains("fido2-assertion"),
        "the audit payload must carry the grant type: {}",
        rows[0].data
    );
}

/// A posture-denied grant records `login_failed`, never `login_success` —
/// temporal step-up policies treat `login_success` as proof of a completed,
/// policy-compliant hardware login, so the denied attempt must not refresh
/// the recency window on the token-exchange path.
#[tokio::test]
async fn test_posture_denied_grant_records_login_failed_not_success() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("denied-audit.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("denied-audit@example.com", &org.id, false)
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

    // Windows 23H2 fails the os_recency floor (build < 26100).
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "windows",
        "os_version": "10.0.22631.0",
        "os_build": "22631",
    }])
    .to_string();
    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
    .await;
    assert_eq!(status, 400, "grant must be denied: {json}");

    // The audit write is spawned; poll briefly for it to land.
    let query = |kind: &'static str| {
        let audit = harness.state.audit.clone();
        let user_id = user.id.clone();
        async move {
            audit
                .query_events(&db::AuditEventFilter {
                    event_types: Some(vec![kind.to_string()]),
                    user_id: Some(user_id),
                    ..Default::default()
                })
                .await
                .expect("query audit events")
        }
    };
    let mut failed_rows = Vec::new();
    for _ in 0..40 {
        failed_rows = query("login_failed").await;
        if !failed_rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        failed_rows.len(),
        1,
        "denied attempt must record login_failed"
    );
    assert!(
        failed_rows[0].data.contains("posture policy denied"),
        "failure reason must name the posture policy: {}",
        failed_rows[0].data
    );
    let success_rows = query("login_success").await;
    assert!(
        success_rows.is_empty(),
        "denied attempt must not record login_success"
    );
}

/// it should be visible immediately, but we poll briefly for safety.
async fn poll_policy_denied_audit(harness: &TestHarness, user_id: &str) -> db::AuditEvent {
    for _ in 0..40 {
        let rows = harness
            .state
            .audit
            .query_events(&db::AuditEventFilter {
                event_types: Some(vec!["policy_denied".to_string()]),
                user_id: Some(user_id.to_string()),
                ..Default::default()
            })
            .await
            .expect("query audit events");
        if !rows.is_empty() {
            return rows.into_iter().next().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no policy_denied audit event found for user {user_id}");
}

/// A custom posture policy deny through the full HTTP router must record the
/// actual policy name in the `policy_denied` audit event — not the generic
/// "custom" label. The user-facing error must also name the policy.
#[tokio::test]
async fn custom_policy_denial_records_name_in_audit_and_error() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("custom-audit.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("custom-audit@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    // Create and activate a custom posture policy with a distinctive name.
    let policy = db::create_custom_policy(
        &harness.state.store,
        db::CreateCustomPolicyParams {
            name: "Test Audit Policy",
            description: None,
            policy_text: "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.disk_encryption_enabled };",
            org_id: &org.id,
            builder_spec: None,
        },
    )
    .await
    .expect("Failed to create custom policy");
    db::update_custom_policy(
        &harness.state.store,
        &policy.id,
        &org.id,
        db::UpdateCustomPolicyParams {
            name: None,
            description: db::FieldUpdate::Keep,
            policy_text: None,
            active: Some(true),
            builder_spec: db::FieldUpdate::Keep,
        },
    )
    .await
    .expect("Failed to activate custom policy");

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    // Posture without disk encryption → denied by the custom policy.
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "macos",
        "os_version": "15.3.1",
        "disk_encryption_enabled": false,
    }])
    .to_string();

    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
    .await;

    assert_eq!(
        status, 400,
        "FIDO2 grant must be denied by custom policy. Response: {json}"
    );
    assert!(
        json["error"].as_str() == Some("access_denied"),
        "Expected access_denied error, got: {json}"
    );

    // Step 4: Verify the audit record carries the actual policy name.
    let audit_row = poll_policy_denied_audit(&harness, &user.id).await;
    let audit_data: serde_json::Value =
        serde_json::from_str(&audit_row.data).expect("audit data is valid JSON");
    assert_eq!(
        audit_data["policy"].as_str(),
        Some("Test Audit Policy"),
        "audit record must carry the actual custom policy name, not 'custom': {}",
        audit_data
    );
    assert_eq!(
        audit_data["action"].as_str(),
        Some("issue_token"),
        "audit record must carry the issue_token action: {}",
        audit_data
    );

    // Step 5: Verify the user-facing error message also names the policy.
    let error_description = json["error_description"].as_str().unwrap_or("");
    assert!(
        error_description.contains("Test Audit Policy"),
        "user-facing error must name the custom policy 'Test Audit Policy', got: {error_description}"
    );

    // Step 6: Verify Prometheus metrics used the generic "custom" label.
    let handle = vouch_server::infra::metrics::install_recorder().expect("prometheus recorder");
    let metrics_text = handle.render();
    assert!(
        metrics_text.contains("vouch_policy_decisions_total"),
        "metrics must include vouch_policy_decisions_total, got:\n{metrics_text}"
    );
    assert!(
        metrics_text.contains(r#"outcome="deny""#) && metrics_text.contains(r#"policy="custom""#),
        "metrics must record the deny with the generic 'custom' label (cardinality control), got:\n{metrics_text}"
    );
}

/// A preconfigured policy deny through the full HTTP router must record the
/// slug in the audit record, and metrics must use the same slug.
#[tokio::test]
async fn preconfigured_policy_denial_records_slug_in_audit_and_metrics() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("preconfigured-audit.example.com")
        .await
        .expect("Failed to create org");
    let user = harness
        .create_user_in_org("preconfigured-audit@example.com", &org.id, false)
        .await
        .expect("Failed to create user");

    let device = IntegrationMockDevice::new();
    register_mock_device_in_db(&harness, &user.id, &user.email, &device).await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org.id,
        vec!["disk_encryption".to_string()],
    )
    .await
    .expect("Failed to activate disk_encryption");

    let (client, pkcs8) = create_jwt_client(&harness, &user.id).await;
    let (challenge, state) = get_challenge(&harness).await;

    // Posture without disk encryption → denied by the preconfigured policy.
    let posture_json = serde_json::json!([{
        "type": "device_posture",
        "posture_version": 1,
        "os": "macos",
        "os_version": "15.3.1",
        "disk_encryption_enabled": false,
    }])
    .to_string();

    let (status, json) = exchange_fido2_assertion(AssertionExchange {
        harness: &harness,
        device: &device,
        challenge: &challenge,
        state_jwt: &state,
        user_id: &user.id,
        client: &client,
        pkcs8: &pkcs8,
        authorization_details: Some(&posture_json),
    })
    .await;

    assert_eq!(
        status, 400,
        "FIDO2 grant must be denied by disk_encryption. Response: {json}"
    );

    // Verify the audit record carries the slug.
    let audit_row = poll_policy_denied_audit(&harness, &user.id).await;
    let audit_data: serde_json::Value =
        serde_json::from_str(&audit_row.data).expect("audit data is valid JSON");
    assert_eq!(
        audit_data["policy"].as_str(),
        Some("disk_encryption"),
        "audit record must carry the preconfigured slug, not a generic label: {}",
        audit_data
    );

    // Verify metrics use the slug too.
    let handle = vouch_server::infra::metrics::install_recorder().expect("prometheus recorder");
    let metrics_text = handle.render();
    assert!(
        metrics_text.contains(r#"outcome="deny""#)
            && metrics_text.contains(r#"policy="disk_encryption""#),
        "metrics must record the deny with the preconfigured slug label, got:\n{metrics_text}"
    );
}
