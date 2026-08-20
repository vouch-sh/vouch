// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end verification that `policy_denied` audit records carry the
//! actual custom policy name (not the generic "custom") through the full
//! HTTP router path.
//!
//! These tests exercise the complete FIDO2 assertion grant flow
//! (`/oauth/fido2/challenge` → `/oauth/token`) with a custom posture policy
//! active, then read back the `policy_denied` audit event and verify its
//! `policy` JSON field. They also verify the user-facing error message and
//! the Prometheus metrics label.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db::{self, CreateAuthenticatorParams};
use vouch_tests::{IntegrationMockDevice, TestHarness};

use vouch_server::test_utils::build_client_assertion;

/// Create a `private_key_jwt` OAuth client for the token endpoint.
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
            name: "Audit Denial Test Client".to_string(),
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

/// Register a mock FIDO2 device as an authenticator for a user.
async fn register_mock_device(
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
    .expect("Failed to create authenticator")
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
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_str)
        .expect("challenge must be valid base64url");
    (challenge, state)
}

/// Exchange a FIDO2 assertion for an access token. Returns (status, json).
async fn exchange_assertion(
    harness: &TestHarness,
    device: &IntegrationMockDevice,
    challenge: &[u8],
    state_jwt: &str,
    user_id: &str,
    client: &vouch_server::test_utils::TestOAuthClient,
    pkcs8: &[u8],
    authorization_details: Option<&str>,
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

/// Poll the audit log for a `policy_denied` event for the given user.
/// The audit write happens inside `authorize_decision` (not spawned), so
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
    register_mock_device(&harness, &user.id, &user.email, &device).await;

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

    let (status, json) = exchange_assertion(
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
    register_mock_device(&harness, &user.id, &user.email, &device).await;

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

    let (status, json) = exchange_assertion(
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
