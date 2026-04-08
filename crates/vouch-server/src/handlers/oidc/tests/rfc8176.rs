// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8176 — AMR/ACR Values tests.

use super::helpers::*;

// ============================================================================
// RFC 8176 — AMR/ACR Claim Presence
// ============================================================================

#[tokio::test]
async fn test_rfc8176_amr_in_access_token() {
    // RFC 8176 / RFC 9068 Section 2.2: Access token must contain amr claim
    // with FIDO2 authentication methods.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "amr-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // amr must be present and be a JSON array
    let amr = claims.get("amr").expect("amr claim must be present");
    assert!(amr.is_array(), "amr must be a JSON array, not a string");

    let amr_values: Vec<&str> = amr
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    // RFC 8176: FIDO2 authentication produces hwk, pin, user
    assert!(
        amr_values.contains(&"hwk"),
        "amr should contain 'hwk' (hardware key)"
    );
    assert!(amr_values.contains(&"pin"), "amr should contain 'pin'");
    assert!(
        amr_values.contains(&"user"),
        "amr should contain 'user' (user presence)"
    );
}

#[tokio::test]
async fn test_rfc8176_acr_in_access_token() {
    // RFC 9068 Section 2.2: Access token should contain acr claim
    // indicating NIST AAL3 for FIDO2 hardware authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    let acr = claims
        .get("acr")
        .expect("acr claim must be present")
        .as_str()
        .expect("acr is a string");

    assert_eq!(
        acr, "urn:nist:authentication:assurance-level:aal3",
        "FIDO2 hardware auth should produce AAL3 acr"
    );
}

#[tokio::test]
async fn test_rfc8176_amr_claim_format_in_access_token() {
    // RFC 8176: FIDO2-issued access tokens should include amr claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "amr-at@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // amr should be present for FIDO2 tokens
    if let Some(amr) = claims.get("amr") {
        assert!(amr.is_array(), "amr must be a JSON array, got: {amr}");
        let amr_values: Vec<&str> = amr
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        // FIDO2 tokens should include "hwk" (hardware key)
        assert!(
            amr_values.contains(&"hwk"),
            "FIDO2 token amr should include 'hwk', got: {amr_values:?}"
        );
    }
}

#[tokio::test]
async fn test_rfc8176_acr_claim_type_in_access_token() {
    // RFC 8176: FIDO2-issued access tokens should include acr claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "acr-at@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // acr should be present for FIDO2 tokens
    if let Some(acr) = claims.get("acr") {
        assert!(acr.is_string(), "acr must be a string, got: {acr}");
    }
}

// ============================================================================
// RFC 8176 — AMR/ACR Validation
// ============================================================================

#[tokio::test]
async fn test_rfc8176_amr_values_are_rfc8176_registered() {
    // RFC 8176 Section 2: AMR values must be from the IANA registry.
    // For FIDO2 authentication, only "hwk", "pin", and "user" are valid.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "amr-registered@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);
    let amr = claims["amr"].as_array().expect("amr must be a JSON array");

    let registered_values = [
        "face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin", "pop", "pwd",
        "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia",
    ];

    for value in amr {
        let v = value.as_str().expect("AMR value must be a string");
        assert!(
            registered_values.contains(&v),
            "AMR value '{v}' is not in the RFC 8176 IANA registry"
        );
    }
}

#[tokio::test]
async fn test_rfc8176_amr_is_array_not_string() {
    // RFC 8176: The amr claim MUST be a JSON array of strings,
    // even when there is only one authentication method.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "amr-array@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);
    let amr = claims.get("amr").expect("amr claim must be present");

    assert!(
        amr.is_array(),
        "RFC 8176: amr must be a JSON array, not a string. Got: {amr}"
    );
    assert!(
        !amr.as_array().unwrap().is_empty(),
        "amr array must not be empty for FIDO2 authentication"
    );

    // Every element must be a string
    for (i, val) in amr.as_array().unwrap().iter().enumerate() {
        assert!(val.is_string(), "amr[{i}] must be a string, got: {val}");
    }
}

#[tokio::test]
async fn test_rfc8176_id_token_amr_matches_access_token() {
    // AMR/ACR claims must be consistent between ID token and access token
    // when both are issued from the same authorization code exchange.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "amr-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let at_claims = decode_jwt_payload(&access_token);
    let id_claims = decode_jwt_payload(&id_token);

    // Both tokens must have amr
    let at_amr = at_claims.get("amr").expect("access_token must have amr");
    let id_amr = id_claims.get("amr").expect("id_token must have amr");

    assert_eq!(
        at_amr, id_amr,
        "AMR claims must be consistent: access_token={at_amr}, id_token={id_amr}"
    );

    // Both tokens must have acr
    let at_acr = at_claims.get("acr").expect("access_token must have acr");
    let id_acr = id_claims.get("acr").expect("id_token must have acr");

    assert_eq!(
        at_acr, id_acr,
        "ACR claims must be consistent: access_token={at_acr}, id_token={id_acr}"
    );
}
