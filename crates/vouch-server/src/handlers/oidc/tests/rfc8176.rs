// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8176 — AMR/ACR Values tests.

use super::helpers::*;

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
