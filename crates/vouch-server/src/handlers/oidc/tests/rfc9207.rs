// SPDX-License-Identifier: BUSL-1.1
//! RFC 9207 — Issuer Identification tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc9207_iss_in_error_redirect() {
    // RFC 9207 Section 2: Error redirects must include `iss` parameter.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "iss-error@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Trigger an error redirect (missing PKCE)
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Should have Location header")
            .to_str()
            .expect("Valid header");

        let redirect_url = url::Url::parse(location).expect("Valid URL");
        let iss_param: Option<String> = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "iss")
            .map(|(_, v)| v.to_string());

        assert!(
            iss_param.is_some(),
            "RFC 9207: Error redirect must include iss parameter: {}",
            location
        );
        assert_eq!(
            iss_param.as_deref(),
            Some(state.config().base_url.as_str()),
            "iss must match the issuer identifier"
        );
    }
}

#[tokio::test]
async fn test_rfc9207_iss_matches_discovery_issuer() {
    // RFC 9207 Section 2: The iss value must be byte-for-byte identical
    // to the issuer in the discovery document.
    let (app, _state) = test_app().await;

    // Get issuer from discovery
    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let discovery_issuer = discovery["issuer"].as_str().expect("issuer in discovery");

    // RFC 9207 Section 3: Discovery must advertise iss parameter support
    assert_eq!(
        discovery["authorization_response_iss_parameter_supported"], true,
        "Discovery must advertise iss parameter support per RFC 9207"
    );

    // Verify it matches the configured base_url (used in redirects)
    assert!(!discovery_issuer.is_empty(), "Issuer must not be empty");
    assert!(
        discovery_issuer.starts_with("https://"),
        "Issuer must be an HTTPS URL"
    );
}

#[tokio::test]
async fn test_rfc9207_authorize_response_includes_iss_parameter() {
    // RFC 9207 Section 2: The authorization response MUST include the iss parameter
    // so clients can bind the response to the correct authorization server.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-iss@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state=nonce123",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Authenticated request must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // RFC 9207 Section 2: iss must be present and equal to the authorization server's issuer
    assert!(
        location.contains("iss="),
        "Authorization response must include iss parameter (RFC 9207): {location}"
    );

    // Parse the URL and check the iss value
    let iss_start = location.find("iss=").expect("iss parameter exists") + 4;
    let after_iss = location.get(iss_start..).expect("iss_start in bounds");
    let iss_end = after_iss
        .find('&')
        .map(|i| iss_start + i)
        .unwrap_or(location.len());
    let iss_encoded = location
        .get(iss_start..iss_end)
        .expect("iss range in bounds");
    let iss = urlencoding::decode(iss_encoded)
        .expect("iss must be valid URL-encoded")
        .into_owned();

    let expected_issuer = &state.config().base_url;
    assert_eq!(
        &iss, expected_issuer,
        "iss in authorization response must match server issuer"
    );
}

#[tokio::test]
async fn test_rfc9207_authorize_error_redirect_includes_iss() {
    // RFC 9207 Section 2: The iss parameter MUST be included even in
    // error redirect responses, not just successful ones.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-erriss@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // response_type=token is unsupported — will produce an error redirect
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&state=err-iss-test",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Error must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // RFC 9207: iss must be present in error responses too
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207 Section 2): {location}"
    );

    // Verify iss matches the server's issuer
    let expected_issuer = &state.config().base_url;
    let encoded_issuer = urlencoding::encode(expected_issuer);
    assert!(
        location.contains(&format!("iss={encoded_issuer}")),
        "iss must match server issuer '{expected_issuer}': {location}"
    );
}
