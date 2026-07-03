// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Core 1.0 Section 4 — Discovery + JWKS tests.

use super::helpers::*;
use std::collections::BTreeSet;

#[tokio::test]
async fn test_oidc_discovery_required_fields() {
    // OIDC Core 1.0 Section 4.2: Discovery document must contain required fields
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Required fields per OIDC Core 1.0 Section 4.2
    assert!(discovery.get("issuer").is_some(), "issuer is required");
    assert!(
        discovery.get("authorization_endpoint").is_some(),
        "authorization_endpoint is required"
    );
    assert!(
        discovery.get("token_endpoint").is_some(),
        "token_endpoint is required"
    );
    assert!(discovery.get("jwks_uri").is_some(), "jwks_uri is required");
    assert!(
        discovery.get("response_types_supported").is_some(),
        "response_types_supported is required"
    );
    assert!(
        discovery.get("subject_types_supported").is_some(),
        "subject_types_supported is required"
    );
    assert!(
        discovery
            .get("id_token_signing_alg_values_supported")
            .is_some(),
        "id_token_signing_alg_values_supported is required"
    );
}

#[tokio::test]
async fn test_oidc_discovery_issuer_matches_base_url() {
    // OIDC Core 1.0 Section 4.2: issuer must match the base URL
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let issuer = discovery["issuer"].as_str().expect("issuer is a string");
    assert_eq!(issuer, state.config().base_url);
}

#[tokio::test]
async fn test_oidc_discovery_endpoints_are_absolute_urls() {
    // All endpoint URLs should be absolute
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let endpoints = [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "revocation_endpoint",
        "introspection_endpoint",
    ];

    for endpoint in endpoints {
        if let Some(url) = discovery.get(endpoint).and_then(|v| v.as_str()) {
            assert!(
                url.starts_with("https://"),
                "{endpoint} should be an absolute HTTPS URL"
            );
        }
    }
}

#[tokio::test]
async fn test_oidc_discovery_supported_grant_types() {
    // Verify supported grant types are advertised
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let grant_types = discovery["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported is an array");

    let grant_types: Vec<&str> = grant_types.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        grant_types.contains(&"authorization_code"),
        "authorization_code grant type should be supported"
    );
    assert!(
        grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
        "device_code grant type should be supported"
    );
}

#[tokio::test]
async fn test_oidc_discovery_grant_types_match_token_parser() {
    // Regression guard: discovery metadata and token parser must stay in sync.
    let (app, _state) = test_app().await;
    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let discovered: BTreeSet<String> = discovery["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported is an array")
        .iter()
        .map(|v| v.as_str().expect("grant type should be string").to_string())
        .collect();

    let parser_supported =
        crate::services::oidc::grant_type::OAuthGrantType::supported_wire_values()
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>();

    assert_eq!(
        discovered, parser_supported,
        "discovery grant_types_supported must exactly match token endpoint parser support"
    );

    for grant in &discovered {
        let parsed = grant.parse::<crate::services::oidc::grant_type::OAuthGrantType>();
        assert!(
            parsed.is_ok(),
            "discovery advertises unsupported grant type in parser: {grant}"
        );
    }
}

#[tokio::test]
async fn test_oidc_discovery_device_authorization_endpoint() {
    // RFC 8628 Section 4: device_authorization_endpoint must be advertised
    // when device_code grant type is supported
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 8628: device_authorization_endpoint is required when device_code is supported
    let endpoint = discovery
        .get("device_authorization_endpoint")
        .expect("device_authorization_endpoint is required per RFC 8628");

    let endpoint_url = endpoint.as_str().expect("Should be a string");
    assert!(
        endpoint_url.starts_with("https://"),
        "device_authorization_endpoint should be an absolute HTTPS URL"
    );
    assert!(
        endpoint_url.ends_with("/oauth/device"),
        "device_authorization_endpoint should point to /oauth/device"
    );

    // Verify it matches the configured base URL
    let expected = format!("{}/oauth/device", state.config().base_url);
    assert_eq!(endpoint_url, expected);
}

// ========================================================================
// JWKS Endpoint Tests (OIDC Core 1.0 Section 3)
// ========================================================================

#[tokio::test]
async fn test_jwks_endpoint_returns_keys() {
    // OIDC Core 1.0: JWKS endpoint should return valid key set
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/oauth/jwks", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(jwks.get("keys").is_some(), "JWKS must contain 'keys' array");
    let keys = jwks["keys"].as_array().expect("keys is an array");
    assert!(!keys.is_empty(), "JWKS should contain at least one key");

    // Verify key format
    for key in keys {
        assert!(key.get("kty").is_some(), "Key must have 'kty' field");
        assert!(key.get("alg").is_some(), "Key must have 'alg' field");
    }
}

#[tokio::test]
async fn test_jwks_returns_ec_key_for_es256() {
    // AWS OIDC requires EC public key for ES256 verification
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/oauth/jwks", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = jwks["keys"].as_array().expect("keys is an array");
    assert!(!keys.is_empty(), "JWKS should have at least one key");

    let key = &keys[0];

    // Verify it's an EC key for ES256
    assert_eq!(key["kty"], "EC", "Key type should be EC");
    assert_eq!(key["crv"], "P-256", "Curve should be P-256");
    assert_eq!(key["alg"], "ES256", "Algorithm should be ES256");
    assert_eq!(key["use"], "sig", "Usage should be sig");

    // Verify EC public key coordinates are present
    assert!(key.get("x").is_some(), "EC key must have x coordinate");
    assert!(key.get("y").is_some(), "EC key must have y coordinate");

    // Verify x and y are valid base64url strings (not empty)
    let x = key["x"].as_str().expect("x should be a string");
    let y = key["y"].as_str().expect("y should be a string");
    assert!(!x.is_empty(), "x coordinate should not be empty");
    assert!(!y.is_empty(), "y coordinate should not be empty");

    // Verify kid is present
    assert!(key.get("kid").is_some(), "EC key must have kid");
    let kid = key["kid"].as_str().expect("kid should be a string");
    assert!(
        kid.starts_with("vouch-oidc-"),
        "kid should start with vouch-oidc-"
    );
}

#[tokio::test]
async fn test_discovery_advertises_es256() {
    // Verify discovery document advertises ES256 for ID token signing
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let algs = discovery["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("Should be an array");

    assert!(
        algs.iter().any(|a| a == "ES256"),
        "Discovery should advertise ES256 signing"
    );

    // Should NOT advertise HS256 (symmetric) for AWS compatibility
    assert!(
        !algs.iter().any(|a| a == "HS256"),
        "Discovery should not advertise HS256 for AWS compatibility"
    );
}

#[tokio::test]
async fn test_oidc_discovery_form_post_in_response_modes() {
    // OIDC Core 1.0 + OAuth 2.0 Form Post Response Mode: response_modes_supported
    // must include "form_post" after the OIDC compliance update.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let modes = discovery["response_modes_supported"]
        .as_array()
        .expect("response_modes_supported is an array");
    let mode_strs: Vec<&str> = modes.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        mode_strs.contains(&"form_post"),
        "response_modes_supported must include form_post, got: {mode_strs:?}"
    );
    assert!(
        mode_strs.contains(&"query"),
        "response_modes_supported must include query"
    );
}

#[tokio::test]
async fn test_oidc_discovery_userinfo_signing_alg_values_supported() {
    // OIDC Core Section 5.3.4: userinfo_signing_alg_values_supported must be present
    // and include ES256.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let algs = discovery["userinfo_signing_alg_values_supported"]
        .as_array()
        .expect("userinfo_signing_alg_values_supported must be present and an array");
    let alg_strs: Vec<&str> = algs.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        alg_strs.contains(&"ES256"),
        "userinfo_signing_alg_values_supported must include ES256, got: {alg_strs:?}"
    );
}

#[tokio::test]
async fn test_oidc_discovery_end_session_endpoint_present() {
    // RP-Initiated Logout 1.0 §4: end_session_endpoint must be advertised.
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let end_session_endpoint = discovery["end_session_endpoint"]
        .as_str()
        .expect("end_session_endpoint must be present and a string in OIDC discovery document");
    let expected = format!("{}/oauth/logout", state.config().base_url);
    assert_eq!(
        end_session_endpoint, expected,
        "end_session_endpoint must equal <base_url>/oauth/logout"
    );
    assert!(
        end_session_endpoint.starts_with("https://"),
        "end_session_endpoint must be an absolute HTTPS URL, got: {end_session_endpoint}"
    );
}

#[tokio::test]
async fn test_oidc_discovery_hardware_claims_not_in_claims_supported() {
    // OIDC compliance: hardware_verified and hardware_aaguid must not appear in
    // claims_supported after removal from standard OIDC id_tokens.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let claims = discovery["claims_supported"]
        .as_array()
        .expect("claims_supported is an array");
    let claim_strs: Vec<&str> = claims.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        !claim_strs.contains(&"hardware_verified"),
        "claims_supported must not include hardware_verified (removed for OIDC conformance)"
    );
    assert!(
        !claim_strs.contains(&"hardware_aaguid"),
        "claims_supported must not include hardware_aaguid (removed for OIDC conformance)"
    );
}
