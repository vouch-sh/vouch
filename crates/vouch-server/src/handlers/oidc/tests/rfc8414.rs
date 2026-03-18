// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8414 — Authorization Server Metadata tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc8414_metadata_content_type() {
    // RFC 8414 Section 3: Response must be application/json.
    let (app, _state) = test_app().await;

    let response = http_get_full(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(response.status, StatusCode::OK);

    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Should have Content-Type")
        .to_str()
        .expect("Valid string");
    assert!(
        content_type.contains("application/json"),
        "Metadata must be application/json, got: {}",
        content_type
    );
}

#[tokio::test]
async fn test_rfc8414_endpoint_auth_methods_in_metadata() {
    // RFC 8414 Section 2: Metadata should include revocation and introspection
    // endpoint authentication methods if those endpoints exist.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Required OIDC endpoints
    assert!(
        metadata.get("revocation_endpoint").is_some(),
        "Should have revocation_endpoint"
    );
    assert!(
        metadata.get("introspection_endpoint").is_some(),
        "Should have introspection_endpoint"
    );

    // token_endpoint_auth_methods_supported
    let auth_methods = metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("token_endpoint_auth_methods_supported must be an array");
    assert!(
        !auth_methods.is_empty(),
        "Must support at least one auth method"
    );
    assert!(
        auth_methods.iter().any(|m| m == "client_secret_basic"),
        "Should support client_secret_basic"
    );
}

#[tokio::test]
async fn test_rfc8414_metadata_required_fields() {
    // RFC 8414 Section 2 + OIDC Discovery 1.0 Section 3: Verify all required fields.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // REQUIRED per OIDC Discovery 1.0
    assert!(m.get("issuer").is_some(), "Must have issuer");
    assert!(
        m.get("authorization_endpoint").is_some(),
        "Must have authorization_endpoint"
    );
    assert!(
        m.get("token_endpoint").is_some(),
        "Must have token_endpoint"
    );
    assert!(m.get("jwks_uri").is_some(), "Must have jwks_uri");
    assert!(
        m.get("response_types_supported").is_some(),
        "Must have response_types_supported"
    );
    assert!(
        m.get("subject_types_supported").is_some(),
        "Must have subject_types_supported"
    );
    assert!(
        m.get("id_token_signing_alg_values_supported").is_some(),
        "Must have id_token_signing_alg_values_supported"
    );

    // RECOMMENDED
    assert!(
        m.get("scopes_supported").is_some(),
        "Should have scopes_supported"
    );
    assert!(
        m.get("claims_supported").is_some(),
        "Should have claims_supported"
    );

    // RFC 7636: PKCE support
    assert!(
        m.get("code_challenge_methods_supported").is_some(),
        "Should have code_challenge_methods_supported"
    );
    let methods = m["code_challenge_methods_supported"]
        .as_array()
        .expect("array");
    assert!(
        methods.iter().any(|m| m == "S256"),
        "Must support S256 code challenge method"
    );

    // RFC 8707: Resource indicators
    assert!(
        m.get("resource_indicators_supported").is_some(),
        "Should advertise resource_indicators_supported"
    );

    // RFC 9207: Issuer identification in auth responses
    assert_eq!(
        m["authorization_response_iss_parameter_supported"], true,
        "Should advertise iss parameter support"
    );

    // RFC 7523: JWT client auth signing algorithms
    assert!(
        m.get("token_endpoint_auth_signing_alg_values_supported")
            .is_some(),
        "Should advertise JWT auth signing algorithms"
    );
}

#[tokio::test]
async fn test_rfc8414_grant_types_supported() {
    // Verify the grant types metadata includes all supported grants.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let grants = m["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");

    let grant_strings: Vec<&str> = grants.iter().filter_map(|g| g.as_str()).collect();

    assert!(
        grant_strings.contains(&"authorization_code"),
        "Must support authorization_code"
    );
    assert!(
        grant_strings.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
        "Must support device_code"
    );
    assert!(
        grant_strings.contains(&"urn:ietf:params:oauth:grant-type:token-exchange"),
        "Must support token-exchange"
    );
    assert!(
        grant_strings.contains(&"urn:ietf:params:oauth:grant-type:jwt-bearer"),
        "Must support jwt-bearer"
    );
}

#[tokio::test]
async fn test_rfc8414_oauth_authorization_server_alias_returns_200() {
    // RFC 8414 Section 3: The authorization server MUST publish its metadata at
    // /.well-known/oauth-authorization-server in addition to the OIDC path.
    let (app, _state) = test_app().await;

    let response = http_get_full(&app, "/.well-known/oauth-authorization-server", &[]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "RFC 8414 alias must return 200 OK"
    );
    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Must have Content-Type header")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        content_type.contains("application/json"),
        "RFC 8414 alias must return application/json, got: {content_type}"
    );
    let metadata: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(
        metadata.get("issuer").is_some(),
        "RFC 8414 metadata must include issuer"
    );
    assert!(
        metadata.get("authorization_endpoint").is_some(),
        "RFC 8414 metadata must include authorization_endpoint"
    );
    assert!(
        metadata.get("token_endpoint").is_some(),
        "RFC 8414 metadata must include token_endpoint"
    );
}

#[tokio::test]
async fn test_rfc8414_oauth_authorization_server_alias_matches_openid_configuration() {
    // RFC 8414 Section 3: Both discovery endpoints must expose identical metadata.
    let (app, state) = test_app().await;

    let (oidc_status, oidc_body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    let (rfc8414_status, rfc8414_body) =
        http_get(&app, "/.well-known/oauth-authorization-server", &[]).await;

    assert_eq!(oidc_status, StatusCode::OK);
    assert_eq!(rfc8414_status, StatusCode::OK);

    let oidc_meta: serde_json::Value = serde_json::from_str(&oidc_body).expect("Valid JSON");
    let rfc8414_meta: serde_json::Value = serde_json::from_str(&rfc8414_body).expect("Valid JSON");

    // Key fields must be identical
    let base_url = &state.config().base_url;
    let fields = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
    ];
    for field in &fields {
        assert_eq!(
            oidc_meta.get(*field),
            rfc8414_meta.get(*field),
            "Field '{field}' must match between both discovery endpoints"
        );
    }

    // Both issuers must match the server's base URL
    assert_eq!(
        rfc8414_meta["issuer"].as_str(),
        Some(base_url.as_str()),
        "RFC 8414 issuer must equal base_url"
    );
}
