// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8414 — Authorization Server Metadata tests.
//!
//! Covers discovery fields required by RFC 8414 Section 2, including
//! the revocation and introspection endpoint authentication method arrays.

use super::helpers::*;

// ============================================================================
// RFC 8414 Section 2 — Required Metadata Fields
// ============================================================================

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

// ============================================================================
// RFC 8414 Section 3 — Discovery Endpoints
// ============================================================================

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

// ============================================================================
// RFC 8414 — Endpoint Authentication Methods
// ============================================================================

#[tokio::test]
async fn test_discovery_includes_revocation_auth_methods() {
    // RFC 8414 Section 2: revocation_endpoint_auth_methods_supported must be present
    // and be a non-empty array when the revocation endpoint is advertised.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let methods = metadata
        .get("revocation_endpoint_auth_methods_supported")
        .expect("revocation_endpoint_auth_methods_supported must be present")
        .as_array()
        .expect("revocation_endpoint_auth_methods_supported must be an array");

    assert!(
        !methods.is_empty(),
        "revocation_endpoint_auth_methods_supported must contain at least one method"
    );
}

#[tokio::test]
async fn test_discovery_includes_introspection_auth_methods() {
    // RFC 8414 Section 2: introspection_endpoint_auth_methods_supported must be present
    // and be a non-empty array when the introspection endpoint is advertised.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let methods = metadata
        .get("introspection_endpoint_auth_methods_supported")
        .expect("introspection_endpoint_auth_methods_supported must be present")
        .as_array()
        .expect("introspection_endpoint_auth_methods_supported must be an array");

    assert!(
        !methods.is_empty(),
        "introspection_endpoint_auth_methods_supported must contain at least one method"
    );
}

#[tokio::test]
async fn test_discovery_auth_methods_match_token_endpoint() {
    // RFC 8414 Section 2: All three *_auth_methods_supported arrays should expose
    // the same set of authentication methods since the server applies uniform auth
    // policy across the token, revocation, and introspection endpoints.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let token_methods = metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("token_endpoint_auth_methods_supported must be an array");
    let revocation_methods = metadata["revocation_endpoint_auth_methods_supported"]
        .as_array()
        .expect("revocation_endpoint_auth_methods_supported must be an array");
    let introspection_methods = metadata["introspection_endpoint_auth_methods_supported"]
        .as_array()
        .expect("introspection_endpoint_auth_methods_supported must be an array");

    assert_eq!(
        token_methods, revocation_methods,
        "revocation_endpoint_auth_methods_supported must match token_endpoint_auth_methods_supported"
    );
    assert_eq!(
        token_methods, introspection_methods,
        "introspection_endpoint_auth_methods_supported must match token_endpoint_auth_methods_supported"
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

#[tokio::test]
async fn test_discovery_request_uri_parameter_supported() {
    // OIDC Core Section 6.2: When request_uri is supported, the server MUST
    // advertise request_uri_parameter_supported: true in discovery metadata.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let meta: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(
        meta["request_uri_parameter_supported"], true,
        "Discovery must advertise request_uri_parameter_supported: true"
    );
}

#[tokio::test]
async fn test_discovery_require_request_uri_registration_is_false() {
    // OIDC Core Section 6.2: require_request_uri_registration: false means the
    // server accepts HTTPS request_uri values without prior registration.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let meta: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Field must be present and false — registration is optional (allowlist opt-in).
    assert_eq!(
        meta["require_request_uri_registration"], false,
        "Discovery must advertise require_request_uri_registration: false"
    );
}

#[tokio::test]
async fn test_discovery_request_object_signing_alg_values_supported() {
    // RFC 9101: The server must advertise which algorithms it accepts for
    // signed Request Objects in request_object_signing_alg_values_supported.
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let meta: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let algs = meta["request_object_signing_alg_values_supported"]
        .as_array()
        .expect("request_object_signing_alg_values_supported must be a JSON array");

    let alg_strs: Vec<&str> = algs.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        alg_strs.contains(&"ES256"),
        "request_object_signing_alg_values_supported must include ES256, got: {alg_strs:?}"
    );
    // At minimum RS256 or ES256 must be listed — both are widely supported.
    assert!(
        alg_strs.contains(&"RS256") || alg_strs.contains(&"ES256"),
        "request_object_signing_alg_values_supported must include at least RS256 or ES256"
    );
}

// ============================================================================
// RFC 8414 — Metadata Validation
// ============================================================================

#[tokio::test]
async fn test_rfc8414_no_none_alg_in_signing_algorithms() {
    // Security: The "none" algorithm must never be advertised in any
    // signing algorithm list. RFC 8725 Section 3.2 prohibits "none".
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let alg_fields = [
        "id_token_signing_alg_values_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
    ];

    for field in &alg_fields {
        if let Some(algs) = m.get(*field) {
            let alg_array = algs.as_array().expect("algorithm field must be an array");
            assert!(
                !alg_array.iter().any(|v| v == "none"),
                "RFC 8725: '{field}' must NOT contain 'none' algorithm"
            );
        }
    }
}

#[tokio::test]
async fn test_rfc8414_issuer_no_trailing_slash() {
    // RFC 8414 Section 2: The issuer identifier MUST be byte-for-byte
    // identical everywhere it appears. No trailing slash normalization.
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let issuer = m["issuer"].as_str().expect("issuer must be a string");

    assert!(
        !issuer.ends_with('/'),
        "RFC 8414: issuer must NOT have trailing slash, got: {issuer}"
    );

    // Must match the configured base_url exactly
    let expected = &state.config().base_url;
    assert_eq!(
        issuer,
        expected.as_str(),
        "issuer must be byte-for-byte identical to configured base_url"
    );
}

#[tokio::test]
async fn test_rfc8414_scopes_supported_includes_openid() {
    // OIDC Discovery Section 3: scopes_supported MUST include "openid".
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let scopes = m["scopes_supported"]
        .as_array()
        .expect("scopes_supported must be a JSON array");

    assert!(
        scopes.iter().any(|s| s == "openid"),
        "scopes_supported must include 'openid', got: {scopes:?}"
    );
}
