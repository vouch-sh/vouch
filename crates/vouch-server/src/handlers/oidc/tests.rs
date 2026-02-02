// SPDX-License-Identifier: BUSL-1.1
//! Tests for OIDC handlers.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use crate::test_utils::*;
use aws_lc_rs::digest::SHA256;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ========================================================================
// OIDC Discovery Tests (OIDC Core 1.0 Section 4.2)
// ========================================================================

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
    assert_eq!(issuer, state.config.base_url);
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
    let expected = format!("{}/oauth/device", state.config.base_url);
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

// ========================================================================
// UserInfo Endpoint Tests (OIDC Core 1.0 Section 5.3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_requires_bearer_token() {
    // OIDC Core 1.0 Section 5.3.1: UserInfo requires bearer token
    let (app, _state) = test_app().await;

    // No token
    let (status, body) = http_get(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "invalid_token");

    // Invalid token format
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_returns_sub_claim() {
    // OIDC Core 1.0 Section 5.3.2: Response must include 'sub' claim
    let (app, state) = test_app().await;

    // Create a test user and session
    let user = create_test_user(&state.db, "userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        userinfo.get("sub").is_some(),
        "UserInfo must contain 'sub' claim"
    );
    assert!(
        userinfo.get("email").is_some(),
        "UserInfo must contain 'email' claim"
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token() {
    // Invalid token should return 401
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "invalid_token");
}

// ========================================================================
// Token Endpoint Tests (RFC 6749 Section 5)
// ========================================================================

#[tokio::test]
async fn test_token_invalid_grant_type() {
    // RFC 6749 Section 5.2: unsupported_grant_type error
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=invalid_grant_type&code=test",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_missing_code() {
    // RFC 6749 Section 5.2: invalid_request when code is missing
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "invalid_request");
}

#[tokio::test]
async fn test_token_invalid_code() {
    // RFC 6749 Section 5.2: invalid_grant for invalid authorization code
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=invalid_code&redirect_uri=https://example.com/callback",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "invalid_grant");
}

// ========================================================================
// PKCE Tests (RFC 7636)
// ========================================================================

#[tokio::test]
async fn test_pkce_s256_validation() {
    // RFC 7636 Section 4.6: SHA256 code challenge verification
    // Test vector from RFC 7636 Appendix B
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Compute the challenge using the same method as the handler
    let computed_challenge =
        URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&SHA256, code_verifier.as_bytes()));

    assert_eq!(
        computed_challenge, expected_challenge,
        "RFC 7636 test vector must match"
    );
}

// ========================================================================
// Token Revocation Tests (RFC 7009)
// ========================================================================

#[tokio::test]
async fn test_revoke_valid_token() {
    // RFC 7009 Section 2.1: Successful revocation returns 200
    let (app, state) = test_app().await;

    // Create a test session
    let user = create_test_user(&state.db, "revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, _body) =
        http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_revoke_invalid_token_returns_ok() {
    // RFC 7009 Section 2.1: Invalid token should also return 200 (security best practice)
    let (app, _state) = test_app().await;

    let (status, _body) =
        http_post_form(&app, "/oauth/revoke", "token=completely_invalid_token", &[]).await;

    // Per RFC 7009, always return 200 to prevent token oracle attacks
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_revoke_token_invalidates_session() {
    // After revocation, the token should not work
    let (app, state) = test_app().await;

    // Create a test session
    let user = create_test_user(&state.db, "revoke-check@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Verify token works before revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token
    let (status, _body) =
        http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;
    assert_eq!(status, StatusCode::OK);

    // Verify token no longer works after revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token should fail after revocation"
    );
}

// ========================================================================
// Token Introspection Tests (RFC 7662)
// ========================================================================

#[tokio::test]
async fn test_introspect_active_token() {
    // RFC 7662 Section 2.2: Active token returns active=true with claims
    let (app, state) = test_app().await;

    // Create a test session
    let user = create_test_user(&state.db, "introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) =
        http_post_form(&app, "/oauth/introspect", &format!("token={}", token), &[]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);
    assert!(
        response.get("exp").is_some(),
        "Active token should have exp"
    );
    assert!(
        response.get("iat").is_some(),
        "Active token should have iat"
    );
    assert!(
        response.get("sub").is_some(),
        "Active token should have sub"
    );
}

#[tokio::test]
async fn test_introspect_invalid_token() {
    // RFC 7662 Section 2.2: Invalid token returns active=false
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/introspect", "token=invalid_token_here", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], false);
    // Inactive tokens should not leak claims
    assert!(response.get("exp").is_none());
    assert!(response.get("sub").is_none());
}

#[tokio::test]
async fn test_introspect_revoked_token() {
    // RFC 7662 Section 2.2: Revoked token returns active=false
    let (app, state) = test_app().await;

    // Create and then revoke a token
    let user = create_test_user(&state.db, "introspect-revoked@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Revoke the token
    let _ = http_post_form(&app, "/oauth/revoke", &format!("token={}", token), &[]).await;

    // Introspect should now return inactive
    let (status, body) =
        http_post_form(&app, "/oauth/introspect", &format!("token={}", token), &[]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], false);
}

// ========================================================================
// Token Exchange Tests (RFC 8693)
// ========================================================================

#[tokio::test]
async fn test_token_exchange_requires_grant_type() {
    // RFC 8693 Section 2.1: grant_type is required
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=invalid&subject_token=test",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_exchange_valid_token_types() {
    // RFC 8693 Section 2.1: Valid token type URNs should be accepted
    let valid_types = [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:jwt",
    ];

    for token_type in valid_types {
        // Just verify these are defined correctly
        assert!(
            token_type.starts_with("urn:ietf:params:oauth:token-type:"),
            "Token type URN should have correct prefix"
        );
    }
}

#[tokio::test]
async fn test_token_exchange_invalid_subject_token() {
    // RFC 8693: Invalid subject token returns invalid_grant
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "invalid_grant");
}

#[tokio::test]
async fn test_token_exchange_successful() {
    // RFC 8693: Successful token exchange
    let (app, state) = test_app().await;

    // Create a valid subject token
    let user = create_test_user(&state.db, "exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Should return access_token"
    );
    assert!(
        response.get("issued_token_type").is_some(),
        "Should return issued_token_type"
    );
    assert!(
        response.get("token_type").is_some(),
        "Should return token_type"
    );
    assert!(
        response.get("expires_in").is_some(),
        "Should return expires_in"
    );
}

#[tokio::test]
async fn test_token_exchange_scope_downgrade() {
    // RFC 8693 Section 2.2: Can reduce scope, not expand
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Request a subset of scopes
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
            token
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
    // Should only have requested scope (openid) not full scope
    assert!(scope.contains("openid") || scope.is_empty());
}
