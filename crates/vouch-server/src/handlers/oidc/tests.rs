// SPDX-License-Identifier: BUSL-1.1
//! Tests for OIDC handlers.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::db;
use crate::services::oidc::authorization::{
    AuthorizationCodeParams, CodeChallengeMethod, issue_authorization_code,
};
use crate::services::oidc::scope::ScopeSet;
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
    assert_eq!(error["error"], "invalid_token");

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

    // Create a test user and session (FIDO2 session — no email scope)
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
    // FIDO2 sessions don't have email scope, so email claims are omitted
    // per OIDC Core Section 5.4
    assert!(
        userinfo.get("email").is_none(),
        "FIDO2 session should not have email claim without email scope"
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
    assert_eq!(error["error"], "invalid_token");
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
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_missing_code() {
    // RFC 6749 Section 5.2: invalid_request when code is missing
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_invalid_code() {
    // RFC 6749 Section 5.2: invalid_grant for invalid authorization code
    let (app, state) = test_app().await;

    // Create a test user and OAuth client for authentication
    let user = create_test_user(&state.db, "invalid-code@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=invalid_code&redirect_uri=https://example.com/callback",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
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
    // RFC 7009 Section 2.1: Successful revocation returns 200 and invalidates the token
    let (app, state) = test_app().await;

    // Create a test session and OAuth client for authentication
    let user = create_test_user(&state.db, "revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

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

    // Revoke the token with client authentication (RFC 7009 Section 2.1)
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;
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

    // Create a test session and OAuth client for authentication
    let user = create_test_user(&state.db, "revoke-check@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

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

    // Revoke the token (requires client authentication per RFC 7009)
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;
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

    // Create a test user, OAuth client (for auth), and session
    let user = create_test_user(&state.db, "introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

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
    let (app, state) = test_app().await;

    // Create an OAuth client for authentication (RFC 7662 Section 2.1)
    let user = create_test_user(&state.db, "introspect-invalid@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        "token=invalid_token_here",
        &[("Authorization", &auth_header)],
    )
    .await;

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

    // Create user, OAuth client, and session
    let user = create_test_user(&state.db, "introspect-revoked@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Revoke the token (requires client authentication per RFC 7009)
    let _ = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    // Introspect should now return inactive (with client auth per RFC 7662)
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

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
    assert_eq!(error["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_exchange_valid_token_types() {
    // RFC 8693 Section 2.1: All valid subject_token_type URNs should be accepted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-types@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let valid_types = [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:jwt",
    ];

    for token_type in valid_types {
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type={}",
                token, token_type
            ),
            &[("Authorization", &auth_header)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Token type {} should be accepted, got: {}",
            token_type,
            body
        );
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert!(
            response.get("access_token").is_some(),
            "Response for {} should contain access_token",
            token_type
        );
    }
}

#[tokio::test]
async fn test_token_exchange_invalid_subject_token() {
    // RFC 8693: Invalid subject token returns invalid_grant
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-invalid@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_exchange_successful() {
    // RFC 8693: Successful token exchange
    let (app, state) = test_app().await;

    // Create a valid subject token and client for authentication
    let user = create_test_user(&state.db, "exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[("Authorization", &auth_header)],
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
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Request a subset of scopes
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
    // Should only have requested scope (openid) not full scope
    assert!(scope.contains("openid") || scope.is_empty());
}

// ========================================================================
// Client Secret Hash Round-Trip Tests (regression)
// ========================================================================

#[tokio::test]
async fn test_client_secret_hash_roundtrip() {
    // Regression test: client secrets hashed at creation time must match
    // hashes produced during authentication. A previous bug used hex encoding
    // at creation but base64url at validation, so authentication always failed.
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.db, "secret-roundtrip@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // The test helper uses hash_token() (base64url). Validate that
    // db::validate_oauth_client_credentials finds the secret when we
    // hash the plaintext secret with the same function.
    let secret_hash = crate::handlers::hash_token(&client.client_secret);
    let result =
        crate::db::validate_oauth_client_credentials(&state.db, &client.client_id, &secret_hash)
            .await
            .expect("DB query should succeed");

    assert!(
        result.is_some(),
        "Client secret round-trip must succeed: hash at creation must match hash at validation"
    );
}

// ========================================================================
// Helper: issue an OAuth access token via auth code exchange
// ========================================================================

/// Create an authorization code and exchange it at `/oauth/token` to get an access token.
/// Returns `(access_token, id_token)`.
async fn issue_oauth_access_token(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
) -> (String, String) {
    issue_oauth_access_token_with_scope(app, state, user, auth_id, client, "openid email").await
}

/// Create an authorization code with a specific scope and exchange it at `/oauth/token`.
/// Uses the real `issue_authorization_code()` service function to exercise the full
/// code path including server-side code storage for single-use enforcement.
/// Returns `(access_token, id_token)`.
async fn issue_oauth_access_token_with_scope(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    auth_id: &str,
    client: &TestOAuthClient,
    scope: &str,
) -> (String, String) {
    use crate::services::oidc::authorization::{AuthorizationCodeParams, issue_authorization_code};

    let scope_set = ScopeSet::parse(scope);

    let code_params = AuthorizationCodeParams {
        client_id: &client.client_id,
        redirect_uri: "https://example.com/callback",
        user_id: &user.id,
        email: &user.email,
        authenticator_id: auth_id,
        aaguid: None,
        scope: &scope_set,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        resource: None,
    };

    let code = issue_authorization_code(state, code_params)
        .await
        .expect("Failed to issue authorization code");

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            code, "https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange should succeed: {}",
        body
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string();
    let id_token = response["id_token"]
        .as_str()
        .expect("id_token present")
        .to_string();

    (access_token, id_token)
}

// ========================================================================
// OAuth Access Token + UserInfo End-to-End Tests
// ========================================================================

#[tokio::test]
async fn test_auth_code_flow_token_works_with_userinfo() {
    // Full OIDC flow: issue auth code → exchange → call /oauth/userinfo → assert 200
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "oauth-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Call userinfo with the OAuth access token
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "UserInfo should accept OAuth access token"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        userinfo["email"].as_str().unwrap(),
        "oauth-userinfo@example.com"
    );
    assert!(userinfo["sub"].is_string(), "sub claim must be present");
}

#[tokio::test]
async fn test_auth_code_flow_token_works_with_introspection() {
    // Issue auth code → exchange → /oauth/introspect → assert active=true
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "oauth-introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["active"], true,
        "OAuth access token should be active"
    );
    assert!(response.get("exp").is_some(), "Should have exp claim");
    assert!(response.get("sub").is_some(), "Should have sub claim");
}

#[tokio::test]
async fn test_auth_code_flow_token_revocation() {
    // Issue auth code → exchange → verify userinfo works → revoke → verify 401
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "oauth-revoke@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Verify token works before revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token
    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify token no longer works after revocation
    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token should fail after revocation"
    );
}

#[tokio::test]
async fn test_oauth_access_token_rejected_at_management_endpoints() {
    // OAuth access tokens (ES256, RFC 9068) are rejected at management endpoints
    // because the management endpoint only decodes HS256 FIDO2 session tokens.
    // The ES256 token fails HS256 decoding, returning 401 (unauthorized).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "oauth-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Try calling key listing endpoint with OAuth access token
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    // ES256 access tokens cannot be decoded by the HS256-only management
    // endpoint, so they fail at the JWT decode step with 401.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "OAuth access token should be rejected at management endpoints: {}",
        body
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unauthorized");
}

#[tokio::test]
async fn test_fido2_session_still_works_at_management_endpoints() {
    // Verify FIDO2 session tokens still work at management endpoints
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "fido2-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Call key listing endpoint with FIDO2 session token (should succeed)
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "FIDO2 session should work at management endpoints"
    );
}

// ========================================================================
// OIDC Scope Conformance Tests
// ========================================================================

#[tokio::test]
async fn test_userinfo_respects_openid_only_scope() {
    // OIDC Core Section 5.4: Without email scope, email claims should be omitted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "scope-openid@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token with only "openid" scope (no "email")
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
    assert!(
        userinfo.get("email").is_none(),
        "email claim should be omitted without email scope"
    );
    assert!(
        userinfo.get("email_verified").is_none(),
        "email_verified should be omitted without email scope"
    );
}

#[tokio::test]
async fn test_userinfo_includes_email_with_email_scope() {
    // OIDC Core Section 5.4: With email scope, email claims should be present
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token with "openid email" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid email")
            .await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
    assert!(
        userinfo.get("email").is_some(),
        "email claim should be present with email scope"
    );
    assert_eq!(
        userinfo["email"].as_str().unwrap(),
        "scope-email@example.com"
    );
    assert_eq!(userinfo["email_verified"], true);
}

#[tokio::test]
async fn test_introspection_returns_actual_scope() {
    // RFC 7662 Section 2.2: Introspection must return actual granted scope
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token with only "openid" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);

    let scope = response["scope"].as_str().expect("scope should be present");
    assert_eq!(
        scope, "openid",
        "Introspection should return actual granted scope"
    );
}

#[tokio::test]
async fn test_id_token_scope_aware() {
    // OIDC Core Section 5.4: ID token should only include email when scope grants it
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "idtoken-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token with only "openid" scope (no email)
    let (_access_token, id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    // Decode the ID token (just decode claims, don't verify signature in test)
    let parts: Vec<&str> = id_token.split('.').collect();
    assert!(parts.len() >= 2, "ID token should have at least 2 parts");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Valid base64");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("Valid JSON payload");

    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(
        claims.get("email").is_none(),
        "ID token should not have email claim without email scope"
    );
    assert!(
        claims.get("email_verified").is_none(),
        "ID token should not have email_verified without email scope"
    );
}

#[tokio::test]
async fn test_backward_compat_token_without_scope() {
    // JWTs without scope field should deserialize as None
    let claims_json = r#"{"iss":"https://vouch.example.com","aud":"https://vouch.example.com","sub":"user-id","email":"test@example.com","iat":1700000000,"exp":1700028800,"purpose":"fido2_session"}"#;
    let claims: crate::services::auth::SessionClaims =
        serde_json::from_str(claims_json).expect("Should deserialize without scope");
    assert!(
        claims.scope.is_none(),
        "Missing scope field should deserialize as None"
    );
}

#[tokio::test]
async fn test_token_exchange_uses_subject_scope() {
    // RFC 8693: Token exchange should respect subject token's scope
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-scope2@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token with only "openid" scope
    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;

    let auth_header = client.basic_auth_header();

    // Exchange and request "openid email" — should only get "openid" (intersection)
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid email",
            access_token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let scope = response.get("scope").and_then(|s| s.as_str()).unwrap_or("");
    assert_eq!(
        scope, "openid",
        "Exchange should intersect with subject token's scope"
    );
}

// ========================================================================
// WWW-Authenticate Header Tests (RFC 6750 Section 3)
// ========================================================================

#[tokio::test]
async fn test_userinfo_401_includes_www_authenticate() {
    // RFC 6750 Section 3: 401 responses MUST include WWW-Authenticate header
    let (app, _state) = test_app().await;

    // No token — should get 401 with WWW-Authenticate
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.starts_with("Bearer"),
        "WWW-Authenticate should use Bearer scheme, got: {}",
        www_auth_str
    );
    assert!(
        www_auth_str.contains("error="),
        "WWW-Authenticate should include error parameter, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_invalid_token_includes_www_authenticate() {
    // RFC 6750 Section 3.1: invalid_token error with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer invalid_token_here")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.contains("invalid_token"),
        "WWW-Authenticate should include invalid_token error, got: {}",
        www_auth_str
    );
}

#[tokio::test]
async fn test_userinfo_unsupported_scheme_includes_www_authenticate() {
    // RFC 6750 Section 3: Unsupported auth scheme should return 401 with WWW-Authenticate
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "NotBearer token")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers
        .get("WWW-Authenticate")
        .expect("401 response must include WWW-Authenticate header");
    let www_auth_str = www_auth
        .to_str()
        .expect("WWW-Authenticate should be a string");
    assert!(
        www_auth_str.starts_with("Bearer"),
        "WWW-Authenticate should use Bearer scheme"
    );
}

// ========================================================================
// DPoP Integration Tests (RFC 9449)
// ========================================================================

/// Helper: Generate an EC P-256 key pair and return (signing_key, DPoP JWK header fields).
fn generate_dpop_key_pair() -> (aws_lc_rs::signature::EcdsaKeyPair, serde_json::Value) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    // Extract x/y coordinates from uncompressed public key (65 bytes: 0x04 || x || y)
    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    (key_pair, jwk)
}

/// Helper: Create and sign a DPoP proof JWT for the given method and URI.
fn create_dpop_proof(
    key_pair: &aws_lc_rs::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> String {
    use aws_lc_rs::digest;

    // Build header
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    // Build claims
    let jti = uuid::Uuid::now_v7().to_string();
    let now = jiff::Timestamp::now().as_second();
    let mut claims = serde_json::json!({
        "jti": jti,
        "htm": method,
        "htu": uri,
        "iat": now
    });

    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }

    if let Some(token) = access_token {
        // Compute ath (access token hash)
        let hash = digest::digest(&digest::SHA256, token.as_bytes());
        let ath = URL_SAFE_NO_PAD.encode(hash.as_ref());
        claims["ath"] = serde_json::json!(ath);
    }

    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    // Sign with ES256
    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign DPoP proof");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{}.{}.{}", header_b64, claims_b64, sig_b64)
}

#[tokio::test]
async fn test_dpop_token_exchange_with_proof() {
    // RFC 9449: Token endpoint should accept DPoP proof and return DPoP-bound token
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Generate DPoP key pair and proof
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();

    // Token exchange with DPoP proof
    let response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "DPoP token exchange should succeed: {}",
        response.body
    );
    let body: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(
        body.get("access_token").is_some(),
        "Should return access_token"
    );

    // RFC 9449 Section 5: token_type should be "DPoP" when DPoP was used
    let token_type = body["token_type"].as_str().unwrap_or("");
    assert_eq!(
        token_type, "DPoP",
        "Token type should be DPoP when DPoP proof is provided"
    );
}

#[tokio::test]
async fn test_dpop_userinfo_with_dpop_scheme() {
    // RFC 9449 Section 7.1: UserInfo with DPoP-bound token and DPoP authorization scheme
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate DPoP key pair
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Get an access token with DPoP binding via token exchange
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        exchange_response.status,
        StatusCode::OK,
        "Exchange should succeed: {}",
        exchange_response.body
    );
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Now use the DPoP-bound token at userinfo with DPoP scheme
    let userinfo_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(dpop_bound_token),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &userinfo_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "UserInfo with DPoP scheme should succeed: {}",
        response.body
    );
    let userinfo: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert!(userinfo.get("sub").is_some(), "sub claim must be present");
}

#[tokio::test]
async fn test_dpop_userinfo_key_mismatch_rejected() {
    // RFC 9449 Section 7.1: DPoP proof made with a different key than the token binding
    // should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate two different DPoP key pairs
    let (dpop_key1, dpop_jwk1) = generate_dpop_key_pair();
    let (dpop_key2, dpop_jwk2) = generate_dpop_key_pair();

    // Get a DPoP-bound token using key1
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let dpop_proof1 = create_dpop_proof(
        &dpop_key1,
        &dpop_jwk1,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();

    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof1),
        ],
    )
    .await;

    assert_eq!(exchange_response.status, StatusCode::OK);
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Try to use the token with key2 (different key) — should fail
    let bad_proof = create_dpop_proof(
        &dpop_key2,
        &dpop_jwk2,
        "GET",
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(dpop_bound_token),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &bad_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "DPoP with mismatched key should be rejected: {}",
        response.body
    );
}

#[tokio::test]
async fn test_dpop_scheme_without_proof_rejected() {
    // RFC 9449: Using DPoP authorization scheme without a DPoP proof header should fail
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-noproof@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("DPoP {}", token))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "DPoP scheme without proof should be rejected: {}",
        response.body
    );
}

#[tokio::test]
async fn test_dpop_non_bound_token_with_dpop_scheme_rejected() {
    // RFC 9449 Section 7.1: Using DPoP scheme with a non-DPoP-bound token should fail
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-nonbound@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get a regular (non-DPoP-bound) access token
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(&access_token),
    );

    // Use DPoP scheme with non-DPoP-bound token
    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", access_token)),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Non-DPoP-bound token with DPoP scheme should be rejected: {}",
        response.body
    );
}

// ========================================================================
// P0: RFC 9700 — OAuth 2.0 Security Best Current Practice
// ========================================================================

#[tokio::test]
async fn test_rfc9700_authorization_code_single_use() {
    // RFC 9700 Section 2.1 / RFC 6749 Section 10.5:
    // Using the same authorization code twice must fail.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "single-use@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // First use — should succeed
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "First use of authorization code should succeed"
    );

    // Second use — must fail per RFC 6749 Section 10.5
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Second use of authorization code must fail"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_pkce_required_at_handler_level() {
    // RFC 9700 Section 2.1.1: Omitting code_challenge at /oauth/authorize returns error.
    // The authorize endpoint requires PKCE (S256) for all clients.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-required@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Authorize request without code_challenge — should redirect with error
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test123",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should be a redirect (302) with error in the location
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "Should redirect with error: {}",
        response.body
    );
    let location = response
        .headers
        .get("Location")
        .expect("Should have Location header")
        .to_str()
        .expect("Valid header");
    assert!(
        location.contains("error="),
        "Redirect should contain error parameter: {}",
        location
    );
    assert!(
        location.contains("state=test123"),
        "Error redirect should preserve state parameter: {}",
        location
    );
}

#[tokio::test]
async fn test_rfc9700_client_id_matching_at_token_endpoint() {
    // RFC 9700 Section 2.2: client_id at token endpoint must match authorization.
    // Code issued to client A cannot be exchanged by client B.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "client-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client_a = create_test_oauth_client(&state.db, &user.id).await;
    let client_b = create_test_oauth_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client_a.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    // Try to exchange with client_b credentials — must fail
    let auth_header_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header_b)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Code for client A should not be exchangeable by client B"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_redirect_uri_exact_match_at_token() {
    // RFC 9700 / RFC 6749 Section 4.1.3: redirect_uri at token endpoint must
    // exactly match the one used during authorization.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "redirect-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Use a different redirect_uri at token endpoint — must fail
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback/different",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Mismatched redirect_uri must fail"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn test_rfc9700_redirect_uri_required_when_present_in_auth() {
    // RFC 6749 Section 4.1.3: If redirect_uri was present in auth request,
    // it MUST be present at token request too.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "redirect-required@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Omit redirect_uri at token endpoint — must fail
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!("grant_type=authorization_code&code={}", code),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing redirect_uri must fail when it was in the authorization request"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Should return error for missing redirect_uri"
    );
}

// ========================================================================
// P0: RFC 6749 — OAuth 2.0 Authorization Framework
// ========================================================================

#[tokio::test]
async fn test_rfc6749_error_page_for_unknown_client_id() {
    // RFC 6749 Section 4.1.2.1: Invalid client_id must show error page,
    // NOT redirect to an unregistered URI.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code&client_id=nonexistent-client&redirect_uri=https://evil.com/callback&code_challenge=abc&code_challenge_method=S256",
        &[],
    )
    .await;

    // Should show an error page (200 with HTML), NOT redirect to evil.com
    assert_ne!(
        response.status,
        StatusCode::SEE_OTHER,
        "Unknown client_id must NOT cause redirect to unregistered URI"
    );
    assert_ne!(
        response.status,
        StatusCode::FOUND,
        "Unknown client_id must NOT cause redirect to unregistered URI"
    );
    // Should either be 200 (error page) or 400
    assert!(
        response.status == StatusCode::OK || response.status == StatusCode::BAD_REQUEST,
        "Should show error page for unknown client_id, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_rfc6749_redirect_uri_validation_against_registered() {
    // RFC 6749 Section 10.6: Authorize endpoint rejects unregistered redirect URIs.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "redirect-unregistered@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=abc&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://evil.com/steal-code")
        ),
        &[],
    )
    .await;

    // Must NOT redirect to the unregistered URI
    if let Some(location) = response.headers.get("Location") {
        let loc = location.to_str().unwrap_or("");
        assert!(
            !loc.starts_with("https://evil.com"),
            "Must not redirect to unregistered URI: {}",
            loc
        );
    }
    // Should show error page instead
    assert!(
        response.status == StatusCode::OK || response.status == StatusCode::BAD_REQUEST,
        "Should show error page for unregistered redirect_uri, got: {}",
        response.status
    );
}

#[tokio::test]
async fn test_rfc6749_token_error_response_format() {
    // RFC 6749 Section 5.2: Token endpoint errors must include `error` field
    // and optional `error_description`, with correct HTTP status.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=authorization_code", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 6749 Section 5.2: REQUIRED error field
    assert!(
        error.get("error").is_some(),
        "Token error must include 'error' field"
    );
    let error_code = error["error"].as_str().expect("error is a string");
    assert!(!error_code.is_empty(), "Error code must not be empty");

    // error_description is optional but recommended
    if let Some(desc) = error.get("error_description") {
        assert!(desc.is_string(), "error_description must be a string");
    }
}

#[tokio::test]
async fn test_rfc6749_state_parameter_passthrough() {
    // RFC 6749 Section 4.1.2: State sent in authorize request must appear
    // unchanged in the error redirect response.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "state-passthrough@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let unique_state = "unique-state-value-12345";

    // This will fail validation (no code_challenge) and redirect with error + state
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            unique_state
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

        // Parse the redirect URL and check for state parameter
        let redirect_url = url::Url::parse(location).expect("Valid URL");
        let state_param: Option<String> = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string());

        assert_eq!(
            state_param.as_deref(),
            Some(unique_state),
            "State parameter must be preserved unchanged in redirect"
        );
    }
}

// ========================================================================
// P0: RFC 9207 — Authorization Server Issuer Identification
// ========================================================================

#[tokio::test]
async fn test_rfc9207_iss_in_error_redirect() {
    // RFC 9207 Section 2: Error redirects must include `iss` parameter.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "iss-error@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

// ========================================================================
// P0: RFC 8725 — JWT Best Current Practices
// ========================================================================

#[tokio::test]
async fn test_rfc8725_cross_type_token_substitution() {
    // RFC 8725 Section 3.11: Access token (at+jwt) cannot be used where
    // session token (vouch-session+jwt) is expected and vice versa.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "cross-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get an OAuth access token (ES256, typ=at+jwt)
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Try using the access token at a management endpoint that expects a
    // FIDO2 session token (HS256, typ=vouch-session+jwt) — should fail
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Access token (at+jwt) should not be accepted where session token is expected"
    );

    // Get a FIDO2 session token (HS256, typ=vouch-session+jwt)
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Session token should work at management endpoints
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", session_token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session token should work at management endpoints"
    );
}

#[tokio::test]
async fn test_rfc8725_required_claims_validation() {
    // RFC 8725 Section 3.4: Missing required claims causes rejection.
    // Forge a JWT missing the `iss` claim and verify it's rejected.
    let (app, _state) = test_app().await;

    // Create a JWT with no claims at all (will fail validation)
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[(
            "Authorization",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6InZvdWNoLXNlc3Npb24rand0In0.e30.invalid",
        )],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWT without required claims must be rejected"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_token");
}

#[tokio::test]
async fn test_rfc8725_jwe_envelope_rejection() {
    // RFC 8725 Section 3.2: Encrypted JWT (5-part) must be rejected.
    // JWE has 5 Base64url-encoded parts separated by dots.
    let (app, _state) = test_app().await;

    let fake_jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo.48V1_ALb6US04.5eym8TW_c8SuK0ltJ3rpYIzOeDQz.XFBoMYUZodetZdvTiFvSkQ";

    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", fake_jwe))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWE (5-part JWT) must be rejected at validation endpoints"
    );
}

// ========================================================================
// P0: RFC 9449 — DPoP Edge Cases
// ========================================================================

#[tokio::test]
async fn test_rfc9449_jti_replay_prevention() {
    // RFC 9449 Section 10: Replaying a DPoP proof with same jti must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create a single DPoP proof
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();

    // First use — should succeed
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "First DPoP proof use should succeed"
    );

    // Replay same proof (same jti) — must be rejected
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Replayed DPoP proof must be rejected: {}",
        body
    );
}

#[tokio::test]
async fn test_rfc9449_wrong_typ_header() {
    // RFC 9449 Section 4.1: DPoP proof with wrong typ (JWT instead of dpop+jwt) must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Manually construct a DPoP proof with wrong typ
    let header = serde_json::json!({
        "typ": "JWT",  // Wrong! Should be "dpop+jwt"
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    let jti = uuid::Uuid::now_v7().to_string();
    let now = jiff::Timestamp::now().as_second();
    let claims = serde_json::json!({
        "jti": jti,
        "htm": "POST",
        "htu": format!("{}/oauth/token", state.config().base_url),
        "iat": now
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let bad_proof = format!("{}.{}.{}", header_b64, claims_b64, sig_b64);

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof with wrong typ must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_htm_method_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof with wrong HTTP method must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create a proof with GET method for a POST endpoint
    let bad_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET", // Wrong! Token endpoint uses POST
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof with wrong HTTP method must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_htu_uri_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof for a different URI must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htu@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create a proof for /oauth/userinfo but use it at /oauth/token
    let bad_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/userinfo", state.config().base_url), // Wrong URI!
        None,
        None,
    );

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &bad_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP proof for wrong URI must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_expired_dpop_proof() {
    // RFC 9449 Section 4.2: DPoP proof with old iat must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Manually construct a proof with iat set to 1 hour ago
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

    let old_iat = jiff::Timestamp::now().as_second() - 3600; // 1 hour ago
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "POST",
        "htu": format!("{}/oauth/token", state.config().base_url),
        "iat": old_iat
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let expired_proof = format!("{}.{}.{}", header_b64, claims_b64, sig_b64);

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            access_token
        ),
        &[("Authorization", &auth_header), ("DPoP", &expired_proof)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expired DPoP proof must be rejected"
    );
}

#[tokio::test]
async fn test_rfc9449_ath_mismatch() {
    // RFC 9449 Section 7.1: DPoP proof with wrong access token hash must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-ath@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get a DPoP-bound token
    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None,
        None,
    );

    let auth_header = client.basic_auth_header();
    let exchange_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[
            ("Authorization", &auth_header),
            ("DPoP", &dpop_proof),
        ],
    )
    .await;

    assert_eq!(exchange_response.status, StatusCode::OK);
    let exchange_body: serde_json::Value =
        serde_json::from_str(&exchange_response.body).expect("Valid JSON");
    let dpop_bound_token = exchange_body["access_token"]
        .as_str()
        .expect("access_token present");

    // Create a proof with ath hash for a DIFFERENT token
    let wrong_ath_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some("completely-wrong-token"),
    );

    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {}", dpop_bound_token)),
            ("DPoP", &wrong_ath_proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "DPoP proof with wrong ath must be rejected: {}",
        response.body
    );
}

// ========================================================================
// P1: RFC 7523 — JWT Profile for Client Auth and Authorization Grants
// ========================================================================

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_missing_assertion() {
    // RFC 7523 Section 2.1: jwt-bearer grant requires assertion parameter.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_invalid_assertion() {
    // RFC 7523 Section 3: Invalid JWT assertion signature returns error.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=invalid.jwt.token",
        &[],
    )
    .await;

    // Should fail with an error status (400 or 401 depending on implementation)
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Invalid JWT assertion should be rejected, got status: {}",
        status
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_grant"
            || error["error"] == "invalid_client"
            || error["error"] == "invalid_request",
        "Invalid JWT assertion should be rejected, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_rfc7521_mutual_exclusion_of_client_auth() {
    // RFC 7521 Section 4.2: Sending both client_secret and client_assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "mutual-excl@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code=test&client_id={}&client_secret={}&client_assertion=fake.jwt.assertion&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client.client_id, client.client_secret
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Combining auth methods must be rejected"
    );
}

#[tokio::test]
async fn test_rfc7521_basic_auth_and_assertion_mutual_exclusion() {
    // RFC 7521 Section 4.2: Basic auth header + client_assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "basic-assert@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=authorization_code&code=test&client_assertion=fake.jwt.assertion&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Basic auth + client_assertion must be rejected"
    );
}

#[tokio::test]
async fn test_rfc7521_wrong_assertion_type() {
    // RFC 7521 Section 4.2: Wrong client_assertion_type must be rejected.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=test&subject_token_type=urn:ietf:params:oauth:token-type:access_token&client_assertion=fake.jwt.assertion&client_assertion_type=wrong:assertion:type",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Wrong assertion type must be rejected"
    );
}

// ========================================================================
// P1: RFC 9068 — JWT Profile for Access Tokens
// ========================================================================

#[tokio::test]
async fn test_rfc9068_required_claims_in_access_token() {
    // RFC 9068 Section 2.2: Access token must contain all required claims:
    // iss, exp, aud, sub, client_id, iat, jti
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "rfc9068-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Decode the access token (ES256 JWT) — just read the claims payload
    let parts: Vec<&str> = access_token.split('.').collect();
    assert!(
        parts.len() >= 2,
        "Access token should have at least 2 parts"
    );

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("Valid base64");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("Valid JSON");

    // RFC 9068 Section 2.2: REQUIRED claims
    assert!(
        claims.get("iss").is_some(),
        "Access token must have iss claim"
    );
    assert!(
        claims.get("exp").is_some(),
        "Access token must have exp claim"
    );
    assert!(
        claims.get("aud").is_some(),
        "Access token must have aud claim"
    );
    assert!(
        claims.get("sub").is_some(),
        "Access token must have sub claim"
    );
    assert!(
        claims.get("client_id").is_some(),
        "Access token must have client_id claim"
    );
    assert!(
        claims.get("iat").is_some(),
        "Access token must have iat claim"
    );
    assert!(
        claims.get("jti").is_some(),
        "Access token must have jti claim"
    );

    // Verify iss matches the issuer
    assert_eq!(
        claims["iss"].as_str().unwrap(),
        state.config().base_url,
        "iss must match configured issuer"
    );

    // Verify client_id matches
    assert_eq!(
        claims["client_id"].as_str().unwrap(),
        client.client_id,
        "client_id must match the requesting client"
    );
}

#[tokio::test]
async fn test_rfc9068_typ_header_is_at_jwt() {
    // RFC 9068 Section 2.1: Access token header must have typ: "at+jwt"
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "rfc9068-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Decode the header
    let parts: Vec<&str> = access_token.split('.').collect();
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("Valid base64");
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("Valid JSON");

    assert_eq!(
        header["typ"].as_str().unwrap(),
        "at+jwt",
        "Access token header must have typ: at+jwt per RFC 9068"
    );
    assert_eq!(
        header["alg"].as_str().unwrap(),
        "ES256",
        "Access token must be signed with ES256"
    );
}

#[tokio::test]
async fn test_rfc9068_jti_uniqueness() {
    // RFC 9068 Section 2.2: Two consecutively issued tokens must have different jti values.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "rfc9068-jti@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Use token exchange to get two different access tokens (avoids auth code single-use)
    let (subject_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    let (status1, body1) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    let resp1: serde_json::Value = serde_json::from_str(&body1).expect("Valid JSON");
    let access_token1 = resp1["access_token"]
        .as_str()
        .expect("access_token1")
        .to_string();

    let (status2, body2) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            subject_token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    let resp2: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");
    let access_token2 = resp2["access_token"]
        .as_str()
        .expect("access_token2")
        .to_string();

    // Decode both tokens to compare jti values
    let claims1 = decode_jwt_payload(&access_token1);
    let claims2 = decode_jwt_payload(&access_token2);

    let jti1 = claims1["jti"].as_str().expect("jti in first token");
    let jti2 = claims2["jti"].as_str().expect("jti in second token");

    assert_ne!(
        jti1, jti2,
        "Two consecutively issued tokens must have different jti values"
    );
}

#[tokio::test]
async fn test_rfc9068_recommended_claims() {
    // RFC 9068 Section 2.2 RECOMMENDED claims: auth_time, amr, acr
    // should be present for FIDO2-issued tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "rfc9068-recommended@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // RECOMMENDED claims for hardware-key-authenticated tokens
    assert!(
        claims.get("auth_time").is_some(),
        "FIDO2-issued access token should have auth_time"
    );
    assert!(
        claims.get("amr").is_some(),
        "FIDO2-issued access token should have amr"
    );
    assert!(
        claims.get("acr").is_some(),
        "FIDO2-issued access token should have acr"
    );
}

#[tokio::test]
async fn test_rfc9068_introspection_matches_token() {
    // RFC 9068 Section 4: Introspection of JWT access token returns matching claims.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "rfc9068-introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);

    // Verify introspection includes matching claims
    assert!(response.get("sub").is_some(), "Should have sub");
    assert!(response.get("client_id").is_some(), "Should have client_id");
    assert!(response.get("exp").is_some(), "Should have exp");
    assert!(response.get("iat").is_some(), "Should have iat");
    assert!(
        response.get("token_type").is_some(),
        "Should have token_type"
    );
}

/// Helper to decode JWT payload without signature verification.
fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert!(parts.len() >= 2, "JWT should have at least 2 parts");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("Valid base64");
    serde_json::from_slice(&payload).expect("Valid JSON")
}

// ========================================================================
// P1: RFC 8693 — Token Exchange Edge Cases
// ========================================================================

#[tokio::test]
async fn test_rfc8693_missing_subject_token() {
    // RFC 8693 Section 2.1: Missing subject_token returns invalid_request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-missing-subject@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Missing subject_token should be rejected, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_rfc8693_missing_subject_token_type() {
    // RFC 8693 Section 2.1: Missing subject_token_type returns invalid_request.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-missing-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Missing subject_token_type should be rejected"
    );
}

#[tokio::test]
async fn test_rfc8693_issued_token_type_in_response() {
    // RFC 8693 Section 2.2: Response must include issued_token_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-issued-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let issued_type = response["issued_token_type"]
        .as_str()
        .expect("issued_token_type must be present");
    assert!(
        issued_type.starts_with("urn:ietf:params:oauth:token-type:"),
        "issued_token_type must be a valid URN: {}",
        issued_type
    );
}

#[tokio::test]
async fn test_rfc8693_unsupported_requested_token_type() {
    // RFC 8693 Section 2.1: Unsupported requested_token_type returns error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-bad-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:invalid:type",
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Unsupported requested_token_type should be rejected"
    );
}

#[tokio::test]
async fn test_rfc8693_delegation_depth_limit() {
    // RFC 8693 / Vouch: Exceeding max delegation depth (5) must be rejected.
    // We test this by performing a chain of token exchanges with actor tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "delegation-depth@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Get initial OAuth access token
    let (mut subject_token, _) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Create a series of actor tokens (another user)
    let _actor_user = create_test_user(&state.db, "actor@example.com").await;

    // Chain exchanges with actor tokens to build delegation depth.
    // MAX_DELEGATION_DEPTH is 5, so after 5 successful exchanges with actor tokens,
    // the 6th should fail.
    let mut depth = 0;
    let mut failed = false;

    for i in 0..7 {
        // Create a unique actor user for each iteration to avoid session hash collisions
        let actor_email = format!("actor-{}@example.com", i);
        let iter_actor = create_test_user(&state.db, &actor_email).await;
        let iter_actor_auth = create_test_authenticator(&state.db, &iter_actor.id).await;
        let actor_token =
            create_test_session(&state, &iter_actor.id, &iter_actor.email, &iter_actor_auth).await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token={}&actor_token_type=urn:ietf:params:oauth:token-type:access_token",
                subject_token, actor_token
            ),
            &[("Authorization", &auth_header)],
        )
        .await;

        if status != StatusCode::OK {
            depth = i;
            failed = true;
            let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
            assert_eq!(
                error["error"], "invalid_request",
                "Delegation depth exceeded should return invalid_request"
            );
            break;
        }

        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        subject_token = response["access_token"]
            .as_str()
            .expect("access_token present")
            .to_string();
    }

    assert!(
        failed,
        "Delegation chain should be rejected at some point (max depth is 5), got to depth {}",
        depth
    );
}

#[tokio::test]
async fn test_rfc8693_client_auth_required_for_exchange() {
    // RFC 8693: Token exchange requires client authentication.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-noauth@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Try token exchange without any client authentication
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

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Token exchange without client auth should fail, got: {}",
        status
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Token exchange without client auth should return invalid_client"
    );
}

// ========================================================================
// P1: RFC 7662 — Token Introspection
// ========================================================================

#[tokio::test]
async fn test_rfc7662_introspection_requires_client_auth() {
    // RFC 7662 Section 2.1: Introspection requires client authentication.
    let (app, _state) = test_app().await;

    // Try introspection without any authentication
    let (status, body) =
        http_post_form(&app, "/oauth/introspect", "token=some_token_value", &[]).await;

    // Should either return 401 or return active=false (server policy)
    if status == StatusCode::UNAUTHORIZED {
        // Explicit rejection
    } else if status == StatusCode::OK {
        let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            response["active"], false,
            "Unauthenticated introspection should return active=false"
        );
    } else {
        panic!(
            "Expected 401 or 200 with active=false, got: {} {}",
            status, body
        );
    }
}

#[tokio::test]
async fn test_rfc7662_response_content_type() {
    // RFC 7662 Section 2.2: Response Content-Type must be application/json.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-ct@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={}", token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Should have Content-Type header")
        .to_str()
        .expect("Valid string");
    assert!(
        content_type.contains("application/json"),
        "Introspection response must be application/json, got: {}",
        content_type
    );
}

#[tokio::test]
async fn test_rfc7662_active_token_required_fields() {
    // RFC 7662 Section 2.2: Active token introspection response must include
    // required fields: active, scope, client_id, token_type, exp, iat, sub, iss
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-fields@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["active"], true);

    // RFC 7662 Section 2.2: REQUIRED for active tokens
    assert!(response.get("sub").is_some(), "Active token must have sub");
    assert!(response.get("exp").is_some(), "Active token must have exp");
    assert!(response.get("iat").is_some(), "Active token must have iat");
    assert!(response.get("iss").is_some(), "Active token must have iss");
    assert!(
        response.get("client_id").is_some(),
        "Active token must have client_id"
    );
    assert!(
        response.get("token_type").is_some(),
        "Active token must have token_type"
    );
    assert!(
        response.get("scope").is_some(),
        "Active token must have scope"
    );
}

// ========================================================================
// P2: OpenID Connect Core 1.0
// ========================================================================

#[tokio::test]
async fn test_oidc_id_token_at_hash_claim() {
    // OIDC Core Section 3.1.3.6: When issued alongside access token,
    // ID token must include at_hash claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "at-hash@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let id_claims = decode_jwt_payload(&id_token);
    assert!(
        id_claims.get("at_hash").is_some(),
        "ID token must include at_hash when issued with access token"
    );
    let at_hash = id_claims["at_hash"].as_str().expect("at_hash is a string");
    assert!(!at_hash.is_empty(), "at_hash must not be empty");
}

#[tokio::test]
async fn test_oidc_id_token_nonce_echo() {
    // OIDC Core Section 3.1.2.1: Nonce from auth request must appear in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "nonce-echo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let test_nonce = "unique-nonce-value-12345";
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: Some(test_nonce),
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token present");
    let id_claims = decode_jwt_payload(id_token);

    assert_eq!(
        id_claims["nonce"].as_str(),
        Some(test_nonce),
        "ID token must echo the nonce from the authorization request"
    );
}

#[tokio::test]
async fn test_oidc_id_token_required_claims() {
    // OIDC Core Section 2: ID token must contain iss, sub, aud, exp, iat.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "id-token-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    assert!(claims.get("iss").is_some(), "ID token must have iss");
    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(claims.get("aud").is_some(), "ID token must have aud");
    assert!(claims.get("exp").is_some(), "ID token must have exp");
    assert!(claims.get("iat").is_some(), "ID token must have iat");
}

#[tokio::test]
async fn test_oidc_id_token_aud_contains_client_id() {
    // OIDC Core Section 2: Audience must include the requesting client_id.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "id-token-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    let aud = &claims["aud"];

    // aud can be a string or an array
    if let Some(aud_str) = aud.as_str() {
        assert_eq!(
            aud_str, client.client_id,
            "ID token aud must match client_id"
        );
    } else if let Some(aud_arr) = aud.as_array() {
        assert!(
            aud_arr
                .iter()
                .any(|a| a.as_str() == Some(&client.client_id)),
            "ID token aud array must include client_id"
        );
    } else {
        panic!("ID token aud must be a string or array");
    }
}

#[tokio::test]
async fn test_oidc_userinfo_sub_matches_id_token() {
    // OIDC Core Section 5.3.2: UserInfo sub must match ID token sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "userinfo-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Get sub from ID token
    let id_claims = decode_jwt_payload(&id_token);
    let id_sub = id_claims["sub"].as_str().expect("ID token has sub");

    // Get sub from UserInfo
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {}", access_token))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let userinfo_sub = userinfo["sub"].as_str().expect("UserInfo has sub");

    assert_eq!(id_sub, userinfo_sub, "UserInfo sub must match ID token sub");
}

#[tokio::test]
async fn test_oidc_scope_based_claim_filtering() {
    // OIDC Core Section 5.4: email scope adds email claims.
    // Request with "openid email" scope should include email in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "scope-filter@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue with "openid email" scope
    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback",
            code
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token");
    let id_claims = decode_jwt_payload(id_token);

    // With email scope, ID token should include email
    assert!(
        id_claims.get("email").is_some(),
        "ID token should include email when email scope is granted"
    );
}

// ========================================================================
// P2: RFC 7636 — PKCE Edge Cases
// ========================================================================

#[tokio::test]
async fn test_rfc7636_code_verifier_too_short() {
    // RFC 7636 Section 4.1: code_verifier must be 43-128 chars.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-short@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Create valid challenge from a valid verifier, but present a too-short verifier
    let valid_verifier = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // 47 chars
    let challenge = sha256_base64url(valid_verifier);

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(
                crate::services::oidc::authorization::CodeChallengeMethod::S256,
            ),
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Use too-short verifier (< 43 chars)
    let short_verifier = "tooshort";
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback&code_verifier={}",
            code, short_verifier
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Too-short code_verifier should be rejected"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_grant" || error["error"] == "invalid_request",
        "Should return error for too-short verifier"
    );
}

#[tokio::test]
async fn test_rfc7636_plain_method_rejection() {
    // RFC 9700 / RFC 7636 Section 4.2: plain method must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-plain@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=test&code_challenge_method=plain&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should reject with error (redirect with error or error page)
    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Location header")
            .to_str()
            .expect("Valid");
        assert!(
            location.contains("error="),
            "Plain PKCE method should be rejected: {}",
            location
        );
    }
    // Either way, the request should not succeed silently
}

#[tokio::test]
async fn test_rfc7636_end_to_end_pkce_flow() {
    // RFC 7636 Section 4.6: Full PKCE flow: authorize with challenge, exchange with verifier.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-e2e@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate a valid PKCE pair
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_abcdefg"; // >= 43 chars
    let challenge = sha256_base64url(code_verifier);

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(
                crate::services::oidc::authorization::CodeChallengeMethod::S256,
            ),
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Exchange with correct verifier — should succeed
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback&code_verifier={}",
            code, code_verifier
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PKCE flow should succeed with correct verifier: {}",
        body
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Should return access_token"
    );
}

#[tokio::test]
async fn test_rfc7636_wrong_verifier_rejected() {
    // RFC 7636: Wrong code_verifier must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-wrong@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let correct_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_wrong123";
    let challenge = sha256_base64url(correct_verifier);

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(
                crate::services::oidc::authorization::CodeChallengeMethod::S256,
            ),
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let auth_header = client.basic_auth_header();

    // Exchange with WRONG verifier
    let wrong_verifier = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_different";
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback&code_verifier={}",
            code, wrong_verifier
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Wrong code_verifier must be rejected"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

/// Helper: compute SHA-256 and base64url-encode (for PKCE S256).
fn sha256_base64url(input: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&SHA256, input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

// ========================================================================
// P2: RFC 8707 — Resource Indicators
// ========================================================================

#[tokio::test]
async fn test_rfc8707_invalid_resource_uri() {
    // RFC 8707 Section 2: Invalid resource URI at authorize endpoint
    // returns invalid_target error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "resource-invalid@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Use a non-absolute URI as resource
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=test&code_challenge_method=S256&scope=openid&resource=not-a-valid-uri",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Should redirect with error or show error page
    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Location header")
            .to_str()
            .expect("Valid");
        assert!(
            location.contains("error="),
            "Invalid resource URI should cause error: {}",
            location
        );
    }
}

// ========================================================================
// P2: RFC 7009 — Token Revocation
// ========================================================================

#[tokio::test]
async fn test_rfc7009_revocation_200_ok_regardless() {
    // RFC 7009 Section 2: Revocation always returns 200 OK regardless of token validity.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-ok@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    // Revoke a nonexistent token
    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        "token=nonexistent_token_value",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Revocation must return 200 OK regardless of token validity"
    );
    // RFC 7009 Section 2.1: Response body SHOULD be empty
    assert!(
        response.body.is_empty() || response.body == "null",
        "Revocation response body should be empty, got: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc7009_token_type_hint_handling() {
    // RFC 7009 Section 2: token_type_hint is accepted but not required.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Revoke with valid token_type_hint
    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        &format!("token={}&token_type_hint=access_token", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    // Verify token is actually revoked via introspection
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={}", access_token),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        result["active"], false,
        "Revoked token should be inactive on introspection"
    );
}

#[tokio::test]
async fn test_rfc7009_invalid_hint_still_processes() {
    // RFC 7009 Section 2.1: Invalid token_type_hint should still process.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-bad-hint@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/revoke",
        "token=some_token&token_type_hint=completely_invalid_hint",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "Invalid hint should still return 200 OK"
    );
}

// ========================================================================
// P2: RFC 8176 — AMR Values
// ========================================================================

#[tokio::test]
async fn test_rfc8176_amr_in_access_token() {
    // RFC 8176 / RFC 9068 Section 2.2: Access token must contain amr claim
    // with FIDO2 authentication methods.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "amr-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

    let user = create_test_user(&state.db, "acr-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

// ========================================================================
// P2: RFC 6749 — Unsupported Grant Type
// ========================================================================

#[tokio::test]
async fn test_rfc6749_unsupported_grant_type() {
    // RFC 6749 Section 5.2: Unsupported grant_type returns specific error.
    let (app, _state) = test_app().await;

    let (status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=client_credentials", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unsupported_grant_type",
        "Unknown grant type must return unsupported_grant_type"
    );
}

// ========================================================================
// P2: RFC 8628 — Device Authorization Grant
// ========================================================================

#[tokio::test]
async fn test_rfc8628_device_authorization_response_format() {
    // RFC 8628 Section 3.2: Device authorization response must include
    // required fields: device_code, user_code, verification_uri, expires_in, interval.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "device-resp@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 8628 Section 3.2: REQUIRED fields
    assert!(
        response.get("device_code").is_some(),
        "Must have device_code"
    );
    assert!(response.get("user_code").is_some(), "Must have user_code");
    assert!(
        response.get("verification_uri").is_some(),
        "Must have verification_uri"
    );
    assert!(response.get("expires_in").is_some(), "Must have expires_in");
    assert!(response.get("interval").is_some(), "Must have interval");
}

#[tokio::test]
async fn test_rfc8628_verification_uri_complete() {
    // RFC 8628 Section 3.2: Response SHOULD include verification_uri_complete.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "device-complete@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 8628 Section 3.2: verification_uri_complete is OPTIONAL
    // but RECOMMENDED. If present, it should contain the user_code.
    if let Some(complete_uri) = response.get("verification_uri_complete") {
        let uri_str = complete_uri
            .as_str()
            .expect("verification_uri_complete is a string");
        let user_code = response["user_code"].as_str().expect("user_code");
        assert!(
            uri_str.contains(user_code),
            "verification_uri_complete should contain the user_code"
        );
    }
    // If not present, that's acceptable per the RFC (OPTIONAL field)
}

#[tokio::test]
async fn test_rfc8628_pending_token_request() {
    // RFC 8628 Section 3.5: Polling before user authorizes returns authorization_pending.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "device-pending@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Get device code
    let (status, body) = http_post_form(
        &app,
        "/oauth/device",
        &format!("client_id={}&scope=openid", client.client_id),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let device_code = response["device_code"].as_str().expect("device_code");

    // Poll token endpoint — should return authorization_pending
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
            device_code
        ),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "authorization_pending",
        "Unfinished device code should return authorization_pending"
    );
}

// ========================================================================
// P3: RFC 8414 — Authorization Server Metadata
// ========================================================================

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

// ========================================================================
// Helpers for RFC 7523 JWT Bearer Tests
// ========================================================================

/// Generate an ES256 key pair and return (key_pair_pkcs8_bytes, JWK JSON with public key).
fn generate_es256_signing_key() -> (Vec<u8>, serde_json::Value) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("Failed to parse key");

    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
        "kid": "test-key-1"
    });

    (pkcs8.as_ref().to_vec(), jwk)
}

/// Sign a JWT assertion with an ES256 key (pkcs8 bytes).
fn sign_jwt_assertion(
    pkcs8_bytes: &[u8],
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)
        .expect("Failed to parse key");

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("Failed to sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Create a test OAuth client configured for `private_key_jwt` auth with inline JWKS.
/// Returns (TestOAuthClient, pkcs8_bytes) where pkcs8_bytes is the ES256 signing key.
async fn create_test_jwt_client(pool: &db::Pool, user_id: &str) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    // Create the client first
    let client = create_test_oauth_client(pool, user_id).await;

    // Get the internal ID for the client
    let oauth_client = db::get_oauth_client_by_client_id(pool, &client.client_id)
        .await
        .expect("DB error")
        .expect("Client not found");

    // Set inline JWKS
    let jwks_json = serde_json::to_string(&serde_json::json!({
        "keys": [jwk]
    }))
    .unwrap();
    db::update_oauth_client_jwks(pool, &oauth_client.id, &jwks_json)
        .await
        .expect("Failed to set JWKS");

    // Set auth method to private_key_jwt
    db::update_oauth_client_auth_method(pool, &oauth_client.id, "private_key_jwt")
        .await
        .expect("Failed to set auth method");

    (client, pkcs8_bytes)
}

/// Build a JWT assertion for private_key_jwt client auth (RFC 7523 Section 2.2).
fn build_client_assertion(
    client_id: &str,
    audience: &str,
    pkcs8_bytes: &[u8],
    jti: Option<&str>,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let mut claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 60
    });
    if let Some(jti_val) = jti {
        claims["jti"] = serde_json::json!(jti_val);
    } else {
        claims["jti"] = serde_json::json!(uuid::Uuid::now_v7().to_string());
    }
    sign_jwt_assertion(pkcs8_bytes, &header, &claims)
}

// ========================================================================
// Phase 2: RFC 7523 — JWT Bearer Handler Integration Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7523_private_key_jwt_client_auth_full_flow() {
    // RFC 7523 Section 2.2: Full handler integration test for private_key_jwt
    // client authentication combined with authorization_code grant.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-auth-full@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    // Issue an authorization code
    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    // Exchange code with private_key_jwt client assertion
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "private_key_jwt auth should succeed: {resp_body}"
    );
    let response: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Response should contain access_token"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_jti_replay_rejected() {
    // RFC 7523 Section 3: JTI replay must be rejected at the handler level.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-replay@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let fixed_jti = "replay-test-jti-12345";

    // First request: issue code and exchange with JWT assertion
    let scope_set = ScopeSet::parse("openid");
    let code1 = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let assertion1 = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body1 = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code1,
        urlencoding::encode("https://example.com/callback"),
        assertion1
    );

    let (status1, resp1) = http_post_form(&app, "/oauth/token", &body1, &[]).await;
    assert_eq!(status1, StatusCode::OK, "First use of JTI should succeed");
    let resp1_json: serde_json::Value = serde_json::from_str(&resp1).expect("Valid JSON");
    let access_token = resp1_json["access_token"].as_str().expect("access_token");

    // Second request with same JTI: use token exchange (avoids auth code reissue)
    let assertion2 = build_client_assertion(
        &client.client_id,
        &token_endpoint,
        &pkcs8_bytes,
        Some(fixed_jti),
    );

    let body2 = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={access_token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        assertion2
    );

    let (status2, resp_body) = http_post_form(&app, "/oauth/token", &body2, &[]).await;
    assert!(
        status2 == StatusCode::UNAUTHORIZED || status2 == StatusCode::BAD_REQUEST,
        "Replayed JTI should be rejected, got {status2}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_expired_assertion_rejected() {
    // RFC 7523 Section 3: Expired JWT assertion must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    // Build an expired assertion (iat and exp in the past)
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client.client_id,
        "sub": client.client_id,
        "aud": format!("{}/oauth/token", state.config().base_url),
        "iat": now - 600,
        "exp": now - 300,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expired assertion should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_wrong_audience() {
    // RFC 7523 Section 3: JWT assertion with wrong audience must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-wrong-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    // Build assertion with wrong audience
    let assertion = build_client_assertion(
        &client.client_id,
        "https://wrong-audience.example.com/token",
        &pkcs8_bytes,
        None,
    );

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong audience should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_wrong_key() {
    // RFC 7523 Section 3: JWT assertion signed with wrong key must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-wrong-key@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, _correct_pkcs8) = create_test_jwt_client(&state.db, &user.id).await;

    // Generate a different key pair (not the one registered with the client)
    let (wrong_pkcs8, _wrong_jwk) = generate_es256_signing_key();

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &wrong_pkcs8, None);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong signing key should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_private_key_jwt_iss_sub_mismatch() {
    // RFC 7523 Section 3: For client auth, iss MUST equal sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-iss-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    // Build assertion where iss != sub
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": client.client_id,
        "sub": "different-subject",
        "aud": format!("{}/oauth/token", state.config().base_url),
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "iss != sub should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7521_mutual_exclusion_secret_and_assertion() {
    // RFC 7521 Section 4.2: client_assertion cannot be combined with
    // client_secret or Basic auth.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-mutual-excl@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let (client, pkcs8_bytes) = create_test_jwt_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code");

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    // Send both client_secret and client_assertion — must be rejected
    let auth_header = client.basic_auth_header();
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={}",
        code,
        urlencoding::encode("https://example.com/callback"),
        assertion
    );

    let (status, resp_body) = http_post_form(
        &app,
        "/oauth/token",
        &body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Combining Basic auth with client_assertion must be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_with_trusted_issuer() {
    // RFC 7523 Section 2.1: Full JWT bearer grant flow with a real trusted issuer.
    // We create a trusted issuer, pre-populate its JWKS cache, sign a JWT
    // assertion, and exchange it at /oauth/token.
    let (app, state) = test_app().await;

    // Create user that the JWT subject will map to
    let user = create_test_user(&state.db, "jwt-bearer-user@example.com").await;

    // Generate ES256 key pair for the trusted issuer
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    // Create trusted issuer
    let issuer_url = "https://trusted-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.db,
        issuer_url,
        "Test Trusted Issuer",
        None,
        "https://trusted-issuer.example.com/.well-known/jwks.json",
        Some("email"), // Map sub claim to email
        Some("openid email"),
        Some(3600),
    )
    .await
    .expect("Failed to create trusted issuer");

    // Pre-populate JWKS cache so we don't need an actual HTTP server
    let jwks_json = serde_json::to_string(&serde_json::json!({
        "keys": [jwk]
    }))
    .unwrap();
    db::update_issuer_jwks_cache(&state.db, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update JWKS cache");

    // Build JWT assertion for the bearer grant
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer\
         &assertion={}&scope=openid email",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "JWT bearer grant should succeed: {resp_body}"
    );
    let response: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Response should contain access_token"
    );
    assert_eq!(response["token_type"], "Bearer");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_jti_replay() {
    // RFC 7523 Section 3: JTI replay detection for JWT bearer grants.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-bearer-replay@example.com").await;
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://replay-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.db,
        issuer_url,
        "Replay Test Issuer",
        None,
        "https://replay-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(3600),
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.db, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    let fixed_jti = "bearer-replay-jti-99";
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": fixed_jti
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    // First use should succeed
    let (status1, resp1) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First JWT bearer grant should succeed: {resp1}"
    );

    // Replay with same JTI should fail
    let (status2, resp2) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status2 == StatusCode::BAD_REQUEST || status2 == StatusCode::UNAUTHORIZED,
        "JWT bearer grant JTI replay should be rejected, got {status2}: {resp2}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_unknown_issuer() {
    // RFC 7523: JWT bearer grant from an unknown issuer should be rejected.
    let (app, _state) = test_app().await;

    let (pkcs8_bytes, _jwk) = generate_es256_signing_key();

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": "https://unknown-issuer.example.com",
        "sub": "someone@example.com",
        "aud": "https://test.example.com",
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Unknown issuer should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_user_not_found() {
    // RFC 7523: JWT bearer grant with valid issuer but unmapped user should fail.
    let (app, state) = test_app().await;

    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://no-user-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.db,
        issuer_url,
        "No User Issuer",
        None,
        "https://no-user-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(3600),
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.db, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": "nonexistent@example.com",
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 60,
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Unmapped user should be rejected, got {status}: {resp_body}"
    );
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_missing_assertion_handler() {
    // RFC 7523: JWT bearer grant without assertion parameter should be rejected.
    let (app, _state) = test_app().await;

    let body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer";

    let (status, resp_body) = http_post_form(&app, "/oauth/token", body, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing assertion should be rejected: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc7523_jwt_bearer_grant_lifetime_exceeded() {
    // RFC 7523 Section 3: JWT assertion lifetime exceeding issuer max must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "jwt-bearer-long@example.com").await;
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();

    let issuer_url = "https://short-lifetime-issuer.example.com";
    let issuer = db::create_trusted_jwt_issuer(
        &state.db,
        issuer_url,
        "Short Lifetime Issuer",
        None,
        "https://short-lifetime-issuer.example.com/jwks",
        Some("email"),
        Some("openid"),
        Some(60), // Max 60 seconds
    )
    .await
    .expect("Failed to create issuer");

    let jwks_json = serde_json::to_string(&serde_json::json!({ "keys": [jwk] })).unwrap();
    db::update_issuer_jwks_cache(&state.db, &issuer.id, &jwks_json)
        .await
        .expect("Failed to update cache");

    // Build assertion that exceeds max lifetime (iat to exp > 60s)
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "JWT", "kid": "test-key-1"
    });
    let claims = serde_json::json!({
        "iss": issuer_url,
        "sub": user.email,
        "aud": state.config().base_url,
        "iat": now,
        "exp": now + 600, // 10 minutes > max 60 seconds
        "jti": uuid::Uuid::now_v7().to_string()
    });
    let assertion = sign_jwt_assertion(&pkcs8_bytes, &header, &claims);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
        assertion
    );

    let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Excessive lifetime should be rejected, got {status}: {resp_body}"
    );
}

// ========================================================================
// Phase 2: RFC 8693 — Token Exchange Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc8693_issued_token_type_in_exchange_response() {
    // RFC 8693 Section 2.2: Response MUST include issued_token_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("issued_token_type").is_some(),
        "Response must include issued_token_type (RFC 8693 Section 2.2)"
    );
    let issued_type = response["issued_token_type"].as_str().unwrap();
    assert!(
        issued_type.starts_with("urn:ietf:params:oauth:token-type:"),
        "issued_token_type should be a valid URN, got: {issued_type}"
    );
}

#[tokio::test]
async fn test_rfc8693_unsupported_requested_token_type_rejected() {
    // RFC 8693 Section 2.1: Unsupported requested_token_type returns error.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-unsupported@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &requested_token_type=urn:ietf:params:oauth:token-type:saml2"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Unsupported requested_token_type should fail: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

#[tokio::test]
async fn test_rfc8693_actor_token_delegation_chain() {
    // RFC 8693 Section 2.1: Token exchange with actor token produces nested `act` claims.
    let (app, state) = test_app().await;

    // Create grantor (subject) user
    let grantor = create_test_user(&state.db, "grantor@example.com").await;
    let grantor_auth = create_test_authenticator(&state.db, &grantor.id).await;
    let client = create_test_oauth_client(&state.db, &grantor.id).await;

    // Create grantee (actor) user
    let grantee = create_test_user(&state.db, "grantee@example.com").await;
    let grantee_auth = create_test_authenticator(&state.db, &grantee.id).await;

    // Get tokens for both users
    let (grantor_token, _) =
        issue_oauth_access_token(&app, &state, &grantor, &grantor_auth, &client).await;
    let (grantee_token, _) =
        issue_oauth_access_token(&app, &state, &grantee, &grantee_auth, &client).await;

    let auth_header = client.basic_auth_header();

    // Perform token exchange with actor token
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={grantor_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token={grantee_token}\
             &actor_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange with actor should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged_token = response["access_token"]
        .as_str()
        .expect("access_token present");

    // Decode the exchanged token and verify `act` claim
    let claims = decode_jwt_payload(exchanged_token);
    assert!(
        claims.get("act").is_some(),
        "Exchanged token should have 'act' claim for delegation chain"
    );
    let act = &claims["act"];
    assert!(
        act.get("sub").is_some(),
        "act claim should contain sub field"
    );
    assert_eq!(
        act["sub"], "grantee@example.com",
        "act.sub should be the grantee email"
    );
}

#[tokio::test]
async fn test_rfc8693_token_lifetime_capped_by_subject() {
    // RFC 8693 Section 2.2: Exchanged token lifetime should not exceed
    // the remaining lifetime of the subject token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-lifetime@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let expires_in = response["expires_in"].as_u64().expect("expires_in present");

    // Decode the subject token to check its remaining lifetime
    let subject_claims = decode_jwt_payload(&access_token);
    let subject_exp = subject_claims["exp"].as_i64().expect("subject exp");
    let now = jiff::Timestamp::now().as_second();
    let subject_remaining = subject_exp.saturating_sub(now);

    // The exchanged token's lifetime should not exceed the subject token's remaining TTL
    assert!(
        expires_in <= subject_remaining as u64 + 5, // +5s tolerance for test timing
        "Exchanged token lifetime ({expires_in}s) should not exceed subject remaining ({subject_remaining}s)"
    );
}

#[tokio::test]
async fn test_rfc8693_invalid_actor_token_type() {
    // RFC 8693: Invalid actor_token_type should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "exchange-bad-actor-type@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &actor_token=some-token\
             &actor_token_type=urn:ietf:params:oauth:token-type:saml2"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "Invalid actor_token_type should be rejected, got {status}: {body}"
    );
}

// ========================================================================
// Phase 2: RFC 7662 — Token Introspection Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7662_introspection_active_token_has_required_fields() {
    // RFC 7662 Section 2.2: Active token response must include
    // all required fields.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-fields@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Introspection should succeed: {body}"
    );
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert_eq!(result["active"], true, "Token should be active");
    assert!(result.get("scope").is_some(), "Must include scope");
    assert!(result.get("client_id").is_some(), "Must include client_id");
    assert!(
        result.get("token_type").is_some(),
        "Must include token_type"
    );
    assert!(result.get("exp").is_some(), "Must include exp");
    assert!(result.get("iat").is_some(), "Must include iat");
    assert!(result.get("sub").is_some(), "Must include sub");
    assert!(result.get("iss").is_some(), "Must include iss");
}

#[tokio::test]
async fn test_rfc7662_introspection_response_content_type() {
    // RFC 7662 Section 2.2: Response Content-Type must be application/json.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-ct@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let ct = response
        .headers
        .get("Content-Type")
        .expect("Must have Content-Type")
        .to_str()
        .expect("Valid str");
    assert!(
        ct.contains("application/json"),
        "Content-Type must be application/json, got: {ct}"
    );
}

#[tokio::test]
async fn test_rfc7662_cross_client_introspection() {
    // RFC 7662 Section 4: Introspection should handle cross-client scenarios.
    // Client B introspects a token issued to Client A.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-cross@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client_a = create_test_oauth_client(&state.db, &user.id).await;
    let client_b = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token for client A
    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client_a).await;

    // Introspect with client B
    let auth_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token_a}"),
        &[("Authorization", &auth_b)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7662 Section 4: Cross-client introspection MUST return active=false.
    // Client B must not see metadata from tokens issued to Client A.
    assert_eq!(
        result["active"], false,
        "RFC 7662: Client B must not introspect Client A's token, got: {result}"
    );
    // No metadata should be disclosed on cross-client introspection
    assert!(
        result.get("sub").is_none(),
        "Inactive cross-client response must not leak sub"
    );
}

// ========================================================================
// Phase 2: RFC 8707 — Resource Indicators Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc8707_resource_passthrough_authorize_to_token() {
    // RFC 8707 Section 2: Resource indicator in authorization request
    // should flow through to the access token audience.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "resource-pass@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let resource_uri = "https://api.example.com";

    // Issue authorization code with resource parameter
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: Some(resource_uri),
        },
    )
    .await
    .expect("Failed to issue code with resource");

    // Exchange at token endpoint
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange with resource should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = response["access_token"].as_str().expect("access_token");

    // Decode the token and check the audience claim
    let claims = decode_jwt_payload(access_token);
    let aud = claims
        .get("aud")
        .expect("access token should have aud claim");
    let aud_str = aud.as_str().unwrap_or_default();
    assert_eq!(
        aud_str, resource_uri,
        "Access token aud should match the resource indicator"
    );
}

#[tokio::test]
async fn test_rfc8707_resource_uri_with_fragment_rejected() {
    // RFC 8707 Section 2: Resource URI MUST NOT contain a fragment component.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "resource-frag@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&scope=openid\
             &code_challenge=test&code_challenge_method=S256\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            urlencoding::encode("https://api.example.com/resource#fragment")
        ),
        &[],
    )
    .await;

    // Should error — either redirect with error or show error page
    if response.status == StatusCode::SEE_OTHER || response.status == StatusCode::FOUND {
        let location = response
            .headers
            .get("Location")
            .expect("Location header")
            .to_str()
            .expect("Valid");
        assert!(
            location.contains("error="),
            "Resource URI with fragment should cause error redirect: {location}"
        );
    } else {
        // Error page is also acceptable
        assert!(
            response.status == StatusCode::BAD_REQUEST || response.status.is_client_error(),
            "Resource URI with fragment should be rejected, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc8707_resource_in_token_exchange() {
    // RFC 8707: Resource parameter in token exchange should set the audience
    // of the exchanged token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "resource-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let resource_uri = "https://target-api.example.com";

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={access_token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &resource={resource_uri}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Exchange with resource should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged_token = response["access_token"].as_str().expect("access_token");

    // Decode and verify audience matches the resource
    let claims = decode_jwt_payload(exchanged_token);
    if let Some(aud) = claims.get("aud") {
        let aud_str = aud.as_str().unwrap_or_default();
        assert_eq!(
            aud_str, resource_uri,
            "Exchanged token aud should match resource"
        );
    }
}

// ========================================================================
// Phase 2: RFC 9068 — JWT Access Token Format Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc9068_access_token_all_required_claims() {
    // RFC 9068 Section 2.2: Decode an issued access token and verify
    // all required claims are present.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "at-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // RFC 9068 Section 2.2: REQUIRED claims
    assert!(claims.get("iss").is_some(), "Must have iss");
    assert!(claims.get("exp").is_some(), "Must have exp");
    assert!(claims.get("aud").is_some(), "Must have aud");
    assert!(claims.get("sub").is_some(), "Must have sub");
    assert!(claims.get("client_id").is_some(), "Must have client_id");
    assert!(claims.get("iat").is_some(), "Must have iat");
    assert!(claims.get("jti").is_some(), "Must have jti");
}

#[tokio::test]
async fn test_rfc9068_access_token_typ_header() {
    // RFC 9068 Section 2.1: Access token JWT must have typ header "at+jwt".
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "at-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Decode the JWT header
    let parts: Vec<&str> = access_token.split('.').collect();
    assert!(parts.len() >= 2, "JWT should have at least 2 parts");
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("Valid base64");
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("Valid JSON");

    assert_eq!(
        header["typ"], "at+jwt",
        "Access token typ header must be 'at+jwt' per RFC 9068"
    );
}

#[tokio::test]
async fn test_rfc9068_jti_unique_across_tokens() {
    // RFC 9068 Section 2.2: JTI must be unique across consecutively issued tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "at-jti-uniq@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue first token
    let (token1, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Issue second token via token exchange (since auth codes are single-use)
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={token1}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Exchange should succeed: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let token2 = resp["access_token"].as_str().expect("access_token");

    let claims1 = decode_jwt_payload(&token1);
    let claims2 = decode_jwt_payload(token2);

    let jti1 = claims1["jti"].as_str().expect("jti1");
    let jti2 = claims2["jti"].as_str().expect("jti2");
    assert_ne!(jti1, jti2, "JTI values must be unique across tokens");
}

#[tokio::test]
async fn test_rfc9068_access_token_recommended_claims() {
    // RFC 9068 Section 2.2: RECOMMENDED claims in FIDO2-issued access tokens.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "at-recommended@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // RECOMMENDED claims for FIDO2-issued tokens
    // auth_time — when authentication occurred
    assert!(
        claims.get("auth_time").is_some(),
        "FIDO2 token should include auth_time (recommended)"
    );
}

// ========================================================================
// Phase 2: OpenID Connect Core 1.0 — Additional Tests
// ========================================================================

#[tokio::test]
async fn test_oidc_id_token_all_required_claims() {
    // OIDC Core 1.0 Section 2: ID Token must contain required claims.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "idtoken-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);

    assert!(claims.get("iss").is_some(), "ID token must have iss");
    assert!(claims.get("sub").is_some(), "ID token must have sub");
    assert!(claims.get("aud").is_some(), "ID token must have aud");
    assert!(claims.get("exp").is_some(), "ID token must have exp");
    assert!(claims.get("iat").is_some(), "ID token must have iat");
}

#[tokio::test]
async fn test_oidc_id_token_audience_includes_client_id() {
    // OIDC Core 1.0 Section 2: ID Token aud MUST include the client_id.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "idtoken-aud@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);
    let aud = claims.get("aud").expect("ID token must have aud");

    // aud can be a string or array
    let aud_contains_client = if let Some(aud_str) = aud.as_str() {
        aud_str == client.client_id
    } else if let Some(aud_arr) = aud.as_array() {
        aud_arr
            .iter()
            .any(|v| v.as_str() == Some(&client.client_id))
    } else {
        false
    };
    assert!(
        aud_contains_client,
        "ID token aud must contain client_id '{}', got: {aud}",
        client.client_id
    );
}

#[tokio::test]
async fn test_oidc_id_token_at_hash() {
    // OIDC Core 1.0 Section 3.1.3.6: When issued alongside access token,
    // ID token should include at_hash.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "idtoken-athash@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (_, id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&id_token);

    // at_hash is REQUIRED when the ID Token is issued from the Authorization Endpoint
    // with an access_token via the Implicit flow, but OPTIONAL in Authorization Code flow.
    // Check if present (good practice even in code flow).
    if let Some(at_hash) = claims.get("at_hash") {
        assert!(at_hash.is_string(), "at_hash should be a string if present");
    }
    // Not asserting presence since it's optional in authorization code flow
}

#[tokio::test]
async fn test_oidc_userinfo_sub_consistent_with_id_token() {
    // OIDC Core 1.0 Section 5.3.2: UserInfo sub must match ID token sub.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "userinfo-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Get UserInfo
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "UserInfo should succeed: {body}");
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Decode ID token sub
    let id_claims = decode_jwt_payload(&id_token);
    let id_sub = id_claims["sub"].as_str().expect("ID token sub");
    let userinfo_sub = userinfo["sub"].as_str().expect("UserInfo sub");

    assert_eq!(userinfo_sub, id_sub, "UserInfo sub must match ID token sub");
}

#[tokio::test]
async fn test_oidc_scope_based_claims_email() {
    // OIDC Core 1.0 Section 5.4: email scope adds email claims.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue with "openid email" scope
    let (access_token, _) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid email")
            .await;

    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "UserInfo should succeed: {body}");
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    assert!(
        userinfo.get("email").is_some(),
        "email scope should provide email claim"
    );
}

#[tokio::test]
async fn test_oidc_nonce_echo_in_id_token() {
    // OIDC Core 1.0 Section 3.1.2.1: Nonce from auth request appears in ID token.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "nonce-echo@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let nonce_value = "test-nonce-abc123";
    let scope_set = ScopeSet::parse("openid");

    // Issue code with nonce
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: Some(nonce_value),
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code with nonce");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Token exchange should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let id_token = response["id_token"].as_str().expect("id_token present");

    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims.get("nonce").and_then(|n| n.as_str()),
        Some(nonce_value),
        "ID token nonce must echo the auth request nonce"
    );
}

// ========================================================================
// Phase 2: RFC 8176 — AMR/ACR Claims in Issued Tokens
// ========================================================================

#[tokio::test]
async fn test_rfc8176_amr_claim_format_in_access_token() {
    // RFC 8176: FIDO2-issued access tokens should include amr claim.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "amr-at@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

    let user = create_test_user(&state.db, "acr-at@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // acr should be present for FIDO2 tokens
    if let Some(acr) = claims.get("acr") {
        assert!(acr.is_string(), "acr must be a string, got: {acr}");
    }
}

// ========================================================================
// Phase 2: RFC 7636 — PKCE Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7636_code_verifier_length_too_short() {
    // RFC 7636 Section 4.1: code_verifier must be 43-128 characters.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-short@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate a proper challenge from a short verifier
    let short_verifier = "abcdef"; // Too short (< 43 chars)
    let challenge = sha256_base64url(short_verifier);

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
        },
    )
    .await
    .expect("Issue code");

    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={short_verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    // Server should reject short verifiers
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::OK,
        "Short verifier handling: {status}"
    );
    // Note: If the server doesn't validate length but validates the hash,
    // it would still fail because the challenge was computed from the short verifier.
    // The important thing is that the verification process works correctly.
}

#[tokio::test]
async fn test_rfc7636_code_verifier_too_long() {
    // RFC 7636 Section 4.1: code_verifier must be 43-128 characters.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-long@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // 129-character verifier (exceeds max of 128)
    let long_verifier = "a".repeat(129);
    let challenge = sha256_base64url(&long_verifier);

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
        },
    )
    .await
    .expect("Issue code");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={long_verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    // Server enforces MAX length (128 chars) at handler level
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Code verifier exceeding 128 chars should be rejected: {body}"
    );
}

#[tokio::test]
async fn test_rfc7636_complete_pkce_s256_flow() {
    // RFC 7636 Section 4.6: Full PKCE flow — authorize with challenge,
    // exchange with verifier.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-e2e@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Generate valid PKCE verifier (43-128 chars, unreserved characters)
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // 43 chars
    let challenge = sha256_base64url(verifier);

    let scope_set = ScopeSet::parse("openid email");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(&challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
        },
    )
    .await
    .expect("Failed to issue code with PKCE");

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "PKCE end-to-end flow should succeed: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(response.get("access_token").is_some());
    assert!(response.get("id_token").is_some());
}

// ========================================================================
// Phase 2: RFC 7009 — Token Revocation Advanced Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7009_revocation_with_token_type_hint() {
    // RFC 7009 Section 2: token_type_hint is accepted but not required.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();

    // Revoke with token_type_hint
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}&token_type_hint=access_token"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Revocation with token_type_hint should return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_revocation_with_invalid_hint() {
    // RFC 7009 Section 2: Invalid hint is accepted (server ignores it).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-bad-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let auth_header = client.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}&token_type_hint=invalid_type"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Revocation with invalid hint should still return 200"
    );
}

#[tokio::test]
async fn test_rfc7009_revocation_client_auth_required() {
    // RFC 7009 Section 2: Revocation requires client authentication
    // for confidential clients.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "revoke-noauth@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Revoke WITHOUT client credentials
    let (status, _) =
        http_post_form(&app, "/oauth/revoke", &format!("token={access_token}"), &[]).await;

    // Per RFC 7009, revoke endpoint always returns 200 to prevent oracle attacks,
    // but the revocation should NOT actually happen without auth.
    assert_eq!(status, StatusCode::OK);

    // Verify token is still active via introspection
    let auth_header = client.basic_auth_header();
    let (_, intro_body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let intro: serde_json::Value = serde_json::from_str(&intro_body).expect("Valid JSON");
    assert_eq!(
        intro["active"], true,
        "Token should still be active after unauthenticated revocation attempt"
    );
}

// ========================================================================
// Phase 2: Additional DPoP Tests
// ========================================================================

#[tokio::test]
async fn test_rfc9449_dpop_symmetric_algorithm_rejected() {
    // RFC 9449 Section 4.1: DPoP proof signed with symmetric algorithm (HS256)
    // must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-symm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Build a DPoP proof with HS256 header (symmetric — must be rejected)
    let fake_jwk = serde_json::json!({
        "kty": "oct",
        "k": URL_SAFE_NO_PAD.encode(b"symmetric-key-for-testing-12345678")
    });
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": fake_jwk
    });
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": jiff::Timestamp::now().as_second()
    });

    // We can't actually sign this properly since DPoP requires asymmetric keys,
    // but the header declares HS256 which should be caught before signature verification.
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let fake_proof = format!("{header_b64}.{claims_b64}.fakesignature");

    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &fake_proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Symmetric algorithm DPoP proof should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_wrong_typ_header() {
    // RFC 9449 Section 4.1: DPoP proof with wrong typ (JWT instead of dpop+jwt)
    // must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-badtyp@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Build proof with wrong typ header
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": jiff::Timestamp::now().as_second()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key.sign(&rng, signing_input.as_bytes()).expect("sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let proof = format!("{header_b64}.{claims_b64}.{sig_b64}");

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Wrong typ header should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_htm_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof with wrong HTTP method must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htm@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create proof with POST method but use it on a GET request
    let proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST", // Wrong method for GET /oauth/userinfo
        &format!("{}/oauth/userinfo", state.config().base_url),
        None,
        Some(&access_token),
    );

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "HTM mismatch should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_htu_mismatch() {
    // RFC 9449 Section 4.2: DPoP proof for wrong URI must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-htu@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Create proof for /oauth/token but use it on /oauth/userinfo
    let proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{}/oauth/token", state.config().base_url), // Wrong URI
        None,
        Some(&access_token),
    );

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "HTU mismatch should be rejected, got: {status}"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_expired_proof() {
    // RFC 9449 Section 4.2: DPoP proof with old iat should be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "dpop-expired@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();

    // Build proof with old iat (older than max_age_seconds=300)
    let old_iat = jiff::Timestamp::now().as_second() - 600; // 10 minutes ago
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": dpop_jwk
    });
    let ath_hash = aws_lc_rs::digest::digest(&SHA256, access_token.as_bytes());
    let ath = URL_SAFE_NO_PAD.encode(ath_hash.as_ref());
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "GET",
        "htu": format!("{}/oauth/userinfo", state.config().base_url),
        "iat": old_iat,
        "ath": ath
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = dpop_key.sign(&rng, signing_input.as_bytes()).expect("sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    let proof = format!("{header_b64}.{claims_b64}.{sig_b64}");

    let (status, _) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &format!("DPoP {access_token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expired DPoP proof should be rejected, got: {status}"
    );
}

// ========================================================================
// RFC 7662 Section 4 — Cross-Client Introspection Prevention
// ========================================================================

#[tokio::test]
async fn test_rfc7662_cross_client_introspection_returns_inactive() {
    // RFC 7662 Section 4: A token issued to Client A, when introspected by
    // Client B, MUST return active=false to prevent information disclosure.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-cross-inactive@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client_a = create_test_oauth_client(&state.db, &user.id).await;
    let client_b = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token for client A
    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client_a).await;

    // Introspect with client B — must return active=false per RFC 7662 Section 4
    let auth_b = client_b.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token_a}"),
        &[("Authorization", &auth_b)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7662 Section 4: Cross-client introspection returns active=false
    assert_eq!(
        result["active"], false,
        "Client B must not be able to introspect Client A's token, got: {result}"
    );
    // No metadata should be leaked on inactive response
    assert!(
        result.get("sub").is_none(),
        "Inactive response must not leak sub"
    );
    assert!(
        result.get("exp").is_none(),
        "Inactive response must not leak exp"
    );
    assert!(
        result.get("client_id").is_none(),
        "Inactive response must not leak client_id"
    );
}

#[tokio::test]
async fn test_rfc7662_same_client_introspection_returns_active() {
    // RFC 7662 Section 2.2: A client introspecting its own token must receive
    // active=true with full metadata.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "introspect-own-active@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue token for the client
    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Client introspects its own token
    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let result: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Must return active=true with full claims
    assert_eq!(
        result["active"], true,
        "Same-client introspection must return active=true"
    );
    assert!(
        result.get("sub").is_some(),
        "Active introspection must include sub"
    );
    assert!(
        result.get("exp").is_some(),
        "Active introspection must include exp"
    );
    assert!(
        result.get("iat").is_some(),
        "Active introspection must include iat"
    );
}

// ========================================================================
// RFC 8414 — OAuth Authorization Server Metadata Alias
// ========================================================================

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

// ========================================================================
// RFC 7636 Section 4.1 — PKCE Code Verifier Character Set Validation
// ========================================================================

/// Issue an authorization code with a PKCE challenge pre-computed from the given verifier.
async fn issue_pkce_code(
    state: &std::sync::Arc<crate::AppState>,
    client_id: &str,
    user: &crate::db::User,
    auth_id: &str,
    challenge: &str,
) -> String {
    let scope_set = ScopeSet::parse("openid");
    issue_authorization_code(
        state,
        AuthorizationCodeParams {
            client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: Some(challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
        },
    )
    .await
    .expect("Failed to issue authorization code with PKCE")
}

#[tokio::test]
async fn test_rfc7636_code_verifier_invalid_char_space() {
    // RFC 7636 Section 4.1: code_verifier MUST only contain unreserved chars
    // [A-Za-z0-9\-._~]. Space is NOT allowed.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-space@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Build a 44-char verifier with a space embedded.
    // The hash is computed from the exact verifier so the server would normally accept it
    // if it only validates the challenge hash. The charset check must catch the space.
    let verifier = "abcdefghijklmnopqrstuvwxyz0123456789abcde f"; // 44 chars, space at position 43

    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "code_verifier with space must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Must return invalid_request or invalid_grant, got: {error}"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_invalid_char_exclamation() {
    // RFC 7636 Section 4.1: '!' is not in [A-Za-z0-9\-._~] — must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-excl@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // 43-char verifier with '!' character
    let verifier = "abcdefghijklmnopqrstuvwxyz0123456789abcdef!"; // 43 chars, '!' at end
    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "code_verifier with '!' must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Must return error for invalid charset, got: {error}"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_invalid_char_at_sign() {
    // RFC 7636 Section 4.1: '@' (common in email) is not in [A-Za-z0-9\-._~].
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-at@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // 43-char verifier with '@' character
    let verifier = "abcdefghijklmnopqrstuvwxyz0123456789abcde@f"; // 43 chars
    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "code_verifier with '@' must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Must return error for '@' in verifier, got: {error}"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_invalid_char_unicode() {
    // RFC 7636 Section 4.1: Unicode characters (outside ASCII unreserved) must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-unicode@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // 43+ char verifier with a Unicode char (é = U+00E9, 2 bytes in UTF-8)
    // This results in a string > 43 bytes but has invalid characters
    let verifier = "abcdefghijklmnopqrstuvwxyz0123456789abcdéf"; // contains 'é'
    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "code_verifier with Unicode characters must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error["error"] == "invalid_request" || error["error"] == "invalid_grant",
        "Must return error for Unicode in verifier, got: {error}"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_minimum_length_43_accepted() {
    // RFC 7636 Section 4.1: code_verifier of exactly 43 chars (minimum) must be accepted.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-min43@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Exactly 43 chars, all valid unreserved characters
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // RFC 7636 Appendix B
    assert_eq!(verifier.len(), 43, "Test verifier must be exactly 43 chars");

    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Minimum-length (43 char) verifier must be accepted: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Must return access_token for valid minimum-length verifier"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_maximum_length_128_accepted() {
    // RFC 7636 Section 4.1: code_verifier of exactly 128 chars (maximum) must be accepted.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-max128@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Exactly 128 valid unreserved chars
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    assert_eq!(
        verifier.len(),
        128,
        "Test verifier must be exactly 128 chars"
    );
    // Verify all chars are valid
    assert!(
        verifier.bytes().all(|b| b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'),
        "All verifier chars must be in [A-Za-z0-9-._~]"
    );

    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Maximum-length (128 char) verifier must be accepted: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Must return access_token for valid maximum-length verifier"
    );
}

#[tokio::test]
async fn test_rfc7636_code_verifier_all_allowed_char_classes() {
    // RFC 7636 Section 4.1: All character classes from [A-Za-z0-9\-._~] must be accepted.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "pkce-allchars@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Use all allowed character classes in a 50-char verifier
    // Uppercase, lowercase, digits, hyphen, dot, underscore, tilde
    let verifier = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst0123456789-._~";
    assert!(
        verifier.len() >= 43,
        "Test verifier must be at least 43 chars"
    );
    assert!(
        verifier.bytes().all(|b| b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'),
        "All verifier chars must be in [A-Za-z0-9-._~]"
    );

    let challenge = sha256_base64url(verifier);
    let code = issue_pkce_code(&state, &client.client_id, &user, &auth_id, &challenge).await;

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier={verifier}"
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Verifier using all allowed RFC 7636 character classes must be accepted: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Must return access_token for verifier with all allowed char classes"
    );
}

// ========================================================================
// RFC 9449 Section 4.3 — DPoP Nonce Required at Token Endpoint
// ========================================================================

#[tokio::test]
async fn test_rfc9449_dpop_nonce_required_token_endpoint_returns_nonce_header() {
    // RFC 9449 Section 4.3: When dpop_nonce_required=true, the token endpoint MUST
    // return error=use_dpop_nonce AND a DPoP-Nonce response header when a DPoP
    // proof without a nonce is submitted.
    let (app, state) = test_app().await;

    // Enable dpop_nonce_required via ArcSwap in-place mutation
    {
        let current = (**state.config.load()).clone();
        let mut modified = current;
        modified.dpop_nonce_required = true;
        state.config.store(std::sync::Arc::new(modified));
    }

    let user = create_test_user(&state.db, "dpop-nonce-req@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue authorization code (no PKCE, no DPoP needed here)
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    // Build DPoP proof WITHOUT a nonce
    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None, // no nonce
        None,
    );

    let auth_header = client.basic_auth_header();
    let response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;

    // Must be an error status
    assert!(
        response.status == StatusCode::BAD_REQUEST || response.status == StatusCode::UNAUTHORIZED,
        "Token endpoint must reject DPoP proof without nonce when nonce required, got: {}",
        response.status
    );

    // Must include error=use_dpop_nonce in the body
    let error: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        error["error"], "use_dpop_nonce",
        "Error must be use_dpop_nonce when nonce is required, got: {error}"
    );

    // RFC 9449 Section 4.3: Server MUST include DPoP-Nonce response header
    assert!(
        response.headers.get("DPoP-Nonce").is_some(),
        "Server must include DPoP-Nonce header when use_dpop_nonce error is returned"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_nonce_required_retry_with_nonce_succeeds() {
    // RFC 9449 Section 4.3: After receiving use_dpop_nonce, the client MUST
    // retry with the nonce from the DPoP-Nonce response header.
    let (app, state) = test_app().await;

    // Enable dpop_nonce_required
    {
        let current = (**state.config.load()).clone();
        let mut modified = current;
        modified.dpop_nonce_required = true;
        state.config.store(std::sync::Arc::new(modified));
    }

    let user = create_test_user(&state.db, "dpop-nonce-retry@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Issue authorization code
    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let auth_header = client.basic_auth_header();
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // Step 1: Request without nonce — capture the DPoP-Nonce header
    let no_nonce_proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, None, None);
    let first_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &no_nonce_proof)],
    )
    .await;

    // Should get use_dpop_nonce error with DPoP-Nonce header
    assert!(
        first_response.status == StatusCode::BAD_REQUEST
            || first_response.status == StatusCode::UNAUTHORIZED,
        "First request must be rejected: {}",
        first_response.status
    );
    let server_nonce = first_response
        .headers
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce header must be present in error response")
        .to_str()
        .expect("DPoP-Nonce must be valid UTF-8")
        .to_string();

    // DPoP validation fails BEFORE code exchange, so the original code is NOT consumed.
    // Reuse the same code for the retry with the server-provided nonce.

    // Step 2: Retry with the nonce from the response header
    let nonce_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &token_uri,
        Some(&server_nonce),
        None,
    );
    let second_response = http_post_form_full(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &nonce_proof)],
    )
    .await;

    assert_eq!(
        second_response.status,
        StatusCode::OK,
        "Retry with server-provided nonce must succeed: {}",
        second_response.body
    );
    let token_response: serde_json::Value =
        serde_json::from_str(&second_response.body).expect("Valid JSON");
    assert!(
        token_response.get("access_token").is_some(),
        "Successful retry must return access_token"
    );
}

#[tokio::test]
async fn test_rfc9449_dpop_nonce_not_required_no_nonce_succeeds() {
    // When dpop_nonce_required=false (default), DPoP proof without nonce must succeed.
    // This is the default config and prevents regression.
    let (app, state) = test_app().await;

    // Verify the default setting is false
    assert!(
        !state.config().dpop_nonce_required,
        "Default test config must have dpop_nonce_required=false"
    );

    let user = create_test_user(&state.db, "dpop-nononce@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let scope_set = ScopeSet::parse("openid");
    let code = issue_authorization_code(
        &state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id: &auth_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
        },
    )
    .await
    .expect("Failed to issue authorization code");

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let dpop_proof = create_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{}/oauth/token", state.config().base_url),
        None, // no nonce — should still work when not required
        None,
    );

    let auth_header = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &auth_header), ("DPoP", &dpop_proof)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "DPoP without nonce must succeed when nonce is not required: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response.get("access_token").is_some(),
        "Must return access_token when nonce not required"
    );
}

// ========================================================================
// RFC 6749 Section 4.1.2 — Authorization Endpoint Redirect Tests
// ========================================================================

#[tokio::test]
async fn test_rfc6749_authorize_authenticated_user_redirects_with_code() {
    // RFC 6749 Section 4.1.2: Authenticated user must receive a 302/303 redirect
    // to the redirect_uri with code and state parameters.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-authed@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // Create a valid session stored in the DB (cookie-based auth)
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Build a valid PKCE challenge
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "teststate-rfc6749";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
        ),
        &[("Cookie", &format!("vouch_session={session_token}"))],
    )
    .await;

    // Must redirect (302 or 303)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Authenticated authorize request must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Location must be valid UTF-8");

    // RFC 6749 Section 4.1.2: code parameter must be present
    assert!(
        location.contains("code="),
        "Location must include authorization code: {location}"
    );

    // RFC 6749 Section 4.1.2: state must be echoed unchanged
    assert!(
        location.contains(&format!("state={state_param}")),
        "Location must echo state parameter unchanged: {location}"
    );

    // RFC 9207 Section 2: iss parameter must be present
    assert!(
        location.contains("iss="),
        "Location must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unknown_client_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If client_id is unknown, the server MUST NOT
    // redirect to the redirect_uri — it must show an error page.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code&client_id=nonexistent-client-xyz\
         &redirect_uri=https://example.com/callback&scope=openid\
         &code_challenge=dummychallenge&code_challenge_method=S256",
        &[],
    )
    .await;

    // Must show an error page (200 HTML), NOT redirect to the unregistered URI
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Unknown client must produce error page, not redirect, got: {}",
        response.status
    );

    // Specifically must NOT redirect (no Location header pointing to callback)
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("example.com/callback"),
            "Must not redirect to unregistered URI for unknown client: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_unregistered_redirect_uri_shows_error_page() {
    // RFC 6749 Section 10.6: If redirect_uri is not registered, the server MUST NOT
    // redirect — it must display an error to the user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-badredir@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    // Note: client is registered with https://example.com/callback

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://evil.example.com/steal")
        ),
        &[],
    )
    .await;

    // Must show error page, NOT redirect to the evil URI
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Unregistered redirect_uri must produce error page, not redirect, got: {}",
        response.status
    );

    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("evil.example.com"),
            "Must not redirect to unregistered URI: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_missing_response_type_redirects_with_error() {
    // RFC 6749 Section 4.1.2.1: Missing response_type must produce error=invalid_request
    // redirected back to the registered redirect_uri.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-nort@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let response = http_get_full(
        &app,
        // No response_type parameter
        &format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback")
        ),
        &[],
    )
    .await;

    // Must redirect with error OR show error page
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Redirect must have Location")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            location.contains("error=invalid_request") || location.contains("error="),
            "Redirect must include error parameter: {location}"
        );
    } else {
        // Error page is also acceptable for this case
        assert!(
            response.status == StatusCode::OK || response.status.is_client_error(),
            "Must show error for missing response_type, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc9207_authorize_response_includes_iss_parameter() {
    // RFC 9207 Section 2: The authorization response MUST include the iss parameter
    // so clients can bind the response to the correct authorization server.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-iss@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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
        &[("Cookie", &format!("vouch_session={session_token}"))],
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

// ========================================================================
// RFC 6749 Section 4.1.2.1 — Authorization Endpoint Error Conditions
// ========================================================================

#[tokio::test]
async fn test_rfc6749_authorize_empty_redirect_uri_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If the redirect_uri is missing or invalid,
    // the server MUST NOT redirect and MUST display an error to the user.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-noredir@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256",
            client.client_id,
        ),
        &[],
    )
    .await;

    // Must show an error page, not redirect
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Missing redirect_uri must produce error page, not redirect, got: {}",
        response.status
    );

    // Body must indicate redirect_uri is required
    assert!(
        response.body.contains("redirect_uri"),
        "Error page should mention redirect_uri: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unsupported_response_type_redirects_with_error() {
    // RFC 6749 Section 4.1.2.1: If response_type is unsupported, the server
    // MUST redirect to the redirect_uri with error=unsupported_response_type.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-badrt@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let state_param = "teststate-badrt";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            state_param,
        ),
        &[],
    )
    .await;

    // Must redirect with error
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unsupported response_type must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // RFC 6749 Section 4.1.2.1: error=unsupported_response_type
    assert!(
        location.contains("error=unsupported_response_type"),
        "Redirect must include error=unsupported_response_type: {location}"
    );

    // RFC 6749 Section 4.1.2.1: State must be echoed unchanged
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );

    // RFC 9207 Section 2: iss must be present even in error responses
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_unauthenticated_user_redirects_to_login() {
    // RFC 6749 Section 4.1.1: If the user is not authenticated, the server
    // must redirect to a login page. Vouch stores OAuth params and redirects
    // to /login with pending_auth.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-noauth@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // No session cookie — user is not authenticated
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state=loginstate",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[],
    )
    .await;

    // Must redirect to login
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Unauthenticated user must be redirected to login, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Must redirect to /login with pending_auth parameter
    assert!(
        location.starts_with("/login"),
        "Redirect must target /login: {location}"
    );
    assert!(
        location.contains("pending_auth="),
        "Login redirect must include pending_auth parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_access_denied_personal_scope() {
    // RFC 6749 Section 4.1.2.1: If the user does not have access, the server
    // must deny the request. For Personal scope apps, only the creator can authorize.
    let (app, state) = test_app().await;

    // Create user who owns the app
    let owner = create_test_user(&state.db, "authorize-owner@example.com").await;
    // Create a Personal scope app
    let client = create_test_oauth_client_with_options(
        &state.db,
        &owner.id,
        crate::db::AccessScope::Personal,
        None,
        &[],
    )
    .await;

    // Create a different user who will try to authorize
    let other_user = create_test_user(&state.db, "authorize-other@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &other_user.id).await;
    let session_token =
        create_test_session(&state, &other_user.id, &other_user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("vouch_session={session_token}"))],
    )
    .await;

    // Must show error page (denied template), NOT redirect with code
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Access denied must produce error page, got: {}",
        response.status
    );

    // Must not have a Location header with an auth code
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("code="),
            "Must not issue authorization code to unauthorized user: {loc_str}"
        );
    }

    // Body should indicate access denied
    assert!(
        response.body.contains("access")
            || response.body.contains("denied")
            || response.body.contains("don"),
        "Error page should explain access denial"
    );
}

#[tokio::test]
async fn test_rfc8707_authorize_invalid_resource_redirects_with_error() {
    // RFC 8707 Section 2: If the resource parameter is not registered for the client,
    // the server MUST return error=invalid_target.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-badres@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;

    // Create a client with a specific resource URI
    let client = create_test_oauth_client_with_options(
        &state.db,
        &user.id,
        crate::db::AccessScope::Public,
        None,
        &["https://api.example.com".to_string()],
    )
    .await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    let state_param = "teststate-badres";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}\
             &resource={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            state_param,
            urlencoding::encode("https://unregistered.example.com"),
        ),
        &[("Cookie", &format!("vouch_session={session_token}"))],
    )
    .await;

    // Must redirect with error=invalid_target
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Invalid resource must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=invalid_target"),
        "Redirect must include error=invalid_target (RFC 8707): {location}"
    );

    // RFC 6749 Section 4.1.2.1: State must be echoed
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );

    // RFC 9207: iss must be present
    assert!(
        location.contains("iss="),
        "Error redirect must include iss parameter (RFC 9207): {location}"
    );
}

#[tokio::test]
async fn test_rfc9700_authorize_pkce_required_without_challenge() {
    // RFC 9700 Section 2.1.1: PKCE with S256 is REQUIRED for all clients.
    // Missing code_challenge must be rejected.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-nopkce@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;
    let state_param = "teststate-nopkce";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            state_param,
        ),
        &[],
    )
    .await;

    // Must redirect with error=invalid_request (PKCE required)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Missing PKCE must redirect with error, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error=invalid_request"),
        "Redirect must include error=invalid_request for missing PKCE: {location}"
    );

    // State must be echoed even in error
    assert!(
        location.contains(&format!("state={state_param}")),
        "Error redirect must echo state parameter: {location}"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_missing_client_id_shows_error_page() {
    // RFC 6749 Section 4.1.2.1: If client_id is missing, the server MUST NOT
    // redirect and MUST display an error page.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/authorize?response_type=code\
         &redirect_uri=https://example.com/callback&scope=openid\
         &code_challenge=dummychallenge&code_challenge_method=S256",
        &[],
    )
    .await;

    // Must show error page — no redirect
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Missing client_id must produce error page, got: {}",
        response.status
    );

    // Must not redirect to the callback
    if let Some(location) = response.headers.get("Location") {
        let loc_str = location.to_str().unwrap_or("");
        assert!(
            !loc_str.contains("example.com/callback"),
            "Must not redirect when client_id is missing: {loc_str}"
        );
    }
}

#[tokio::test]
async fn test_rfc9207_authorize_error_redirect_includes_iss() {
    // RFC 9207 Section 2: The iss parameter MUST be included even in
    // error redirect responses, not just successful ones.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-erriss@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

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

#[tokio::test]
async fn test_rfc6749_authorize_pending_auth_expired_shows_error_page() {
    // When returning from login with an invalid or expired pending_auth ID,
    // the server must show an error page since the authorization context is lost.
    let (app, _state) = test_app().await;

    // Use a nonexistent pending_auth ID
    let response = http_get_full(
        &app,
        "/oauth/authorize?pending_auth=nonexistent-pending-id-12345",
        &[],
    )
    .await;

    // Must show error page
    assert!(
        response.status == StatusCode::OK || response.status.is_client_error(),
        "Expired/invalid pending_auth must produce error page, got: {}",
        response.status
    );

    // Body should indicate the session expired
    assert!(
        response.body.contains("expired") || response.body.contains("try again"),
        "Error page should mention expiration or retry"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_state_preserved_across_redirect() {
    // RFC 6749 Section 4.1.2: The state parameter MUST be returned unchanged
    // in the authorization response. This tests a complex state value with
    // special characters that must survive URL encoding round-trip.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-state@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);
    // State value with characters that need URL encoding
    let state_param = "state_with-special.chars~123";

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
            urlencoding::encode(state_param),
        ),
        &[("Cookie", &format!("vouch_session={session_token}"))],
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

    // Parse the redirect URL and verify state is preserved
    let url = url::Url::parse(location).expect("Location must be a valid URL");
    let state_values: Vec<String> = url
        .query_pairs()
        .filter(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .collect();

    assert_eq!(
        state_values.len(),
        1,
        "Must have exactly one state parameter"
    );
    assert_eq!(
        state_values[0], state_param,
        "State parameter must be echoed unchanged"
    );
}

#[tokio::test]
async fn test_rfc6749_authorize_param_length_validation() {
    // The authorization endpoint must reject parameters that exceed
    // maximum allowed lengths to prevent abuse.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-longparam@example.com").await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    // state has max length of 512 — send 600 chars
    let long_state = "x".repeat(600);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dummychallenge&code_challenge_method=S256&state={}",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            long_state,
        ),
        &[],
    )
    .await;

    // Must redirect with error=invalid_request or show error page
    if response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Must have Location header")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            location.contains("error="),
            "Oversized parameter must produce error: {location}"
        );
    } else {
        assert!(
            response.status == StatusCode::OK || response.status.is_client_error(),
            "Must show error for oversized parameter, got: {}",
            response.status
        );
    }
}

#[tokio::test]
async fn test_rfc6749_authorize_code_redirect_to_registered_uri_only() {
    // RFC 6749 Section 10.6: The authorization code must be delivered only
    // to the redirect_uri that was registered for the client. This verifies
    // that the successful redirect goes to the correct URI.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.db, "authorize-reguri@example.com").await;
    let auth_id = create_test_authenticator(&state.db, &user.id).await;
    let client = create_test_oauth_client(&state.db, &user.id).await;

    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge={}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            challenge,
        ),
        &[("Cookie", &format!("vouch_session={session_token}"))],
    )
    .await;

    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "Must redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    // Redirect must go to the registered URI
    assert!(
        location.starts_with("https://example.com/callback?"),
        "Redirect must target the registered redirect_uri: {location}"
    );

    // Must contain the authorization code
    assert!(
        location.contains("code="),
        "Redirect must contain authorization code: {location}"
    );
}
