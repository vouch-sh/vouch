// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9701 — JWT Token Introspection Responses.

use super::helpers::*;
use crate::db::{self, CreateOAuthClientParams, JwsAlgorithm, RegistrationSource};

// ============================================================================
// Helpers
// ============================================================================

/// Create a test OAuth client with `introspection_signed_response_alg = ES256`.
async fn create_test_client_with_introspection_jwt(
    state: &std::sync::Arc<crate::AppState>,
    user_id: &str,
) -> crate::test_utils::TestOAuthClient {
    use aws_lc_rs::rand as aws_rand;

    let (client, client_id) = db::create_oauth_client(
        &state.store,
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name: "JWT Introspect App",
            description: None,
            application_type: crate::db::OAuthClientType::Web,
            redirect_uris: &["https://example.com/callback".to_string()],
            access_scope: crate::db::AccessScope::Public,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Es256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: Some(JwsAlgorithm::Es256),
        },
    )
    .await
    .expect("Failed to create JWT introspect test client");

    let mut secret_bytes = [0u8; 32];
    aws_rand::fill(&mut secret_bytes).expect("RNG failure");
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_hash = crate::handlers::hash_token(&secret);

    db::create_oauth_client_secret(&state.store, &client.id, &secret_hash, Some("test"), None)
        .await
        .expect("Failed to create test client secret");

    crate::test_utils::TestOAuthClient {
        app_id: client.id,
        client_id,
        client_secret: secret,
    }
}

// ============================================================================
// RFC 9701 Tests
// ============================================================================

#[tokio::test]
async fn test_introspect_jwt_response_content_type() {
    // RFC 9701 Section 5: Client with introspection_signed_response_alg = ES256
    // receives Content-Type: application/token-introspection+jwt.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-ct@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client_with_introspection_jwt(&state, &user.id).await;

    let (token, _id_token) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Must have Content-Type")
        .to_str()
        .expect("Valid str");
    assert!(
        content_type.contains("application/token-introspection+jwt"),
        "RFC 9701: Content-Type must be application/token-introspection+jwt, got: {content_type}"
    );
}

#[tokio::test]
async fn test_introspect_jwt_response_is_valid_jwt() {
    // RFC 9701 Section 5: JWT header must have typ = "token-introspection+jwt",
    // payload must include iss, aud, and iat at the top level.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-jwt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client_with_introspection_jwt(&state, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Must be a three-part JWT
    let parts: Vec<&str> = body.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "RFC 9701 response must be a JWT, got: {body}"
    );

    // Header: typ = "token-introspection+jwt"
    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Header must be valid base64url");
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).expect("Header must be valid JSON");
    assert_eq!(
        header["typ"], "token-introspection+jwt",
        "RFC 9701: JWT header typ must be token-introspection+jwt"
    );
    assert_eq!(header["alg"], "ES256", "RFC 9701: JWT must use ES256");

    // Payload: iss, aud, iat present
    let payload_json = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Payload must be valid base64url");
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_json).expect("Payload must be valid JSON");

    assert!(
        payload.get("iss").is_some(),
        "RFC 9701: iss must be present"
    );
    assert!(
        payload.get("aud").is_some(),
        "RFC 9701: aud must be present"
    );
    assert!(
        payload.get("iat").is_some(),
        "RFC 9701: iat must be present"
    );

    // aud must equal the calling client's client_id
    assert_eq!(
        payload["aud"],
        serde_json::Value::String(client.client_id.clone()),
        "RFC 9701: aud must be the calling client_id"
    );

    // iss must be the server base URL
    let config = state.config();
    assert_eq!(
        payload["iss"],
        serde_json::Value::String(config.base_url.clone()),
        "RFC 9701: iss must be the server issuer"
    );
}

#[tokio::test]
async fn test_introspect_jwt_inactive_token() {
    // RFC 9701 Section 4: Inactive token wrapped in JWT must contain
    // token_introspection: {"active": false} and no other token metadata.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-inactive@example.com").await;
    let client = create_test_client_with_introspection_jwt(&state, &user.id).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        "token=invalid_token_that_does_not_exist",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let parts: Vec<&str> = body.split('.').collect();
    assert_eq!(parts.len(), 3, "Inactive response must still be a JWT");

    let payload_json = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Payload must be valid base64url");
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_json).expect("Payload must be valid JSON");

    let ti = &payload["token_introspection"];
    assert_eq!(
        ti["active"], false,
        "RFC 9701: Inactive token_introspection must have active=false"
    );
    // Must not leak any other metadata
    assert!(
        ti.get("sub").is_none(),
        "Inactive introspection must not include sub"
    );
    assert!(
        ti.get("exp").is_none(),
        "Inactive introspection must not include exp"
    );
}

#[tokio::test]
async fn test_introspect_jwt_no_toplevel_sub_exp() {
    // RFC 9701 Section 5.4: The JWT response MUST NOT include top-level sub or exp.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-no-sub-exp@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client_with_introspection_jwt(&state, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let parts: Vec<&str> = body.split('.').collect();
    assert_eq!(parts.len(), 3, "Must be a JWT");

    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("Payload base64url");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Payload JSON");

    // RFC 9701 Section 5.4: no top-level sub or exp
    assert!(
        payload.get("sub").is_none(),
        "RFC 9701 §5.4: JWT MUST NOT have top-level sub, got: {payload}"
    );
    assert!(
        payload.get("exp").is_none(),
        "RFC 9701 §5.4: JWT MUST NOT have top-level exp, got: {payload}"
    );
}

#[tokio::test]
async fn test_introspect_plain_json_default() {
    // RFC 9701 Section 5: Client without introspection_signed_response_alg
    // receives plain JSON (RFC 7662 backward compatibility).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-plain@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let response = http_post_form_full(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let content_type = response
        .headers
        .get("Content-Type")
        .expect("Must have Content-Type")
        .to_str()
        .expect("Valid str");
    assert!(
        content_type.contains("application/json"),
        "Plain client must receive application/json, got: {content_type}"
    );

    // Body must be valid JSON (not a JWT)
    let parsed: serde_json::Value =
        serde_json::from_str(&response.body).expect("Body must be valid JSON");
    assert_eq!(parsed["active"], true, "Token should be active");
}

#[tokio::test]
async fn test_introspect_jwt_token_data_in_nested_claim() {
    // RFC 9701 Section 5.3: Active token data (scope, client_id, etc.)
    // must be inside the token_introspection claim, not at the top level.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9701-nested@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client_with_introspection_jwt(&state, &user.id).await;

    let (token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth_header = client.basic_auth_header();

    let (status, body) = http_post_form(
        &app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let parts: Vec<&str> = body.split('.').collect();
    assert_eq!(parts.len(), 3, "Must be a JWT");

    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("Payload base64url");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("Payload JSON");

    // Token data must be inside token_introspection
    let ti = &payload["token_introspection"];
    assert_eq!(
        ti["active"], true,
        "token_introspection.active must be true"
    );
    assert!(
        ti.get("client_id").is_some(),
        "client_id must be inside token_introspection"
    );
    assert!(
        ti.get("scope").is_some(),
        "scope must be inside token_introspection"
    );

    // Token data must NOT be at the top level of the JWT payload
    assert!(
        payload.get("active").is_none(),
        "RFC 9701: active must not appear at top level of JWT"
    );
    assert!(
        payload.get("client_id").is_none(),
        "RFC 9701: client_id must not appear at top level of JWT"
    );
    assert!(
        payload.get("scope").is_none(),
        "RFC 9701: scope must not appear at top level of JWT"
    );
}

#[tokio::test]
async fn test_discovery_includes_introspection_signing_alg() {
    // RFC 9701 Section 7.1: Discovery must include
    // introspection_signing_alg_values_supported: ["ES256"].
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let algs = discovery
        .get("introspection_signing_alg_values_supported")
        .expect("RFC 9701 §7.1: introspection_signing_alg_values_supported must be present");

    let alg_array = algs.as_array().expect("Must be an array");
    assert!(
        alg_array.iter().any(|v| v == "ES256"),
        "RFC 9701 §7.1: ES256 must be in introspection_signing_alg_values_supported, got: {algs}"
    );
}
