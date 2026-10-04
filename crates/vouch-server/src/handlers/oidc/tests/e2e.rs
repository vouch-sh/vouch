// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end flows, regression tests, and scope conformance tests.

use super::helpers::*;
use crate::{db, handlers};

// ========================================================================
// Regression Tests
// ========================================================================

#[tokio::test]
async fn test_client_secret_hash_roundtrip() {
    // Regression test: client secrets hashed at creation time must match
    // hashes produced during authentication. A previous bug used hex encoding
    // at creation but base64url at validation, so authentication always failed.
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "secret-roundtrip@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // The test helper uses hash_token() (base64url). Validate that
    // db::validate_oauth_client_credentials finds the secret when we
    // hash the plaintext secret with the same function.
    let secret_hash = handlers::hash_token(&client.client_secret);
    let result = db::validate_oauth_client_credentials(
        &state.store,
        &client.client_id,
        &secret_hash,
        jiff::Timestamp::now(),
    )
    .await
    .expect("DB query should succeed");

    assert!(
        result.is_some(),
        "Client secret round-trip must succeed: hash at creation must match hash at validation"
    );
}

// ========================================================================
// OAuth Access Token + UserInfo End-to-End Tests
// ========================================================================

#[tokio::test]
async fn test_auth_code_flow_token_works_with_userinfo() {
    // Full OIDC flow: issue auth code → exchange → call /oauth/userinfo → assert 200
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-userinfo@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
async fn test_oauth_token_works_at_management_endpoints() {
    // Verify OAuth access tokens work at management endpoints
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "oauth-mgmt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    // Call key listing endpoint with OAuth access token (should succeed)
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "OAuth access token should work at management endpoints"
    );
}

// ========================================================================
// OIDC Scope Conformance Tests
// ========================================================================

#[tokio::test]
async fn test_userinfo_respects_openid_only_scope() {
    // OIDC Core Section 5.4: Without email scope, email claims should be omitted
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "scope-openid@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "scope-email@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
async fn test_id_token_scope_aware() {
    // OIDC Core Section 5.4: ID token should only include email when scope grants it
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "idtoken-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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
async fn test_access_token_optional_scope_field() {
    // AccessTokenClaims with missing scope field should deserialize as None
    use crate::services::auth::AccessTokenClaims;
    let claims_json = r#"{"iss":"https://vouch.example.com","aud":"client-id","sub":"user-id","exp":9999999999,"iat":1700000000,"jti":"jti-1","client_id":"client-id","hardware_verified":true}"#;
    let claims: AccessTokenClaims =
        serde_json::from_str(claims_json).expect("Should deserialize without scope");
    assert!(
        claims.scope.is_none(),
        "Missing scope field should deserialize as None"
    );
}

// ========================================================================
// Step 9 Migration — Unified Token Type Tests
// ========================================================================

#[tokio::test]
async fn test_session_spec_client_id_produces_client_bound_token() {
    // A `TestSessionSpec` naming a `client_id` must produce a token whose
    // `client_id` claim is that client, not the server base_url. Introspection
    // cross-client tests depend on it.
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "client-bound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&client.client_id),
            ..Default::default()
        },
    )
    .await;

    let config = state.config();
    let decoded = decode_token(&token, &state.oidc_key, &config.base_url, test_arrival())
        .expect("Token must decode successfully");

    let DecodedToken::AccessToken(claims) = decoded;
    assert_eq!(
        claims.client_id, client.client_id,
        "Token client_id must match the supplied client_id, not the server base_url"
    );
    assert_eq!(claims.sub, user.id, "Token sub must match the user_id");
}

#[tokio::test]
async fn test_unified_token_hardware_verified_claim_always_set() {
    // All unified ES256 access tokens produced by create_oauth_access_token
    // must carry hardware_verified=true (FIDO2 attestation guarantee).
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "hw-verified@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let config = state.config();
    let decoded = decode_token(&token, &state.oidc_key, &config.base_url, test_arrival())
        .expect("Token must decode successfully");

    let DecodedToken::AccessToken(claims) = decoded;
    assert!(
        claims.hardware_verified,
        "All unified access tokens must carry hardware_verified=true"
    );
}

#[tokio::test]
async fn test_unified_token_typ_header_is_at_jwt() {
    // RFC 9068 Section 2.1 + Step 9 migration: the single surviving token type
    // is ES256 with typ "at+jwt". Verify this is what a default TestSessionSpec produces.
    use crate::crypto::jwt::JwtType;

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "typ-header@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    // Peek at the header without full validation
    let header = jsonwebtoken::decode_header(&token).expect("Valid JWT header");
    assert_eq!(
        header.typ.as_deref(),
        Some(JwtType::AccessToken.as_header_str()),
        "Unified token must have typ=at+jwt"
    );
    assert_eq!(
        header.alg,
        jsonwebtoken::Algorithm::ES256,
        "Unified token must be signed with ES256"
    );
}

#[tokio::test]
async fn test_legacy_register_routes_removed() {
    // Step 9: /v1/auth/register/* backward-compat routes were removed.
    // Only /v1/keys/register/* remains. Verify the legacy paths return 404
    // so clients cannot accidentally rely on removed endpoints.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "legacy-route@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    // Legacy path: /v1/auth/register/start — must not exist
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/start",
        Some(r#"{"name":"key"}"#.to_string()),
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/start must return 404 after removal"
    );

    // Legacy path: /v1/auth/register/complete — must not exist
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/auth/register/complete",
        Some(r#"{"state":"x"}"#.to_string()),
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/v1/auth/register/complete must return 404 after removal"
    );
}

#[tokio::test]
async fn test_current_register_routes_still_exist() {
    // Regression guard: /v1/keys/register/* routes must still exist and
    // require authentication (not 404).
    let (app, _state) = test_app().await;

    // Without auth — should be 401, not 404
    let (status, _) = http_request(
        &app,
        "POST",
        "/v1/keys/register/start",
        Some(r#"{"name":"key"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/v1/keys/register/start must exist and require auth (not 404)"
    );
}

#[tokio::test]
async fn test_decoded_token_enum_single_variant_destructuring() {
    // DecodedToken is now a single-variant enum. Verify that exhaustive
    // destructuring (used in introspection.rs etc.) compiles and works correctly.
    // This is a compilation + runtime correctness check.
    use crate::services::auth::{DecodedToken, decode_token};

    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "enum-destr@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let config = state.config();
    let decoded = decode_token(&token, &state.oidc_key, &config.base_url, test_arrival())
        .expect("Token must decode");

    // Exhaustive destructuring of the single-variant enum — if a second variant
    // were added this would produce a compiler warning, keeping tests honest.
    let DecodedToken::AccessToken(claims) = decoded;
    assert!(!claims.sub.is_empty(), "sub must be populated");
    assert!(!claims.iss.is_empty(), "iss must be populated");
    assert!(!claims.jti.is_empty(), "jti must be populated");
}

// ========================================================================
// Credential issuance is reserved for command-line logins
// ========================================================================

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

/// A client that registered its own request-signing key, as any dynamically
/// registered client can, so its tokens clear the `/v1` signature requirement.
async fn signing_client(state: &crate::AppState, owner_id: &str) -> TestOAuthClient {
    create_test_client(
        &state.store,
        owner_id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            ..Default::default()
        },
    )
    .await
}

/// Assert that every credential endpoint refuses `token` as an application's.
async fn assert_credentials_refused(app: &axum::Router, token: &str) {
    let auth = format!("Bearer {token}");

    let (status, body) = http_get(
        app,
        "/v1/credentials/aws/token",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "aws: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "first_party_session_required");

    let (status, body) = http_post_json(
        app,
        "/v1/credentials/ssh",
        r#"{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "ssh: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "first_party_session_required");

    let (status, body) = http_post_json(
        app,
        "/v1/credentials/github/token",
        r#"{"repositories":["owner/repo"]}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "github: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "first_party_session_required");
}

/// The authorization-code grant issues from a browser session whose key
/// ceremony the user performed for Vouch, not for the client redeeming the
/// code. The token says a key was touched, and still cannot obtain credentials.
#[tokio::test]
async fn test_authorization_code_token_cannot_reach_credentials() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "code-credentials@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = signing_client(&state, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    assert_eq!(
        decode_jwt_payload(&access_token)["hardware_verified"],
        true,
        "the token still tells the relying party a key was touched"
    );
    assert_credentials_refused(&app, &access_token).await;
}

/// Token exchange passes the subject session's purpose along, so exchanging an
/// authorization-code token does not turn it into one that obtains credentials.
#[tokio::test]
async fn test_token_exchanged_from_authorization_code_token_cannot_reach_credentials() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "code-exchange@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = signing_client(&state, &user.id).await;

    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type={ACCESS_TOKEN_TYPE}"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange should succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let exchanged = response["access_token"].as_str().expect("access_token");

    assert_credentials_refused(&app, exchanged).await;
}

/// The ID token an exchange mints is a federation credential, so the subject
/// token must come from a command-line login like any other credential request.
#[tokio::test]
async fn test_authorization_code_token_cannot_exchange_for_id_token() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "code-id-token@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = signing_client(&state, &user.id).await;

    let (subject_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={subject_token}\
             &subject_token_type={ACCESS_TOKEN_TYPE}\
             &requested_token_type={ID_TOKEN_TYPE}"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_request");
}

/// An application's token authenticates the user to that application. Vouch's
/// own endpoints refuse it, so it cannot manage the account it names.
#[tokio::test]
async fn test_authorization_code_token_cannot_manage_keys() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "code-keys@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let other_key = create_test_authenticator(&state.store, &user.id).await;
    let client = signing_client(&state, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;
    let auth = format!("Bearer {access_token}");

    let (status, body) = http_post_json(
        &app,
        "/v1/keys/register/start",
        r#"{"name":"another key"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "register: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "first_party_session_required");

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{other_key}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "delete: {body}");
    assert!(
        db::get_authenticator_by_id(&state.store, &other_key)
            .await
            .expect("lookup")
            .is_some(),
        "the key must survive"
    );

    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &auth)]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "list: {body}");
}

/// The same refusal covers the organization admin and application APIs.
#[tokio::test]
async fn test_authorization_code_token_cannot_reach_admin_apis() {
    let (app, state) = test_app().await;

    let org = create_test_org(&state.store, "code-admin.example").await;
    let admin =
        create_test_user_in_org(&state.store, "admin@code-admin.example", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let client = signing_client(&state, &admin.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &admin, &auth_id, &client).await;
    let auth = format!("Bearer {access_token}");

    let (status, body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description":"token","expires_in_days":365,"audit_read":true}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "scim-tokens: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "first_party_session_required");

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "applications: {body}");
}

/// A browser session is accepted at Vouch's endpoints and still cannot obtain
/// credentials: those go to a command-line login.
#[tokio::test]
async fn test_browser_session_cannot_reach_credentials() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "browser-credentials@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            purpose: db::SessionPurpose::OAuthAccessToken,
            ..Default::default()
        },
    )
    .await;
    let auth = format!("Bearer {token}");

    let (status, body) = http_get(&app, "/v1/keys", &[("Authorization", &auth)]).await;
    assert_eq!(status, StatusCode::OK, "keys: {body}");

    let (status, body) = http_get(
        &app,
        "/v1/credentials/aws/token",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "aws: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "hardware_required");
}
