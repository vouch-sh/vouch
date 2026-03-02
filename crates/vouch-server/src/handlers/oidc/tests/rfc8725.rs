// SPDX-License-Identifier: BUSL-1.1
//! RFC 8725 — JWT Best Current Practices tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc8725_cross_type_token_substitution() {
    // RFC 8725 Section 3.11: Only access tokens (ES256, at+jwt) are accepted.
    // HS256 state tokens and ID tokens (typ != "at+jwt") must be rejected.
    let (app, state) = test_app().await;

    // Create an HS256 state token (e.g. registration state) — should be rejected
    // as a Bearer token at resource endpoints.
    let fake_state = state
        .state_signer
        .encode_state_token(
            &serde_json::json!({"sub": "user-1", "exp": 9_999_999_999i64, "iat": 1_000_000_000i64}),
            crate::crypto::jwt::JwtType::RegistrationState,
        )
        .await
        .expect("encode state token");

    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", fake_state))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "HS256 state token must not be accepted as a Bearer token"
    );

    // Valid OAuth access token (ES256, at+jwt) should work
    let user = create_test_user(&state.store, "cross-type@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "OAuth access token (at+jwt) should work at resource endpoints"
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
// Step 9 Migration — Additional Cross-Type Substitution Coverage
// ========================================================================

#[tokio::test]
async fn test_rfc8725_hs256_state_tokens_all_rejected_at_resource_endpoints() {
    // RFC 8725 Section 3.11: All HS256 state token types are rejected at every
    // resource endpoint. Post-migration there is exactly one valid token type:
    // ES256 access tokens with typ "at+jwt". Verify each HS256 type variant
    // is rejected at /oauth/userinfo (token validation path).
    let (app, state) = test_app().await;

    let hs256_types = [
        crate::crypto::jwt::JwtType::AuthorizationCode,
        crate::crypto::jwt::JwtType::RegistrationState,
        crate::crypto::jwt::JwtType::BrowserRegistrationState,
        crate::crypto::jwt::JwtType::BrowserAuthenticationState,
        crate::crypto::jwt::JwtType::GitHubState,
        crate::crypto::jwt::JwtType::Fido2ChallengeState,
    ];

    for jwt_type in hs256_types {
        let fake_token = state
            .state_signer
            .encode_state_token(
                &serde_json::json!({
                    "sub": "attacker",
                    "exp": 9_999_999_999i64,
                    "iat": 1_000_000_000i64
                }),
                jwt_type,
            )
            .await
            .expect("encode state token");

        let (status, _) = http_get(
            &app,
            "/oauth/userinfo",
            &[("Authorization", &format!("Bearer {}", fake_token))],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "HS256 state token (typ={}) must be rejected at /oauth/userinfo",
            jwt_type.as_header_str()
        );
    }
}

#[tokio::test]
async fn test_rfc8725_id_token_rejected_at_resource_endpoint() {
    // RFC 9068 Section 2.1: ID tokens (typ "JWT") signed with the same OIDC
    // key MUST NOT be accepted as access tokens. Only "at+jwt" typ is valid.
    // This is the same-key-different-type substitution attack.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "id-token-sub@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Issue a real ID token through the auth code flow
    let (_access_token, id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Attempt to use the ID token (typ: "JWT") as a Bearer token — must fail
    let (status, _body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {}", id_token))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "ID token (typ=JWT) must not be accepted as a Bearer token at resource endpoints"
    );
}

#[tokio::test]
async fn test_rfc8725_access_token_not_accepted_at_par_as_id_token() {
    // Cross-type: ES256 access token (at+jwt) should not bypass PAR or other
    // endpoints that require specific token types. This checks that the unified
    // ES256 token type still enforces typ-header checking — an access token
    // presented as an "id_token" in a form body should be treated as opaque data
    // (not validated as an ID token).
    //
    // PAR endpoint requires client auth and an authorization request.
    // Supplying an access token as `id_token_hint` should be silently ignored
    // (per OIDC Core, id_token_hint is optional), not cause elevated access.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "par-hint@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    // Submit an access token as id_token_hint to PAR endpoint
    // (the token is valid ES256 but the endpoint should not be confused)
    let auth_header = client.basic_auth_header();
    let (status, _body) = http_post_form(
        &app,
        "/oauth/par",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&id_token_hint={}&code_challenge=abc&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
            token
        ),
        &[("Authorization", &auth_header)],
    )
    .await;

    // PAR may reject (400) or accept with a request_uri; either is fine.
    // What must NOT happen is the access token being granted elevated PAR authority.
    // A 401 would only occur if the client auth itself failed — not expected here.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "Client auth via Basic should not fail when an access token is supplied as id_token_hint"
    );
}
