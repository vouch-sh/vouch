// SPDX-License-Identifier: BUSL-1.1
//! RFC 9068 — JWT Profile for Access Tokens tests.

use super::helpers::*;

#[tokio::test]
async fn test_rfc9068_required_claims_in_access_token() {
    // RFC 9068 Section 2.2: Access token must contain all required claims:
    // iss, exp, aud, sub, client_id, iat, jti
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rfc9068-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "rfc9068-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "rfc9068-jti@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "rfc9068-recommended@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "rfc9068-introspect@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

#[tokio::test]
async fn test_rfc9068_access_token_all_required_claims() {
    // RFC 9068 Section 2.2: Decode an issued access token and verify
    // all required claims are present.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "at-claims@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "at-typ@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "at-jti-uniq@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

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

    let user = create_test_user(&state.store, "at-recommended@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    // RECOMMENDED claims for FIDO2-issued tokens
    // auth_time — when authentication occurred
    assert!(
        claims.get("auth_time").is_some(),
        "FIDO2 token should include auth_time (recommended)"
    );
}

#[tokio::test]
async fn test_access_token_exp_greater_than_iat() {
    // RFC 9068 Section 2.2: exp and iat are both REQUIRED; exp must be after iat.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "at-exp-iat@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    let exp = claims["exp"].as_i64().expect("exp must be an integer");
    let iat = claims["iat"].as_i64().expect("iat must be an integer");

    assert!(
        exp > iat,
        "RFC 9068 §2.2: exp ({exp}) must be greater than iat ({iat})"
    );
}

#[tokio::test]
async fn test_access_token_scope_claim_present() {
    // RFC 9068 Section 2.2: scope claim, when present, MUST be a string (space-separated).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "at-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let claims = decode_jwt_payload(&access_token);

    assert!(
        claims.get("scope").is_some(),
        "Access token must contain a scope claim"
    );
    assert!(
        claims["scope"].is_string(),
        "RFC 9068 §2.2: scope claim must be a string, got: {:?}",
        claims["scope"]
    );
}
