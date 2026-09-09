// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use crate::test_utils::{
    TestSessionSpec, create_test_authenticator, create_test_session_with, create_test_user,
    http_delete_full, http_get_full, http_post_json, test_app, test_app_state, test_config,
};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

/// Build a valid `BrowserRegistrationState` JWT using the test signer.
///
/// Uses `webauthn.start_passkey_registration` to obtain a real
/// `PasskeyRegistration` value — the struct cannot be constructed any
/// other way because its fields are private to webauthn-rs.
async fn make_valid_state_token(state: &AppState) -> String {
    let user_id = Uuid::now_v7();
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, "test@example.com", "test@example.com", None)
        .expect("start_passkey_registration");

    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: "test@example.com".to_string(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };

    reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state")
}

/// Build a minimal valid base64url credential_id (16 zero bytes).
fn valid_credential_id() -> String {
    URL_SAFE_NO_PAD.encode([0u8; 16])
}

/// Build a minimal valid base64url attestation_object (1 non-empty byte).
fn valid_attestation_object() -> String {
    URL_SAFE_NO_PAD.encode([0u8; 1])
}

/// Build a minimal valid base64url client_data_json.
fn valid_client_data_json() -> String {
    let json =
        r#"{"type":"webauthn.create","challenge":"abc","origin":"https://test.example.com"}"#;
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Build the `Cookie` header value for a session token.
///
/// Mirrors how the live `Set-Cookie` header is structured
/// (`create_session_cookie`) so the receipt path in the test harness is
/// symmetric with the cookie the server would set after `browser_login_complete`.
fn session_cookie_header(token: &str) -> String {
    format!("{}={token}", vouch_common::SESSION_COOKIE_NAME)
}

/// Decode the payload claims of a JWT without verifying the signature.
///
/// Splits the token on `.`, base64url-decodes the second part (payload),
/// and parses it as a JSON object. Used only in tests to inspect claims.
fn decode_jwt_payload_claims(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have exactly 3 parts");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to base64url-decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("Failed to parse JWT payload as JSON")
}

// ── test_enrollment_complete_missing_state ───────────────────────────────

#[tokio::test]
async fn test_enrollment_complete_missing_state() {
    let (app, _state) = test_app().await;

    // Omit the `state` field entirely — serde will fail to deserialize.
    let body = serde_json::json!({
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    // `ValidJson` reports every body rejection in the JSON envelope the
    // browser reads, so a missing field is a 400 like any other bad body.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_request"),
        "expected 'invalid_request' in body, got: {resp_body}"
    );
}

// ── test_enrollment_complete_invalid_state_token ─────────────────────────

#[tokio::test]
async fn test_enrollment_complete_invalid_state_token() {
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "state": "not-a-jwt",
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_state"),
        "expected 'invalid_state' in body, got: {resp_body}"
    );
}

// ── test_enrollment_complete_missing_credential_id ───────────────────────

#[tokio::test]
async fn test_enrollment_complete_missing_credential_id() {
    let (app, state) = test_app().await;

    let valid_state = make_valid_state_token(&state).await;

    // Omit `credential_id` — serde will fail to deserialize.
    let body = serde_json::json!({
        "state": valid_state,
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("credential_id"),
        "the rejection must name the missing field, got: {resp_body}"
    );
}

// ── test_enrollment_complete_oversized_credential_id ─────────────────────

#[tokio::test]
async fn test_enrollment_complete_oversized_credential_id() {
    let (app, state) = test_app().await;

    let valid_state = make_valid_state_token(&state).await;

    // A credential ID one byte past the WebAuthn ceiling, encoded.
    let oversized = URL_SAFE_NO_PAD.encode(vec![
        0u8;
        <vouch_common::CredentialIdData as vouch_common::Bounds>::MAX_BYTES
            + 1
    ]);

    let body = serde_json::json!({
        "state": valid_state,
        "credential_id": oversized,
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_request"),
        "expected 'invalid_request' in body, got: {resp_body}"
    );
}

// ── test_browser_register_complete_rejects_replayed_state ───────────────

#[tokio::test]
async fn test_browser_register_complete_rejects_replayed_state() {
    let (app, state) = test_app().await;

    // Build a real user + session so the state JWT and the cookie share
    // the same `user_id`. The fix re-binds the caller to that id; without
    // a matching cookie the request would now be rejected as missing a
    // session before reaching the replay check.
    let user = create_test_user(&state.store, "replay@example.com").await;
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
    let user_id = Uuid::parse_str(&user.id).expect("user id is a uuid");

    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user.email, &user.email, None)
        .expect("start_passkey_registration");

    let now = jiff::Timestamp::now();
    let exp = now.as_second() + 300;
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp,
    };
    let state_jwt = reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state");

    // Pre-consume the state token to simulate prior use.
    let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
    let _claim = crate::db::consume_challenge_state_for_test(&state.store, &state_jwt, expires_at)
        .await
        .expect("pre-consume must succeed");

    // POST to the complete endpoint with the already-consumed state. The
    // fields must be well-formed, since the body checks precede the replay
    // check, but their contents are never used beyond those bounds.
    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let cookie = session_cookie_header(&token);
    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[
            ("Cookie", cookie.as_str()),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("state_already_used"),
        "expected 'state_already_used' in body, got: {resp_body}"
    );
}

// ── test_enrollment_complete_invalid_base64_credential_id ────────────────

#[tokio::test]
async fn test_enrollment_complete_invalid_base64_credential_id() {
    let (app, state) = test_app().await;

    let valid_state = make_valid_state_token(&state).await;

    // "!!" is not valid base64url. `credential_id` is typed
    // `CredentialId<Base64Url>`, so this fails in serde and `ValidJson` reports
    // it in the JSON envelope the browser reads.
    let body = serde_json::json!({
        "state": valid_state,
        "credential_id": "!!not-base64url!!",
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_request"),
        "expected 'invalid_request' in body, got: {resp_body}"
    );
    assert!(
        resp_body.contains("credential_id"),
        "the rejection must name the offending field, got: {resp_body}"
    );
}

// ── test_enrollment_complete_rejects_non_string_field ────────────────────

#[tokio::test]
async fn test_enrollment_complete_rejects_wrong_json_type() {
    let (app, state) = test_app().await;

    let valid_state = make_valid_state_token(&state).await;

    // A JSON number where a base64url string belongs. Typing the field is what
    // turns this into a boundary rejection rather than a handler branch.
    let body = serde_json::json!({
        "state": valid_state,
        "credential_id": 42,
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_request"),
        "expected 'invalid_request' in body, got: {resp_body}"
    );
}

// ── test_oidc_callback_rejects_replayed_state ───────────────────────────

#[tokio::test]
async fn test_oidc_callback_rejects_replayed_state() {
    // GET /oauth/callback must reject a replayed `state` query param.
    // `try_consume_oidc_state` closes the read-vs-consume TOCTOU that
    // would otherwise let two concurrent callbacks both pass
    // validation. Pre-consume the state in the DB, then submit the
    // callback — the handler must fail at the consume step and return
    // the "Invalid or expired state" error template WITHOUT calling
    // the upstream IdP `/token` endpoint.
    use crate::test_utils::http_get;

    let (app, state) = test_app().await;

    // Seed a fresh OIDC state row + the device-auth row it FKs to.
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let device_auth_id = crate::db::create_device_auth_request(
        &state.store,
        "callback-replay-device-hash",
        "CBRP-CODE",
        None,
        expires_at,
        5,
    )
    .await
    .expect("create_device_auth_request");

    let oidc_state_value = "callback-replay-state-12345";
    crate::db::create_oidc_state(
        &state.store,
        oidc_state_value,
        Some(&device_auth_id),
        "test-nonce",
        "",
        expires_at,
        "",
    )
    .await
    .expect("create_oidc_state");

    // Pre-consume to simulate a successful prior callback.
    let _claim = crate::db::try_consume_oidc_state(&state.store, oidc_state_value)
        .await
        .expect("pre-consume must succeed");

    // Submit the callback with the now-consumed state. The handler
    // calls `try_consume_oidc_state` first, which returns
    // AlreadyConsumed, so the upstream IdP is never reached.
    let (status, body) = http_get(
        &app,
        &format!("/oauth/callback?state={oidc_state_value}&code=dummy-auth-code"),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "error template renders with 200 OK; got {status}: {body}"
    );
    assert!(
        body.contains("Invalid or expired state"),
        "expected 'Invalid or expired state' in body, got: {body}"
    );
}

// ── complete_enrollment_after_identity audit events ─────────────────

// ── HTTP-level OIDC callback E2E (wiremock mock IdP) ──────────────────
//
// The shape-gate regression tests above exercise
// `complete_enrollment_after_identity` directly with a hand-built
// `IdentityResult`. The OIDC and SAML HTTP callbacks both funnel through
// that same chokepoint, but the callback also performs the live token
// exchange + ID-token verification + email-claim passthrough before
// constructing the `IdentityResult`. This pair of HTTP-level tests drives
// the real `/oauth/callback` route against an in-process wiremock OIDC IdP
// that signs its own ID token, so the end-to-end behavior (a misconfigured
// IdP asserting an email with a whitespace-bearing domain is rejected at
// the chokepoint, and a well-formed email still proceeds) is verified
// through the full stack — not just the chokepoint function.

/// Build a `ConfiguredOidcProvider` whose endpoints point at `issuer`.
fn mock_oidc_provider(issuer: &str) -> crate::services::idp::ConfiguredIdp {
    use crate::services::idp::ConfiguredIdp;
    use crate::services::idp::oidc::{ConfiguredOidcProvider, OidcProvider};
    use secrecy::SecretString;
    use url::Url;

    ConfiguredIdp::Oidc(ConfiguredOidcProvider {
        id: "mock-idp".to_string(),
        client_id: "mock-client".to_string(),
        client_secret: SecretString::from("mock-secret"),
        provider: OidcProvider {
            issuer: issuer.to_string(),
            authorization_endpoint: Url::parse(&format!("{issuer}/authorize"))
                .expect("parse authorize url"),
            token_endpoint: Url::parse(&format!("{issuer}/token")).expect("parse token url"),
            jwks_uri: Url::parse(&format!("{issuer}/jwks")).expect("parse jwks url"),
        },
    })
}

/// Mount JWKS + token endpoints on the mock server, and return the signing
/// key (so the JWKS matches the signature on the ID token the token
/// endpoint returns).
async fn mount_mock_oidc_idp(
    server: &wiremock::MockServer,
    key: &crate::crypto::keys::OidcSigningKey,
    id_token: String,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    // JWKS endpoint (mirrors the helper in services/idp/oidc/tests.rs).
    let jwk = key.public_key_jwk().expect("public_key_jwk should succeed");
    let jwks_json = serde_json::json!({ "keys": [crate::crypto::jwk::Jwk::Ec(jwk)] }).to_string();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json))
        .mount(server)
        .await;

    // Token endpoint: return the pre-signed ID token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id_token": id_token,
            "access_token": "fake-access-token",
            "token_type": "Bearer",
        })))
        .mount(server)
        .await;
}

/// Build the claims object for a non-Google IdP (no `hd` → domain derived
/// from the email). The nonce must match the OIDC state row's nonce.
fn id_token_claims(issuer: &str, client_id: &str, nonce: &str, email: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": issuer,
        "aud": client_id,
        "sub": "mock-subject-1",
        "exp": 9_999_999_999_i64,
        "iat": 1_000_000_000_i64,
        "email": email,
        "email_verified": true,
        "nonce": nonce,
    })
}

#[tokio::test]
async fn test_oidc_callback_rejects_whitespace_domain_email_e2e() {
    use crate::test_utils::{http_get, test_app_with_idps};

    // In-process mock OIDC IdP that signs its own ID token. HTTP on
    // localhost is allowed by the discovery/JWKS fetcher.
    let server = wiremock::MockServer::start().await;
    let issuer = server.uri();
    let key = crate::crypto::keys::OidcSigningKey::generate().expect("generate signing key");
    let nonce = "e2e-ws-domain-nonce";
    let id_token = key
        .sign_jwt(&id_token_claims(
            &issuer,
            "mock-client",
            nonce,
            "foo@bar .com",
        ))
        .await
        .expect("sign id token");
    mount_mock_oidc_idp(&server, &key, id_token).await;

    let (app, state) = test_app_with_idps(vec![mock_oidc_provider(&issuer)]).await;
    // Open-enrollment mode (the default's positive control): no allowlist.
    {
        let mut config = state.config().as_ref().clone();
        config.allowed_domains = None;
        state.config.store(std::sync::Arc::new(config));
    }

    // Seed the OIDC state row the callback will consume. provider_id must
    // match the mock IdP slug; nonce must match the ID token's.
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let state_value = "e2e-ws-domain-state";
    crate::db::create_oidc_state(
        &state.store,
        state_value,
        None,
        nonce,
        "",
        expires_at,
        "mock-idp",
    )
    .await
    .expect("create_oidc_state");

    // Drive the real /oauth/callback route end-to-end.
    let (status, body) = http_get(
        &app,
        &format!("/oauth/callback?state={state_value}&code=dummy-auth-code"),
        &[],
    )
    .await;

    // The chokepoint rejects the whitespace-bearing domain: the error
    // template renders with 200 OK (not 303 SEE_OTHER), and neither the
    // user nor the synthetic org is persisted.
    assert_eq!(
        status,
        StatusCode::OK,
        "E2E: whitespace-domain email rejected at the OIDC callback chokepoint; got {status}: {body}"
    );
    let user = crate::db::get_user_by_email(&state.store, "foo@bar .com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "E2E: a whitespace-domain email must not be persisted through the OIDC callback"
    );
}

#[tokio::test]
async fn test_oidc_callback_accepts_well_formed_email_e2e() {
    use crate::test_utils::{http_get, test_app_with_idps};

    let server = wiremock::MockServer::start().await;
    let issuer = server.uri();
    let key = crate::crypto::keys::OidcSigningKey::generate().expect("generate signing key");
    let nonce = "e2e-good-email-nonce";
    let id_token = key
        .sign_jwt(&id_token_claims(
            &issuer,
            "mock-client",
            nonce,
            "alice@example.com",
        ))
        .await
        .expect("sign id token");
    mount_mock_oidc_idp(&server, &key, id_token).await;

    let (app, state) = test_app_with_idps(vec![mock_oidc_provider(&issuer)]).await;
    {
        let mut config = state.config().as_ref().clone();
        config.allowed_domains = None;
        state.config.store(std::sync::Arc::new(config));
    }

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let state_value = "e2e-good-email-state";
    crate::db::create_oidc_state(
        &state.store,
        state_value,
        None,
        nonce,
        "",
        expires_at,
        "mock-idp",
    )
    .await
    .expect("create_oidc_state");

    let (status, body) = http_get(
        &app,
        &format!("/oauth/callback?state={state_value}&code=dummy-auth-code"),
        &[],
    )
    .await;

    // Positive control: a well-formed email proceeds through the full
    // OIDC callback to the 303 redirect (the gate does not over-reject).
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "E2E: a well-formed email must proceed through the OIDC callback; got {status}: {body}"
    );
    let user = crate::db::get_user_by_email(&state.store, "alice@example.com")
        .await
        .expect("db query ok")
        .expect("E2E: well-formed email must be persisted");
    assert_eq!(user.email, "alice@example.com");
}

#[tokio::test]
async fn test_saml_acs_rejects_whitespace_domain_email_e2e() {
    // SAML path E2E: the SAML ACS handler (`POST /saml/acs`) validates a
    // signed SAML response, extracts the email from the NameID (verbatim)
    // and the domain via `Email::domain_of`, then calls the SAME
    // `complete_enrollment_after_identity` chokepoint the OIDC callback
    // does. A NameID of `foo@bar .com` (whitespace inside the domain) must
    // be rejected at that shared gate — confirming the SAML callback path
    // inherits the fix without a separate SAML-side gate.
    use crate::services::idp::saml::response::tests::{
        build_signed_saml_response, generate_test_key_and_cert, test_provider, valid_time_window,
    };
    use crate::test_utils::{http_post_form, test_app_with_idps};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let saml_provider = test_provider(cert_der);
    // test_provider uses sp_entity_id "https://vouch.example.com" and acs_url
    // ".../saml/acs"; the test app's base_url is "https://test.example.com".
    // The ACS handler validates Destination=acs_url and Audience=sp_entity_id
    // against the provider, not the app's base_url, so reuse the provider's
    // values for the signed response.
    let acs_url = saml_provider.acs_url.clone();
    let sp_entity_id = saml_provider.sp_entity_id.clone();
    let issuer = saml_provider.idp_metadata.entity_id.clone();
    let (not_before, not_on_or_after) = valid_time_window();
    let request_id = "saml-ws-domain-request-1";

    let xml = build_signed_saml_response(
        &key_pair,
        "foo@bar .com",
        "_resp-ws-1",
        "_assert-ws-1",
        request_id,
        &acs_url,
        &issuer,
        &sp_entity_id,
        &not_before,
        &not_on_or_after,
        Some(request_id),
    );
    let saml_response = B64.encode(xml.as_bytes());

    let (app, state) = test_app_with_idps(vec![crate::services::idp::ConfiguredIdp::Saml(
        saml_provider,
    )])
    .await;
    // Open-enrollment mode (the default): no allowlist.
    {
        let mut config = state.config().as_ref().clone();
        config.allowed_domains = None;
        state.config.store(std::sync::Arc::new(config));
    }

    // Seed the state row the ACS handler will consume. The stored nonce
    // is the AuthnRequest ID the validator checks InResponseTo against.
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let relay_state = "saml-ws-domain-relay";
    crate::db::create_oidc_state(
        &state.store,
        relay_state,
        None,
        request_id,
        "",
        expires_at,
        "corp-saml",
    )
    .await
    .expect("create_oidc_state");

    let form_body = format!(
        "SAMLResponse={}&RelayState={relay_state}",
        urlencode(&saml_response)
    );
    let (status, body) = http_post_form(&app, "/saml/acs", &form_body, &[]).await;

    // The shared chokepoint rejects the whitespace-bearing domain: the
    // error template renders with 200 OK (not 303), and no user is persisted.
    assert_eq!(
        status,
        StatusCode::OK,
        "E2E SAML: whitespace-domain email rejected at the ACS chokepoint; got {status}: {body}"
    );
    let user = crate::db::get_user_by_email(&state.store, "foo@bar .com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "E2E SAML: a whitespace-domain email must not be persisted through the ACS callback"
    );
}

/// Percent-encode a string for `application/x-www-form-urlencoded` bodies.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[tokio::test]
async fn test_enrollment_allowed_domains_distinct_from_invalid_domain_gate() {
    // the new invalid-domain gate and the `allowed_domains`
    // allowlist gate remain distinct and correctly ordered. A
    // well-formed email whose domain IS in the allowlist enrolls (303);
    // a well-formed email whose domain is NOT in the allowlist renders
    // the `enroll-error-domain-not-allowed` template (the allowlist
    // gate), NOT the `enroll-error-invalid-email` template (the new
    // domain-shape gate). A whitespace-bearing domain is rejected by
    // the new gate even when the allowlist is set (the shape gate runs
    // first).

    let state = test_app_state().await;
    {
        let mut config = state.config().as_ref().clone();
        // The default test_config sets allowed_domains = ["example.com"].
        // Keep it (allowlist mode) for this test.
        config.allowed_domains = Some(vec!["example.com".to_string()]);
        state.config.store(std::sync::Arc::new(config));
    }

    // (1) Well-formed email IN the allowlist → proceeds (303).
    let (stored_in, claim_in) =
        seed_and_consume_oidc_state(&state, "allowlist-in-state", None).await;
    let identity_in = IdentityResult {
        email: "bob@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };
    let resp = complete_enrollment_after_identity(
        &state,
        &stored_in,
        identity_in,
        claim_in,
        ClientInfo::default(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "an in-allowlist well-formed email must enroll"
    );

    // (2) Well-formed email NOT in the allowlist → the allowlist gate
    // renders the domain-not-allowed template (200), distinct from the
    // invalid-domain template.
    let (stored_out, claim_out) =
        seed_and_consume_oidc_state(&state, "allowlist-out-state-2", None).await;
    let identity_out = IdentityResult {
        email: "carol@other.com".to_string(),
        domain: Some("other.com".to_string()),
        upstream: None,
    };
    let resp = complete_enrollment_after_identity(
        &state,
        &stored_out,
        identity_out,
        claim_out,
        ClientInfo::default(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "out-of-allowlist email renders the error page (200)"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = String::from_utf8(body.to_vec()).expect("utf8 body");
    assert!(
        body.contains("Domain Not Allowed") || body.contains("not from an allowed domain"),
        "out-of-allowlist must render the domain-not-allowed template, got: {body}"
    );
    assert!(
        !body.contains("invalid email address"),
        "out-of-allowlist must NOT render the invalid-email (shape-gate) template"
    );

    // (3) Whitespace-bearing domain with the allowlist set → the shape
    // gate (which runs first) rejects it with the invalid-email template,
    // NOT the allowlist template (confirming order: shape gate before
    // allowlist gate).
    let (stored_ws, claim_ws) =
        seed_and_consume_oidc_state(&state, "allowlist-ws-state", None).await;
    let identity_ws = IdentityResult {
        email: "dave@bar .com".to_string(),
        domain: Some("bar .com".to_string()),
        upstream: None,
    };
    let resp = complete_enrollment_after_identity(
        &state,
        &stored_ws,
        identity_ws,
        claim_ws,
        ClientInfo::default(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "whitespace-domain email renders the error page (200) even with allowlist set"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = String::from_utf8(body.to_vec()).expect("utf8 body");
    assert!(
        body.contains("invalid email address"),
        "whitespace-domain with allowlist set must render the invalid-email (shape-gate) \
         template, got: {body}"
    );
    assert!(
        !body.contains("Domain Not Allowed"),
        "whitespace-domain must NOT render the allowlist template (shape gate runs first)"
    );
}

/// (state, claim) pair `complete_enrollment_after_identity` requires.
async fn seed_and_consume_oidc_state(
    state: &AppState,
    state_value: &str,
    device_auth_id: Option<&str>,
) -> (crate::db::OidcState, crate::db::OidcStateClaim) {
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    crate::db::create_oidc_state(
        &state.store,
        state_value,
        device_auth_id,
        "test-nonce",
        "",
        expires_at,
        "",
    )
    .await
    .expect("create_oidc_state");
    crate::db::try_consume_oidc_state(&state.store, state_value)
        .await
        .expect("consume oidc state")
}

/// Query the audit store for events of `event_type` for the user. Audit
/// writes are awaited before the handler responds, so the rows are
/// visible immediately.
async fn audit_events_for(
    state: &AppState,
    event_type: &str,
    user_id: &str,
) -> Vec<crate::db::AuditEvent> {
    state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec![event_type.to_string()]),
            user_id: Some(user_id.to_string()),
            ..Default::default()
        })
        .await
        .expect("query audit events")
}

#[tokio::test]
async fn test_direct_web_signin_returning_user_logs_login_success_with_ip() {
    // Direct browser sign-in (empty device_auth_id) by a user who
    // already has a passkey: emits login_success carrying the client IP
    // and no authenticator_id (no FIDO2 assertion happened), and must
    // NOT be recorded as a CLI device-auth approval.
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "returning@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;

    let (stored, claim) = seed_and_consume_oidc_state(&state, "direct-web-state", None).await;

    let client_info = ClientInfo {
        client_ip: Some("203.0.113.7".parse().expect("valid IP")),
        ..Default::default()
    };
    let identity = IdentityResult {
        email: "returning@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, client_info).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let events = audit_events_for(&state, "login_success", &user.id).await;
    assert_eq!(events.len(), 1, "one direct sign-in -> one login_success");
    let event = events.first().expect("login_success event");
    let data: serde_json::Value = serde_json::from_str(&event.data).expect("event data JSON");
    assert_eq!(data["client_ip"], "203.0.113.7");
    assert!(
        data["authenticator_id"].is_null(),
        "no FIDO2 assertion happened, got: {data}"
    );

    let approvals = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        approvals.is_empty(),
        "direct sign-in must not emit device_auth_approved"
    );
}

// ── Regression: bootstrap session must NOT delete keys without FIDO2 ────
//
// The enrollment bootstrap session minted after upstream IdP sign-in (no
// FIDO2 assertion) must carry `auth_time: None`. The destructive-key
// freshness gate in `handlers::enroll_keys::delete_key` anchors on
// `auth_time.unwrap_or(0)`; with the fix it sees Unix epoch and demands a
// step-up. Before the fix the bootstrap session carried the IdP login
// time, so an attacker who hijacked the victim's IdP session could sign
// in directly via the browser, land on `/enroll/keys`, and delete the
// victim's keys (n-1) within the 60-second window without ever touching a
// security key.
//
// This drives the real `complete_enrollment_after_identity` handler for a
// returning user with existing keys on a direct browser sign-in (no CLI),
// extracts the issued session cookie, decodes the JWT to assert `auth_time`
// is absent, then issues `DELETE /enroll/keys/{id}` through the router with
// that cookie and asserts it is rejected with `insufficient_user_authentication`.
#[tokio::test]
async fn test_direct_web_signin_bootstrap_session_cannot_delete_keys() {
    let (app, state) = test_app().await;
    // Two keys: the "last key" guard refuses to delete the only key, so a
    // deletion that *would* be allowed by the freshness gate needs a spare
    // to reach the delete step at all.
    let user = create_test_user(&state.store, "bootstrap-delete@example.com").await;
    let kept = create_test_authenticator(&state.store, &user.id).await;
    let doomed = create_test_authenticator(&state.store, &user.id).await;

    let (stored, claim) = seed_and_consume_oidc_state(&state, "bootstrap-delete-state", None).await;
    let identity = IdentityResult {
        email: "bootstrap-delete@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // A direct web sign-in (no CLI waiting) lands on the keys page; the
    // bootstrap session permits key management, and the exploit drives the
    // DELETE endpoint with the issued cookie.
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii location")
        .to_string();
    assert_eq!(
        location, "/enroll/keys",
        "direct returning-user sign-in lands on the keys page, got {location}"
    );

    // Extract the session cookie value the handler just issued.
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header must be present")
        .to_str()
        .expect("ascii Set-Cookie");
    let cookie_value = set_cookie
        .split_once(&format!("{}=", vouch_common::SESSION_COOKIE_NAME))
        .and_then(|(_, rest)| rest.split(';').next())
        .expect("extract cookie value");

    // G1: the bootstrap session JWT MUST NOT carry `auth_time` — no FIDO2
    // authentication occurred on this direct IdP sign-in.
    let jwt_payload = decode_jwt_payload_claims(cookie_value);
    assert!(
        matches!(
            jwt_payload.get("auth_time"),
            None | Some(serde_json::Value::Null)
        ),
        "bootstrap session must not carry auth_time (no FIDO2 occurred): {jwt_payload}"
    );
    // The session is also not hardware-verified (sanity-check the shape).
    assert_eq!(
        jwt_payload
            .get("hardware_verified")
            .and_then(|v| v.as_bool()),
        Some(false),
        "bootstrap session hardware_verified must be false: {jwt_payload}"
    );

    // Drive DELETE /enroll/keys/{doomed} through the router with the cookie.
    let cookie_header = format!("{}={}", vouch_common::SESSION_COOKIE_NAME, cookie_value);
    let resp = http_delete_full(
        &app,
        &format!("/enroll/keys/{doomed}"),
        &[
            ("Cookie", &cookie_header),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;

    // G2: the destructive-key freshness gate must fail closed — the
    // bootstrap session has no recent FIDO2 auth_time, so step-up is
    // required rather than letting the IdP login time authorize deletion.
    assert_eq!(
        resp.status,
        StatusCode::UNAUTHORIZED,
        "bootstrap session must not be able to delete keys, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("insufficient_user_authentication"),
        "expected step-up error code, body: {}",
        resp.body
    );

    // G3: the victim's keys survive. List via the same cookie and confirm
    // both `kept` and `doomed` are still present (no partial deletion).
    let resp = http_get_full(&app, "/enroll/keys/api", &[("Cookie", &cookie_header)]).await;
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "list keys failed: {}",
        resp.body
    );
    let body: serde_json::Value = serde_json::from_str(&resp.body).expect("json body");
    let ids: Vec<&str> = body
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .expect("keys[]")
        .iter()
        .map(|k| {
            k.get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        })
        .collect();
    assert!(
        ids.contains(&kept.as_str()) && ids.contains(&doomed.as_str()),
        "both keys must survive the rejected deletion, got ids: {ids:?}"
    );
}

#[tokio::test]
async fn test_cli_enroll_returning_user_requires_assertion_before_approval() {
    // `vouch enroll` by a user who already has a key: the upstream IdP
    // sign-in authenticates the person, not the hardware, so the pending
    // device authorization stays Pending and the browser is sent to /login
    // to assert.
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "cli-returning@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;

    let device_code_hash = "cli-returning-device-code-hash";
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let device_auth_id = crate::db::create_device_auth_request(
        &state.store,
        device_code_hash,
        "CLI-RTRN",
        None,
        expires_at,
        0,
    )
    .await
    .expect("create_device_auth_request");

    let (stored, claim) =
        seed_and_consume_oidc_state(&state, "cli-returning-state", Some(&device_auth_id)).await;

    let identity = IdentityResult {
        email: "cli-returning@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect location");
    assert_eq!(
        location, "/login",
        "a returning user must be sent to assert with their key"
    );

    let request = crate::db::get_device_auth_by_code_hash(&state.store, device_code_hash)
        .await
        .expect("device auth lookup")
        .expect("device auth exists");
    assert!(
        matches!(request.state, crate::db::DeviceAuthState::Pending),
        "IdP sign-in alone must not release the waiting CLI"
    );

    let approvals = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        approvals.is_empty(),
        "no approval may be recorded before the assertion"
    );

    let logins = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["login_success".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        logins.is_empty(),
        "an IdP sign-in that still owes an assertion is not a completed login"
    );
}

#[tokio::test]
async fn test_identity_conflict_renders_error_and_audits() {
    // An IdP login whose asserted (issuer, subject) does not match the
    // subject already bound to the account with this email must be
    // refused: no session cookie, an error page, and one
    // identity_bind_refused audit event that carries idp_issuer but no
    // raw email in its data payload.
    let state = test_app_state().await;
    let issuer = "https://idp.conflict.example";
    let victim = db::enroll_user_with_org(
        &state.store,
        "shared@example.com",
        None,
        None,
        Some(&db::UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("victim-subject".to_string()),
        }),
    )
    .await
    .expect("seed bound victim");

    let (stored, claim) = seed_and_consume_oidc_state(&state, "conflict-state", None).await;

    let identity = IdentityResult {
        email: "shared@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: Some(db::UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("attacker-subject".to_string()),
        }),
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;

    // Error page renders 200 OK, and crucially carries no session cookie.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "a refused login must not set a session cookie"
    );

    let events = audit_events_for(&state, "identity_bind_refused", &victim.id).await;
    assert_eq!(events.len(), 1, "one refusal -> one audit event");
    let event = events.first().expect("identity_bind_refused event");
    let data: serde_json::Value = serde_json::from_str(&event.data).expect("event data JSON");
    assert_eq!(data["idp_issuer"], issuer);
    assert!(
        data.get("email").is_none() && data.get("subject").is_none(),
        "audit payload must not carry raw email or subject: {data}"
    );
}

#[tokio::test]
async fn test_non_durable_login_refused_once_issuer_is_bound() {
    // Bugbot finding on PR #837: an account bound to a durable
    // (issuer, subject) — e.g. via a persistent-format SAML NameID —
    // must refuse a later login through the same issuer that carries
    // no durable subject at all (e.g. the IdP sent an
    // emailAddress-format NameID this time), rather than silently
    // falling back to an email-only match. Same observable behavior
    // as a subject mismatch: error page, no cookie, one
    // identity_bind_refused event.
    let state = test_app_state().await;
    let issuer = "https://idp.downgrade.example";
    let victim = db::enroll_user_with_org(
        &state.store,
        "shared@example.com",
        None,
        None,
        Some(&db::UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("victim-subject".to_string()),
        }),
    )
    .await
    .expect("seed bound victim");

    let (stored, claim) = seed_and_consume_oidc_state(&state, "downgrade-state", None).await;

    let identity = IdentityResult {
        email: "shared@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: Some(db::UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: None,
        }),
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "a refused login must not set a session cookie"
    );

    let events = audit_events_for(&state, "identity_bind_refused", &victim.id).await;
    assert_eq!(events.len(), 1, "one refusal -> one audit event");
    let event = events.first().expect("identity_bind_refused event");
    let data: serde_json::Value = serde_json::from_str(&event.data).expect("event data JSON");
    assert_eq!(data["idp_issuer"], issuer);
}

#[tokio::test]
async fn test_lazy_bind_emits_identity_bound_event() {
    // A legacy account (no bindings) signing in through an IdP for the
    // first time is lazily bound and emits identity_bound with the
    // issuer; the sign-in itself succeeds (redirects to the keys page).
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "legacy@example.com").await;

    let (stored, claim) = seed_and_consume_oidc_state(&state, "lazy-bind-state", None).await;

    let issuer = "https://idp.lazy.example";
    let identity = IdentityResult {
        email: "legacy@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: Some(db::UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("legacy-subject".to_string()),
        }),
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let events = audit_events_for(&state, "identity_bound", &user.id).await;
    assert_eq!(events.len(), 1, "first IdP login -> one identity_bound");
    let event = events.first().expect("identity_bound event");
    let data: serde_json::Value = serde_json::from_str(&event.data).expect("event data JSON");
    assert_eq!(data["idp_issuer"], issuer);
}

// Regression for #746: if the device auth cannot be authorized — the row
// expired and was reclaimed, or the callback was submitted twice — the
// failure was logged and the flow continued to the keys page as though
// sign-in had worked, leaving the CLI to poll until timeout. The user must
// get an error page instead.
#[tokio::test]
async fn test_cli_device_auth_failure_renders_error_instead_of_redirect() {
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "cli-stale-da@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;

    // A device_auth_id with no row behind it: authorize_device_auth bails.
    let (stored, claim) =
        seed_and_consume_oidc_state(&state, "cli-stale-da-state", Some("reclaimed-device-auth"))
            .await;

    let identity = IdentityResult {
        email: "cli-stale-da@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;

    assert_ne!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a failed device authorization must not redirect as though sign-in succeeded"
    );
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "no session cookie may be issued when the device auth was not approved"
    );

    // The device auth stays unapproved rather than being silently skipped.
    let approvals = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        approvals.is_empty(),
        "no approval event may be recorded when authorization failed"
    );
}

#[tokio::test]
async fn test_direct_web_enrollment_new_user_emits_no_login_event() {
    // Direct browser sign-in by a brand-new user (no passkey yet):
    // nothing is audited at the IdP stage — the Enrollment event in
    // browser_register_complete covers them after key registration.
    let state = test_app_state().await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "direct-new-user-state", None).await;

    let identity = IdentityResult {
        email: "fresh@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };
    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // A fresh enrollee has no key to assert with: they must reach the keys
    // page to register one, not the /login assertion form.
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii location");
    assert_eq!(
        location, "/enroll/keys",
        "fresh enrollee must be sent to register a first key, got {location}"
    );

    // Audit writes are awaited before the handler responds, so absence
    // here is conclusive.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter::default())
        .await
        .expect("query audit events");
    assert!(
        events.is_empty(),
        "fresh enrollee sign-in emits no audit events yet, got {}",
        events.len()
    );
}

// ── IdP chooser tests ────────────────────────────────────────────────

/// Build a [`ConfiguredIdp::Oidc`] for tests against the given issuer
/// (the issuer drives the chooser button's brand/display name).
fn make_test_oidc_idp(id: &str, issuer: &str) -> crate::services::idp::ConfiguredIdp {
    use secrecy::SecretString;
    crate::services::idp::ConfiguredIdp::Oidc(crate::services::idp::ConfiguredOidcProvider {
        id: id.to_string(),
        client_id: format!("{id}-client-id"),
        client_secret: SecretString::from(format!("{id}-secret")),
        provider: crate::services::idp::oidc::OidcProvider {
            issuer: issuer.to_string(),
            authorization_endpoint: url::Url::parse(&format!("{issuer}/authorize"))
                .expect("auth endpoint url"),
            token_endpoint: url::Url::parse(&format!("{issuer}/token"))
                .expect("token endpoint url"),
            jwks_uri: url::Url::parse(&format!("{issuer}/jwks")).expect("jwks url"),
        },
    })
}

/// Seed a pending device-auth row with a valid user code, return the code.
async fn seed_pending_device_auth(state: &AppState, user_code: &str) {
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    crate::db::create_device_auth_request(
        &state.store,
        &format!("hash-{user_code}"),
        user_code,
        None,
        expires_at,
        5,
    )
    .await
    .expect("seed device_auth_request");
}

fn two_idps() -> Vec<crate::services::idp::ConfiguredIdp> {
    vec![
        make_test_oidc_idp("google", "https://accounts.google.com"),
        make_test_oidc_idp("entra", "https://login.microsoftonline.com/common/v2.0"),
    ]
}

#[tokio::test]
async fn device_chooser_rendered_when_multiple_idps_and_no_provider() {
    let (app, state) = crate::test_utils::test_app_with_idps(two_idps()).await;
    seed_pending_device_auth(&state, "BCDF-GHJK").await;

    let (status, body) = crate::test_utils::http_post_form(
        &app,
        "/device",
        "user_code=BCDF-GHJK",
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "chooser renders 200 OK; body: {body}"
    );
    assert!(
        body.contains("Choose your identity provider"),
        "expected chooser heading, got: {body}"
    );
    assert!(
        body.contains("Sign in with Google"),
        "expected Google button, got: {body}"
    );
    assert!(
        body.contains("Sign in with Microsoft"),
        "expected Microsoft button, got: {body}"
    );
    assert!(
        body.contains("name=\"user_code\""),
        "chooser must carry user_code forward as hidden field; got: {body}"
    );
    assert!(
        body.contains("value=\"BCDF-GHJK\""),
        "hidden user_code value must match; got: {body}"
    );
}

#[tokio::test]
async fn device_redirects_when_provider_selected() {
    let (app, state) = crate::test_utils::test_app_with_idps(two_idps()).await;
    seed_pending_device_auth(&state, "BCDF-GHJK").await;

    let resp = crate::test_utils::http_post_form_full(
        &app,
        "/device",
        "user_code=BCDF-GHJK&provider=entra",
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "want 303 redirect; body: {}",
        resp.body
    );
    let location = resp
        .headers
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii Location");
    assert!(
        location.starts_with("https://login.microsoftonline.com"),
        "expected Microsoft auth URL, got: {location}"
    );
}

#[tokio::test]
async fn device_rejects_unknown_provider_slug() {
    let (app, state) = crate::test_utils::test_app_with_idps(two_idps()).await;
    seed_pending_device_auth(&state, "BCDF-GHJK").await;

    let (status, body) = crate::test_utils::http_post_form(
        &app,
        "/device",
        "user_code=BCDF-GHJK&provider=evil",
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "error template renders 200 OK; body: {body}"
    );
    assert!(
        body.contains("Unknown Provider"),
        "expected 'Unknown Provider' title, got: {body}"
    );
    assert!(
        // Askama HTML-escapes single quotes, so the rendered message
        // contains `&#39;evil&#39;` rather than `'evil'`. The slug name
        // alone is enough to confirm it round-tripped into the error.
        body.contains("evil"),
        "expected slug 'evil' echoed in message, got: {body}"
    );
}

#[tokio::test]
async fn device_single_idp_auto_selects_without_chooser() {
    let idps = vec![make_test_oidc_idp("google", "https://accounts.google.com")];
    let (app, state) = crate::test_utils::test_app_with_idps(idps).await;
    seed_pending_device_auth(&state, "BCDF-GHJK").await;

    let resp = crate::test_utils::http_post_form_full(
        &app,
        "/device",
        "user_code=BCDF-GHJK",
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "single IdP must auto-select; body: {}",
        resp.body
    );
    let location = resp
        .headers
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii Location");
    assert!(
        location.starts_with("https://accounts.google.com"),
        "expected Google auth URL, got: {location}"
    );
}

#[tokio::test]
async fn device_zero_idps_renders_not_configured_error() {
    // Without an IdP we have no way to verify identity or email, so the
    // device flow must refuse rather than fall through to a WebAuthn
    // registration that would create a user keyed on the literal string
    // "new user".
    let (app, state) = test_app().await;
    seed_pending_device_auth(&state, "BCDF-GHJK").await;

    let (status, body) = crate::test_utils::http_post_form(
        &app,
        "/device",
        "user_code=BCDF-GHJK",
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "error template renders 200 OK; body: {body}"
    );
    assert!(
        body.contains("Not Configured"),
        "expected 'Not Configured' title, got: {body}"
    );
    assert!(
        !body.contains("Choose your identity provider"),
        "chooser must NOT render with zero IdPs; got: {body}"
    );
}

#[tokio::test]
async fn enroll_start_chooser_rendered_when_multiple_idps_and_no_provider() {
    let (app, _state) = crate::test_utils::test_app_with_idps(two_idps()).await;

    let (status, body) = crate::test_utils::http_get(&app, "/enroll/start", &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "chooser renders 200 OK; body: {body}"
    );
    assert!(
        body.contains("Choose your identity provider"),
        "expected chooser heading, got: {body}"
    );
    assert!(
        body.contains("/enroll/start?provider=google"),
        "expected Google chooser link, got: {body}"
    );
    assert!(
        body.contains("/enroll/start?provider=entra"),
        "expected Microsoft chooser link, got: {body}"
    );
}

#[tokio::test]
async fn enroll_start_redirects_when_provider_selected() {
    let (app, _state) = crate::test_utils::test_app_with_idps(two_idps()).await;

    let resp = crate::test_utils::http_get_full(&app, "/enroll/start?provider=entra", &[]).await;

    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "want 303 redirect; body: {}",
        resp.body
    );
    let location = resp
        .headers
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii Location");
    assert!(
        location.starts_with("https://login.microsoftonline.com"),
        "expected Microsoft auth URL, got: {location}"
    );
}

#[tokio::test]
async fn enroll_start_single_idp_auto_selects_without_chooser() {
    let idps = vec![make_test_oidc_idp("google", "https://accounts.google.com")];
    let (app, _state) = crate::test_utils::test_app_with_idps(idps).await;

    let resp = crate::test_utils::http_get_full(&app, "/enroll/start", &[]).await;

    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "single IdP must auto-select; body: {}",
        resp.body
    );
    let location = resp
        .headers
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii Location");
    assert!(
        location.starts_with("https://accounts.google.com"),
        "expected Google auth URL, got: {location}"
    );
}

// ── Device verification page pre-fill tests ──────────────────────────

#[tokio::test]
async fn device_verify_page_prefills_valid_user_code() {
    // GET /device?user_code=<valid> pre-fills the input via
    // verification_uri_complete (RFC 8628 §3.3.1).
    let (app, _state) = test_app().await;
    let (status, body) =
        crate::test_utils::http_get(&app, "/device?user_code=QHJT-ZLFH", &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"value="QHJT-ZLFH""#),
        "valid code must be pre-filled, got: {body}"
    );
}

#[tokio::test]
async fn device_verify_page_ignores_invalid_user_code() {
    // A malformed user_code must not be reflected into the page.
    let (app, _state) = test_app().await;
    let (status, body) = crate::test_utils::http_get(&app, "/device?user_code=garbage", &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("GARBAGE"),
        "invalid code must not be reflected, got: {body}"
    );
}

// ── browser_register_complete requires a verified attestation chain ─────
//
// Issue #1111: a self-attested registration used to be accepted, and the
// AAGUID the client put in authData became the `hardware_aaguid` claim that
// relying parties use to gate access by authenticator model. Registration now
// requires an x5c chain that validates against a pinned Yubico root, with no
// setting to relax it, so the forgery has nowhere to enter.
//
// This drives the real endpoint with a well-formed, correctly signed
// self-attestation — everything a forger could produce — and asserts it is
// refused.
//
// This test previously asserted the opposite: that the same object enrolled
// successfully and that the resulting session JWT carried `auth_time`,
// `hardware_verified`, `amr` and `acr` (the regression guard from #1124). That
// success path is no longer reachable from a test, because minting a
// certificate under a pinned Yubico root is exactly what the change makes
// impossible. The claim mapping those assertions covered now lives in
// `services::auth::tests::test_verified_hardware_sets_amr_acr_and_flag`.
#[expect(
    clippy::too_many_lines,
    reason = "end-to-end self-attestation forging: ES256 keypair, COSE_Key, \
              authData, clientData, attStmt, plus the caller-binding session \
              and cookie setup the fix requires"
)]
#[tokio::test]
async fn test_browser_register_complete_rejects_self_attestation() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    let (app, state) = test_app().await;

    // Pre-create the user + session so `complete_enrollment_after_identity`-style
    // rows exist and the cookie's `sub` matches the state JWT's `user_id`.
    // The fix re-binds the caller to that id; without a matching cookie the
    // request would be rejected before the attestation check runs.
    let user_email = "auth-time-regression@example.com";
    let user = create_test_user(&state.store, user_email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let user_id = Uuid::parse_str(&user.id).expect("user id is a uuid");

    // 1. Build a valid BrowserRegistrationState JWT and extract the challenge.
    let (ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, user_email, user_email, None)
        .expect("start_passkey_registration");

    let challenge_bytes: &[u8] = ccr.public_key.challenge.as_ref();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: user_email.to_string(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };
    let state_token = reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state");

    // 2. Generate an ES256 software keypair to act as the "authenticator".
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate ES256 key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
        .expect("parse ES256 key");
    let pub_bytes = key_pair.public_key().as_ref();
    // pub_bytes is 0x04 || X(32) || Y(33) — SEC1 uncompressed point.
    let x: &[u8] = &pub_bytes[1..33];
    let y: &[u8] = &pub_bytes[33..65];

    // 3. Build the COSE_Key (ES256 / P-256).
    let cose_key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()),
        ), // kty: EC2
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer((-7i64).into()),
        ), // alg: ES256
        (
            ciborium::Value::Integer((-1i64).into()),
            ciborium::Value::Integer(1.into()),
        ), // crv: P-256
        (
            ciborium::Value::Integer((-2i64).into()),
            ciborium::Value::Bytes(x.to_vec()),
        ),
        (
            ciborium::Value::Integer((-3i64).into()),
            ciborium::Value::Bytes(y.to_vec()),
        ),
    ]);

    // 4. Build the authData:
    //    rpIdHash(32) + flags(1: AT|UV|UP=0x45) + signCount(4) +
    //    attestedCredentialData: aaguid(16) + credIdLen(2) + credId + COSE_Key
    let rp_id_hash =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, state.config().rp_id.as_bytes());
    let mut auth_data: Vec<u8> = rp_id_hash.as_ref().to_vec();
    auth_data.push(0x45); // AT (0x40) | UV (0x04) | UP (0x01)
    auth_data.extend_from_slice(&[0u8; 4]); // signCount = 0
    // aaguid: 16 bytes (use YubiKey 5 NFC AAGUID so validate_registration_attestation passes)
    let aaguid: [u8; 16] = [
        0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
        0xa8,
    ];
    auth_data.extend_from_slice(&aaguid);
    // credential ID: 16 random-ish bytes (deterministic here is fine)
    let cred_id: [u8; 16] = [0x42; 16];
    auth_data.extend_from_slice(
        &u16::try_from(cred_id.len())
            .expect("cred_id length fits in u16")
            .to_be_bytes(),
    );
    auth_data.extend_from_slice(&cred_id);
    // append COSE_Key
    let mut cose_key_bytes = Vec::new();
    ciborium::into_writer(&cose_key, &mut cose_key_bytes).expect("serialize cose key");
    auth_data.extend_from_slice(&cose_key_bytes);

    // 5. Build the client data JSON.
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge_b64,
        "origin": state.config().base_url,
    });
    let client_data_bytes = serde_json::to_vec(&client_data).expect("serialize client data");
    let client_data_hash =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &client_data_bytes);

    // 6. Build the attestation signature over authData || clientDataHash.
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&auth_data);
    verification_data.extend_from_slice(client_data_hash.as_ref());
    let sig = key_pair
        .sign(&rng, &verification_data)
        .expect("sign attestation");

    // 7. Build the packed attStmt (self-attestation: no x5c, no ecdaaKeyId).
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("alg".to_string()),
            ciborium::Value::Integer((-7i64).into()), // ES256
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(sig.as_ref().to_vec()),
        ),
    ]);

    // 8. Build the attestation object: { fmt: "packed", attStmt, authData }.
    let att_obj = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("packed".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data.clone()),
        ),
    ]);
    let mut att_obj_bytes = Vec::new();
    ciborium::into_writer(&att_obj, &mut att_obj_bytes).expect("serialize att obj");

    // 9. Submit to /enroll/webauthn/complete.
    let body = serde_json::json!({
        "state": state_token,
        "credential_id": URL_SAFE_NO_PAD.encode(cred_id),
        "attestation_object": URL_SAFE_NO_PAD.encode(&att_obj_bytes),
        "client_data_json": URL_SAFE_NO_PAD.encode(&client_data_bytes),
    })
    .to_string();

    let resp = crate::test_utils::http_request_full(
        &app,
        "POST",
        "/enroll/webauthn/complete",
        Some(body),
        &[
            ("Content-Type", "application/json"),
            ("Cookie", session_cookie_header(&session_token).as_str()),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;

    assert_eq!(
        resp.status,
        StatusCode::BAD_REQUEST,
        "a self-attested registration must be refused, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("attestation_cert_required"),
        "expected attestation_cert_required, body: {}",
        resp.body
    );
    assert!(
        resp.headers.get(axum::http::header::SET_COOKIE).is_none(),
        "a refused registration must not establish a session"
    );
}

#[tokio::test]
async fn test_browser_register_start_refuses_deactivated_user() {
    // A deactivated user's surviving enrollment cookie must not begin
    // new hardware-key registration (issue #846).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "deactivated-start@example.com").await;
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

    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, body) = http_post_json(
        &app,
        "/enroll/webauthn/start",
        "{}",
        &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deactivated user must not start key registration: {body}"
    );
}

#[tokio::test]
async fn test_browser_register_complete_refuses_deactivated_user() {
    // A user deactivated after obtaining the registration state (valid
    // for five minutes) must not complete key registration (issue #846).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "deactivated-complete@example.com").await;
    // The session is minted BEFORE deactivation; sessions survive
    // `update_user_active_status` (admin tooling revokes sessions in a
    // separate step). The cookie therefore still extracts a token whose
    // `sub` matches the state JWT — the caller-binding check passes, and
    // the deactivated-user guard fires as it did before the fix.
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
    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");
    let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");

    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.email, &user.email, None)
        .expect("start_passkey_registration");
    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id: user_uuid,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };
    let state_jwt = reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state");

    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let cookie = session_cookie_header(&token);
    let (status, resp) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[
            ("Cookie", cookie.as_str()),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deactivated user must not complete key registration: {resp}"
    );
}

// ── browser_register_complete re-binds the caller to the state JWT ────────
//
// Mirrors the fix applied to the CLI `register_complete`: the cookie
// identified by `extract_session_from_cookie` must hold the same `sub` as
// the state JWT's `user_id`. A captured state JWT is server-signed but not
// encrypted; without this check an attacker who holds it could complete
// the enrollment against the victim's account while presenting only the
// per-route body checks.

/// Build a user + a session cookie the way `browser_register_start` would
/// establish one (so the caller is genuinely a logged-in account) and
/// return both the user row and the raw `Cookie` header value.
async fn browser_user_session(state: &AppState, email: &str) -> (crate::db::User, String) {
    let user = create_test_user(&state.store, email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    (user, session_cookie_header(&token))
}

/// Mint a `BrowserRegistrationState` JWT bound to `user.id`, returning the
/// token and the expiry timestamp the consume test helper needs.
async fn browser_register_state(state: &AppState, user: &crate::db::User) -> (String, i64) {
    let user_id = Uuid::parse_str(&user.id).expect("user id is a uuid");
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user.email, &user.email, None)
        .expect("start_passkey_registration");
    let now = jiff::Timestamp::now();
    let exp = now.as_second() + 300;
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp,
    };
    let jwt = reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state");
    (jwt, exp)
}

#[tokio::test]
async fn test_browser_register_complete_rejects_state_user_mismatch() {
    // Attacker captures the victim's state JWT and submits the completion
    // under their own session cookie. The mismatch must be rejected with
    // 403 forbidden / state_user_mismatch *before* the single-use consume,
    // so the victim can still spend the state later.
    let (app, state) = test_app().await;
    let (victim, victim_cookie) =
        browser_user_session(&state, "victim-browser-mismatch@example.com").await;
    let (attacker, attacker_cookie) =
        browser_user_session(&state, "attacker-browser-mismatch@example.com").await;
    assert_ne!(victim.id, attacker.id, "test setup must distinct users");

    let (state_jwt, exp) = browser_register_state(&state, &victim).await;

    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[
            ("Cookie", attacker_cookie.as_str()),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "mismatched cookie must 403: {resp_body}"
    );
    assert!(
        resp_body.contains("state_user_mismatch"),
        "expected 'state_user_mismatch' in body, got: {resp_body}"
    );

    // The rejected mismatch must NOT have consumed the victim's state
    // token. `consume_challenge_state_for_test` is the only way to splice
    // into the single-use store, so this assertion consumes the token as
    // a side-effect — that's why the legitimate retry below uses a
    // *fresh* state JWT.
    let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
    let consume =
        crate::db::consume_challenge_state_for_test(&state.store, &state_jwt, expires_at).await;
    assert!(
        consume.is_ok(),
        "a rejected mismatch consumed the victim's registration state: {consume:?}"
    );

    // The legitimate retry: the victim spends a fresh state JWT with a
    // matching cookie. The caller-binding check passes, the active-user
    // check passes (victim is active), the consume succeeds, and the
    // request lands in the AAGUID/x5c check — `valid_attestation_object`
    // rejects minimal bytes there with `attestation_cert_required`. Must
    // NOT 403 at the caller-binding guard.
    let (state_jwt, _exp) = browser_register_state(&state, &victim).await;
    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();
    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[
            ("Cookie", victim_cookie.as_str()),
            ("Origin", "https://test.example.com"),
        ],
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "victim with matching cookie must not 403: {resp_body}"
    );
}

#[tokio::test]
async fn test_browser_register_complete_requires_session() {
    // Without a session cookie the request must be rejected by
    // `extract_session_from_cookie` before any state work: the WebAuthn
    // ceremony must not be readable by an anonymous caller of the open
    // `/enroll/webauthn/complete` route.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "no-session@example.com").await;
    let (state_jwt, _exp) = browser_register_state(&state, &user).await;

    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing cookie must 401: {resp_body}"
    );
    assert!(
        resp_body.contains("unauthorized") || resp_body.contains("invalid_session"),
        "expected unauthorized/invalid_session, got: {resp_body}"
    );
}

// ── a rejected body must leave the registration state unconsumed ─────────
//
// Field lengths are rejected during deserialization and the remaining checks
// are what build a `RegistrationCompletion`, which the consume takes as an
// argument. Either way the rejection happens first, so the user can retry the
// same enrollment with the same state token.

/// Build a registration state JWT together with the expiry needed to consume
/// it directly, which `make_valid_state_token` does not expose.
async fn make_state_token_with_exp(state: &AppState, email: &str) -> (String, i64) {
    let user_id = Uuid::now_v7();
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, email, email, None)
        .expect("start_passkey_registration");

    let now = jiff::Timestamp::now();
    let exp = now.as_second() + 300;
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: email.to_string(),
        webauthn_state,
        iat: now.as_second(),
        exp,
    };

    let jwt = reg_state
        .encode(&state.state_signer)
        .await
        .expect("encode state");
    (jwt, exp)
}

/// Assert the state token is still unconsumed by spending it directly.
async fn assert_state_unconsumed(state: &AppState, state_jwt: &str, exp: i64) {
    let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
    let consume =
        crate::db::consume_challenge_state_for_test(&state.store, state_jwt, expires_at).await;
    assert!(
        consume.is_ok(),
        "a rejected request consumed the registration state: {consume:?}"
    );
}

#[tokio::test]
async fn test_enrollment_complete_empty_credential_id_leaves_state_unconsumed() {
    let (app, state) = test_app().await;
    let (state_jwt, exp) = make_state_token_with_exp(&state, "empty-cred@example.com").await;

    // An empty string is valid base64url decoding to `vec![]`. The
    // `CredentialIdData` bound rejects it while the body is deserialized, so
    // the handler never runs and `invalid_request` is the extractor's code.
    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": "",
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
    assert!(
        resp_body.contains("invalid_request"),
        "expected 'invalid_request' in body, got: {resp_body}"
    );
    assert_state_unconsumed(&state, &state_jwt, exp).await;
}

#[tokio::test]
async fn test_enrollment_complete_malformed_client_data_leaves_state_unconsumed() {
    let (app, state) = test_app().await;
    let (state_jwt, exp) = make_state_token_with_exp(&state, "bad-client-data@example.com").await;

    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        // Well-formed base64url, so it survives deserialization, but not JSON.
        "client_data_json": URL_SAFE_NO_PAD.encode(b"not json"),
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
    assert!(
        resp_body.contains("invalid_client_data"),
        "expected 'invalid_client_data' in body, got: {resp_body}"
    );
    assert_state_unconsumed(&state, &state_jwt, exp).await;
}

#[tokio::test]
async fn test_enrollment_complete_foreign_origin_leaves_state_unconsumed() {
    let (app, state) = test_app().await;
    let (state_jwt, exp) = make_state_token_with_exp(&state, "foreign-origin@example.com").await;

    let client_data = URL_SAFE_NO_PAD.encode(
        r#"{"type":"webauthn.create","challenge":"abc","origin":"https://evil.example.com"}"#,
    );
    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": client_data,
    })
    .to_string();

    let (status, resp_body) = http_post_json(
        &app,
        "/enroll/webauthn/complete",
        &body,
        &[("Origin", "https://test.example.com")],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp_body}");
    assert!(
        resp_body.contains("invalid_client_data"),
        "expected 'invalid_client_data' in body, got: {resp_body}"
    );
    assert_state_unconsumed(&state, &state_jwt, exp).await;
}

// ── finalize_enrollment_audit_and_device_auth ─────────────────────────────
//
// `Enrollment` is the handler's only production emit site for
// `AuthEventType::Enrollment`. It is recorded *before* the fallible
// `authorize_device_auth` release so a committed authenticator always has a
// matching enrollment event even when the CLI release fails. The full
// `browser_register_complete` path needs a Yubico-pinned attestation chain,
// so these tests exercise the extracted tail directly — the same tail the
// handler runs after `create_authenticator` commits.

#[tokio::test]
async fn finalize_enrollment_audit_records_enrollment_when_device_auth_release_fails() {
    // Regression: `authorize_device_auth` returns Err after `create_authenticator`
    // already committed the row. The `Enrollment` audit event must still be
    // recorded — the pre-fix code placed it after the fallible `?`, skipping it.
    // `device_auth_id` references no row, so `authorize_device_auth` bails at
    // the "no device auth request found" arm — the cleanup-swept-row and the
    // concurrent-tab-loses-CAS triggers hit the same path in production.
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "da-fail@example.com").await;
    // Stand-in for the authenticator `create_authenticator` already committed.
    let authenticator_id = create_test_authenticator(&state.store, &user.id).await;

    let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.email, &user.email, None)
        .expect("start_passkey_registration");
    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id: "reclaimed-device-auth".to_string(),
        user_id: user_uuid,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };
    let now = jiff::Timestamp::now();
    let result = finalize_enrollment_audit_and_device_auth(
        &state,
        &reg_state,
        &authenticator_id,
        AuthTime::for_test(now.as_second()),
        ClientInfo::default(),
    )
    .await;
    assert!(
        result.is_err(),
        "authorize_device_auth must fail and propagate when the device-auth row is missing"
    );

    // THE BUG FIX: the Enrollment audit row was written before the fallible
    // device-auth release, so it survives the failure.
    let enroll_events = audit_events_for(&state, "enrollment", &user.id).await;
    assert_eq!(
        enroll_events.len(),
        1,
        "Enrollment audit event must be recorded even when authorize_device_auth fails"
    );
    let event = enroll_events.first().expect("enrollment event");
    let data: serde_json::Value = serde_json::from_str(&event.data).expect("event data JSON");
    assert_eq!(
        data.get("authenticator_id")
            .and_then(serde_json::Value::as_str),
        Some(authenticator_id.as_str()),
        "Enrollment audit event must reference the committed authenticator"
    );
    assert_eq!(
        data.get("success").and_then(serde_json::Value::as_bool),
        Some(true),
        "Enrollment audit event must report success: the authenticator IS committed"
    );

    // The DeviceAuthApproved event must NOT be recorded — the release failed.
    let approval_events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query device_auth_approved events");
    assert!(
        approval_events.is_empty(),
        "no DeviceAuthApproved event may be recorded when authorize_device_auth fails"
    );
}

#[tokio::test]
async fn finalize_enrollment_audit_records_both_events_when_cli_release_succeeds() {
    // Happy-path CLI flow: a Pending device-auth row exists and
    // `authorize_device_auth` wins the OCC CAS. Both `Enrollment` and
    // `DeviceAuthApproved` events are recorded, and the row transitions to
    // `Authorized` carrying the enrolling authenticator. No regression on the
    // non-failing CLI branch.
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "da-ok@example.com").await;
    let authenticator_id = create_test_authenticator(&state.store, &user.id).await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().expect("valid timestamp");
    let device_auth_id = crate::db::create_device_auth_request(
        &state.store,
        "hash-da-ok",
        "DA-OK-CODE",
        None,
        expires_at,
        5,
    )
    .await
    .expect("seed pending device auth request");

    let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.email, &user.email, None)
        .expect("start_passkey_registration");
    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id,
        user_id: user_uuid,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };
    let now = jiff::Timestamp::now();
    let result = finalize_enrollment_audit_and_device_auth(
        &state,
        &reg_state,
        &authenticator_id,
        AuthTime::for_test(now.as_second()),
        ClientInfo::default(),
    )
    .await;
    assert!(result.is_ok(), "happy-path CLI release should succeed");

    let enroll_events = audit_events_for(&state, "enrollment", &user.id).await;
    assert_eq!(
        enroll_events.len(),
        1,
        "Enrollment audit event must be recorded on the happy path"
    );
    let approval_events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query device_auth_approved events");
    assert_eq!(
        approval_events.len(),
        1,
        "DeviceAuthApproved must be recorded when authorize_device_auth succeeds"
    );

    // The row transitioned to Authorized and carries the enrolling authenticator.
    let approved = crate::db::get_device_auth_by_id(&state.store, &reg_state.device_auth_id)
        .await
        .expect("read device auth")
        .expect("device auth row present");
    let approval_auth_id = match approved.state {
        crate::db::DeviceAuthState::Authorized(ref ap) => Some(ap.authenticator_id.as_str()),
        _ => None,
    };
    assert_eq!(
        approval_auth_id,
        Some(authenticator_id.as_str()),
        "device-auth row must be Authorized and reference the enrolling authenticator"
    );
}

#[tokio::test]
async fn finalize_enrollment_audit_records_only_enrollment_for_direct_browser_flow() {
    // Direct browser flow (`device_auth_id` empty): no `authorize_device_auth`
    // call is made, so `Enrollment` is recorded and `DeviceAuthApproved` is
    // not. No regression on the `is_empty()` branch.
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "direct@example.com").await;
    let authenticator_id = create_test_authenticator(&state.store, &user.id).await;

    let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.email, &user.email, None)
        .expect("start_passkey_registration");
    let now = jiff::Timestamp::now();
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id: user_uuid,
        user_email: user.email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: now.as_second() + 300,
    };
    let now = jiff::Timestamp::now();
    let result = finalize_enrollment_audit_and_device_auth(
        &state,
        &reg_state,
        &authenticator_id,
        AuthTime::for_test(now.as_second()),
        ClientInfo::default(),
    )
    .await;
    assert!(
        result.is_ok(),
        "direct browser flow has no device-auth release and must succeed"
    );

    let enroll_events = audit_events_for(&state, "enrollment", &user.id).await;
    assert_eq!(
        enroll_events.len(),
        1,
        "Enrollment audit event must be recorded for the direct browser flow"
    );
    let approval_events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["device_auth_approved".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query device_auth_approved events");
    assert!(
        approval_events.is_empty(),
        "no DeviceAuthApproved event may be recorded for the direct browser flow"
    );
}

// ── Upstream email shape validation at the enrollment chokepoint ────────
//
// `complete_enrollment_after_identity` is the single funnel both the OIDC
// and SAML callbacks feed. RFC 5322 §3.4.1 addr-spec requires a non-empty
// local part with no unquoted whitespace or angle brackets; a misconfigured
// IdP emitting a display-name-wrapped or local-part-less email claim must
// be rejected before `enroll_user_with_org` persists it as the primary
// identifier (the same `Email::is_valid_address` rule SCIM create enforces).

// RFC 5322 §3.4.1: a display-name-wrapped mailbox is not an addr-spec.
#[tokio::test]
async fn test_enrollment_rejects_display_name_wrapped_email() {
    let state = test_app_state().await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "bad-email-state-1", None).await;
    let identity = IdentityResult {
        email: "Alice Example <alice@example.com>".to_string(),
        domain: Some("example.com>".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::OK, "error page renders as 200");

    let user = crate::db::get_user_by_email(&state.store, "alice example <alice@example.com>")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "a malformed upstream email must not be persisted"
    );
}

// RFC 5322 §3.4.1: addr-spec requires a non-empty local part.
#[tokio::test]
async fn test_enrollment_rejects_empty_local_part_email() {
    let state = test_app_state().await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "bad-email-state-2", None).await;
    let identity = IdentityResult {
        email: "@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::OK, "error page renders as 200");

    let user = crate::db::get_user_by_email(&state.store, "@example.com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "an email with no local part must not be persisted"
    );
}

// RFC 5322 §3.4.1: addr-spec requires a non-empty domain. The shape check
// lets `foo@` through by design (SCIM's downstream ownership gate rejects
// it), so enrollment needs its own gate: with `allowed_domains` unset (the
// default, open-enrollment mode), nothing else rejects an empty domain
// before `enroll_user_with_org` persists it.
#[tokio::test]
async fn test_enrollment_open_mode_rejects_empty_domain_email() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None;
    state.config.store(std::sync::Arc::new(config));
    let (stored, claim) = seed_and_consume_oidc_state(&state, "bad-email-state-3", None).await;
    let identity = IdentityResult {
        email: "foo@".to_string(),
        domain: Some(String::new()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(resp.status(), StatusCode::OK, "error page renders as 200");

    let user = crate::db::get_user_by_email(&state.store, "foo@")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "an empty-domain email must not be persisted in open-enrollment mode"
    );
}

// RFC 5322 §3.4.1 / RFC 1035: a domain with internal whitespace (e.g.
// `bar .com`) is not a valid DNS domain. `Email::is_valid_address` checks
// whitespace only in the local part, so `foo@bar .com` passes the shape
// gate; and the domain is non-empty, so the empty-domain gate would likewise
// pass it. With `allowed_domains` unset (the default, open-enrollment mode),
// nothing else rejects the malformed domain before `enroll_user_with_org`
// persists it: `Email::new` only trims + ASCII-lowercases, preserving the
// internal space as `User.email = "foo@bar .com"` and a synthetic
// `Organization.domain = "bar .com"` (the chokepoint comment's
// "whitespace-bearing ... value must not be persisted verbatim" read).
// This regression test pins that the enrollment chokepoint rejects it.
#[tokio::test]
async fn test_enrollment_open_mode_rejects_whitespace_domain_email() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None; // open-enrollment mode (the default)
    state.config.store(std::sync::Arc::new(config));
    let (stored, claim) = seed_and_consume_oidc_state(&state, "ws-domain-state", None).await;
    // A non-Google IdP derives `identity.domain` from the email domain via
    // `Email::domain_of`, which keeps the internal space (`Some("bar .com")`).
    let email = "foo@bar .com".to_string();
    let domain = crate::email::Email::domain_of(&email);
    let identity = IdentityResult {
        email,
        domain,
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a whitespace-bearing domain email is rejected at the enrollment chokepoint"
    );

    // The rejection happens before `enroll_user_with_org`, so neither the
    // user nor the synthetic organization is persisted.
    let user = crate::db::get_user_by_email(&state.store, "foo@bar .com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "a whitespace-domain email must not be persisted as a user in open-enrollment mode"
    );
}

// A tab inside the domain (`foo@bar\t.com`) is whitespace too: the gate's
// `is_whitespace()` predicate must reject it, not just the ASCII space.
#[tokio::test]
async fn test_enrollment_open_mode_rejects_tab_in_domain_email() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None; // open-enrollment mode (the default)
    state.config.store(std::sync::Arc::new(config));
    let (stored, claim) = seed_and_consume_oidc_state(&state, "ws-tab-domain-state", None).await;
    let email = "foo@bar\t.com".to_string();
    let domain = crate::email::Email::domain_of(&email);
    let identity = IdentityResult {
        email,
        domain,
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a tab-bearing domain email is rejected at the enrollment chokepoint"
    );

    let user = crate::db::get_user_by_email(&state.store, "foo@bar\t.com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "a tab-domain email must not be persisted as a user in open-enrollment mode"
    );
}

// RFC 5322 §3.4.1: a well-formed addr-spec passes in open-enrollment mode
// too (the positive control pinning that the empty-domain gate does not
// over-reject when `allowed_domains` is unset).
#[tokio::test]
async fn test_enrollment_open_mode_accepts_well_formed_email() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None;
    state.config.store(std::sync::Arc::new(config));
    let user = create_test_user(&state.store, "open-ok@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "good-email-state-2", None).await;
    let identity = IdentityResult {
        email: "open-ok@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a valid email must proceed through enrollment in open-enrollment mode"
    );
}

// RFC 5322 §3.4.1: a well-formed addr-spec passes the shape gate (the
// positive control pinning that the guard does not over-reject).
#[tokio::test]
async fn test_enrollment_accepts_well_formed_email() {
    let state = test_app_state().await;
    let user = create_test_user(&state.store, "shape-ok@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "good-email-state", None).await;
    let identity = IdentityResult {
        email: "shape-ok@example.com".to_string(),
        domain: Some("example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a valid email must proceed through enrollment"
    );
}

// =========================================================================
// Regression: the domain shape gate must inspect `identity.domain` (the
// value actually persisted as `Organization.domain` / `UserDoc.org_domain`),
// not `Email::domain_of(&identity.email)`. When a SAML IdP is configured with
// `domain_attribute` (or an OIDC IdP exposes an `hd` claim), `identity.domain`
// diverges from the email's domain. A whitespace-bearing divergent
// `identity.domain` (e.g. `"bar .com"`) paired with a clean email
// (`alice@example.com`) previously slipped past a gate that read the email
// domain and was persisted verbatim — the exact verbatim persistence the
// chokepoint comment (enroll.rs:754-786) states the gate exists to prevent.
// The bug is reachable only in open-enrollment mode (`allowed_domains` unset
// / empty): the subsequent allowlist gate keys off `identity.domain` and
// rejects the mismatched value, so it scopes the defect to open-enrollment.
// =========================================================================

// Regression: a clean email paired with a divergent whitespace-bearing
// `identity.domain` (as a SAML `domain_attribute` would produce) must be
// rejected at the enrollment chokepoint in open-enrollment mode, and neither
// the user nor a synthetic organization with `domain = "bar .com"` may be
// persisted. Before the fix the gate derived the checked domain from the
// email, so the clean email kept it happy and the whitespace-bearing
// `identity.domain` was persisted verbatim as `Organization.domain`.
//
// `identity.domain` is the canonical domain for enrollment decisions (the
// allowlist gate at enroll.rs:789-808 keys off it directly); the shape gate
// now reads the same source.
#[tokio::test]
async fn test_enrollment_open_mode_rejects_whitespace_in_divergent_identity_domain() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None; // open-enrollment mode
    state.config.store(std::sync::Arc::new(config));
    let (stored, claim) =
        seed_and_consume_oidc_state(&state, "divergent-ws-domain-state", None).await;
    // A clean email (passes the shape check on its own) paired with a
    // whitespace-bearing divergent `identity.domain`, which is what
    // `complete_enrollment_after_identity` hands to `enroll_user_with_org`
    // and persists as the synthetic `Organization.domain`.
    let identity = IdentityResult {
        email: "alice@example.com".to_string(),
        domain: Some("bar .com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a whitespace-bearing divergent identity.domain is rejected at the enrollment chokepoint"
    );

    // The rejection happens before `enroll_user_with_org`, so neither the
    // user nor the synthetic organization is persisted.
    let user = crate::db::get_user_by_email(&state.store, "alice@example.com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "a whitespace-bearing divergent identity.domain must not enroll a user in open-enrollment mode"
    );
}

// Positive control (divergent happy path): a clean divergent
// `identity.domain` (as a SAML `domain_attribute` produces after
// `extract_domain`'s `to_ascii_lowercase` — see
// `domain_from_configured_attribute_is_lowercased` in
// services::idp::saml::response::tests) paired with a clean email must
// still ENROLL in open-enrollment mode, and the synthetic `Organization.domain`
// must equal the `identity.domain` value handed to `enroll_user_with_org`
// (the chokepoint persists that value verbatim via `get_or_create_org`'s
// `domain.to_string()`; the upstream IdP-parsing layers, not the chokepoint,
// are responsible for lowercasing `identity.domain` before it arrives).
//
// This pins that the fix does not over-reject the legitimate SAML
// `domain_attribute` feature: the gate inspects `identity.domain` directly
// (not through `Email::domain_of`, which would `None`-out a bare domain and
// both break this happy path and — per the convergent-domain
// `test_enrollment_open_mode_accepts_well_formed_email` — over-reject every
// convergent-domain login), so a clean bare domain still passes.
#[tokio::test]
async fn test_enrollment_open_mode_accepts_divergent_identity_domain() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None;
    state.config.store(std::sync::Arc::new(config));
    // Do NOT pre-create the user: a fresh enrollment (the normal IdP-login
    // path) creates the user linked to the synthesized org. Pre-creating
    // would leave `resolve_user` returning the existing user with its
    // pre-existing `org_id`, hiding the synthesized-org linkage this test
    // exists to pin.
    let (stored, claim) =
        seed_and_consume_oidc_state(&state, "divergent-good-domain-state", None).await;
    let identity = IdentityResult {
        email: "saml-div@example.com".to_string(),
        // A bare domain (never an email), already lowercased as SAML's
        // `extract_domain` would supply it. The gate must accept it.
        domain: Some("corp.example.com".to_string()),
        upstream: None,
    };

    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a clean divergent identity.domain must enroll in open-enrollment mode"
    );

    let enrolled = crate::db::get_user_by_email(&state.store, "saml-div@example.com")
        .await
        .expect("db query ok")
        .expect("a clean divergent identity.domain must persist a user");
    let org_id = enrolled
        .org_id
        .as_deref()
        .expect("a clean divergent identity.domain must synthesize an org");
    let org_domain = crate::db::get_organization_domain(&state.store, org_id)
        .await
        .expect("db query ok");
    assert_eq!(
        org_domain.as_deref(),
        Some("corp.example.com"),
        "the synthetic Organization.domain must equal the identity.domain value"
    );
}

// Positive control (Google consumer fallback): when `identity.domain` is
// `None` (Google consumer logins with no `hd` claim — see oidc.rs:525-529),
// the gate falls back to `Email::domain_of(&identity.email)`. A clean email
// must still enroll in open-enrollment mode (the fix must not over-reject
// the `None` fallback branch), and a whitespace-bearing email domain must
// still be rejected via the fallback (the fallback branch keeps the
// whitespace/empty check that the convergent-domain regression suite
// already pins for the `Some` branch).
#[tokio::test]
async fn test_enrollment_open_mode_none_domain_falls_back_to_email_and_gates() {
    let state = test_app_state().await;
    let mut config = test_config();
    config.allowed_domains = None;
    state.config.store(std::sync::Arc::new(config));

    // (1) Clean email, `domain: None` → proceeds (the fallback resolves a
    // non-empty, whitespace-free domain from the email).
    let user = create_test_user(&state.store, "google-consumer@example.com").await;
    create_test_authenticator(&state.store, &user.id).await;
    let (stored, claim) = seed_and_consume_oidc_state(&state, "none-domain-good-state", None).await;
    let identity = IdentityResult {
        email: "google-consumer@example.com".to_string(),
        domain: None,
        upstream: None,
    };
    let resp =
        complete_enrollment_after_identity(&state, &stored, identity, claim, ClientInfo::default())
            .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a clean email with identity.domain = None must enroll via the email-domain fallback"
    );

    // (2) Whitespace-bearing email domain, `domain: None` → the fallback
    // resolves the email's whitespace-bearing domain, and the gate rejects
    // it (the fallback branch still applies the whitespace check).
    let (stored_ws, claim_ws) =
        seed_and_consume_oidc_state(&state, "none-domain-ws-state", None).await;
    let identity_ws = IdentityResult {
        email: "foo@bar .com".to_string(),
        domain: None,
        upstream: None,
    };
    let resp = complete_enrollment_after_identity(
        &state,
        &stored_ws,
        identity_ws,
        claim_ws,
        ClientInfo::default(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a whitespace-domain email with identity.domain = None is rejected via the email-domain fallback"
    );
    let user = crate::db::get_user_by_email(&state.store, "foo@bar .com")
        .await
        .expect("db query ok");
    assert!(
        user.is_none(),
        "a whitespace-domain email with identity.domain = None must not enroll via the fallback"
    );
}
