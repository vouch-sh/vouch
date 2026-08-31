// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8705 Section 3 — mTLS certificate-bound access tokens.

use super::helpers::*;

// ========================================================================
// RFC 8705 Section 3 — mTLS Token Binding Tests
// ========================================================================

/// RFC 8705 Section 3: A certificate-bound token MUST be rejected when no
/// client certificate is presented.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_without_cert_returns_401() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-no-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-a");
    let thumbprint = cert_thumbprint(&cert_der);

    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // No client certificate — should be rejected.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        None, // no cert
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"].as_str(),
        Some("invalid_token"),
        "Must return invalid_token when cert-bound token presented without cert"
    );
}

/// RFC 8705 Section 3: A certificate-bound token MUST be rejected when the
/// presented client certificate does not match the bound thumbprint.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_with_wrong_cert_returns_401() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-wrong-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Token is bound to cert A's thumbprint.
    let cert_a_der = make_test_cert_der("client-a");
    let thumbprint_a = cert_thumbprint(&cert_a_der);
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint_a),
            ..Default::default()
        },
    )
    .await;

    // Present cert B — a different certificate.
    let cert_b_der = make_test_cert_der("client-b");
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_b_der),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"].as_str(),
        Some("invalid_token"),
        "Must return invalid_token when presented cert thumbprint does not match token binding"
    );
}

/// RFC 8705 Section 3: A certificate-bound token MUST be accepted when the
/// presented client certificate matches the bound thumbprint.
#[tokio::test]
async fn test_userinfo_mtls_bound_token_with_matching_cert_succeeds() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-match");
    let thumbprint = cert_thumbprint(&cert_der);

    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // Present the correct certificate.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Matching cert should allow access: {body}"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        userinfo["email"].as_str(),
        Some("mtls-match@example.com"),
        "UserInfo must include the correct email"
    );
}

/// Tokens without `cnf.x5t#S256` must work without a client certificate.
#[tokio::test]
async fn test_userinfo_non_mtls_token_works_without_cert() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-none@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Plain token — no cert binding.
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

    // No client certificate — should succeed because token is not cert-bound.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Non-cert-bound token must work without cert: {body}"
    );
    let userinfo: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(userinfo["email"].as_str(), Some("mtls-none@example.com"));
}

// ========================================================================
// RFC 8705 Section 3 — Token Structure Validation
// ========================================================================

/// RFC 8705 Section 3: The cnf claim in an mTLS-bound token must contain
/// x5t#S256 matching the bound certificate's SHA-256 thumbprint.
#[tokio::test]
async fn test_rfc8705_cnf_claim_present_in_mtls_bound_token() {
    let (_app, state) = test_app().await;

    let user = create_test_user(&state.store, "mtls-cnf@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("client-cnf");
    let thumbprint = cert_thumbprint(&cert_der);

    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // Decode the JWT and inspect the cnf claim
    let claims = decode_jwt_payload(&token);

    let cnf = claims
        .get("cnf")
        .expect("RFC 8705: mTLS-bound token must contain cnf claim");

    let x5t = cnf
        .get("x5t#S256")
        .expect("RFC 8705: cnf must contain x5t#S256")
        .as_str()
        .expect("x5t#S256 must be a string");

    assert_eq!(
        x5t,
        thumbprint.as_str(),
        "RFC 8705: x5t#S256 in cnf must match the certificate thumbprint"
    );
}

// ========================================================================
// RFC 8705 — Token Endpoint Coverage
//
// Tests in this section cover the conformance suite scenarios for
// `POST /oauth/token` with mTLS client authentication (RFC 8705 §2.1),
// mTLS certificate-bound access tokens (RFC 8705 §3), combinations
// with DPoP (RFC 9449), and combinations with private_key_jwt (RFC 7523).
// See vouch-conformance TOKEN_TEST_HANDOFF.md scenarios 7–17.
// ========================================================================

/// Create an OAuth client authenticated via mTLS (RFC 8705 §2.1, PKI-based)
/// and bound to issue cert-bound access tokens (RFC 8705 §3).
async fn create_mtls_client_with_cert_binding(
    store: &db::store::DocumentStore,
    user_id: &str,
    subject_dn: &str,
    fapi_profile: db::FapiProfile,
    dpop_bound_access_tokens: bool,
) -> String {
    create_test_client(
        store,
        user_id,
        TestClientSpec {
            name: "Test mTLS Token Client".to_string(),
            token_endpoint_auth_method: Some(db::TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some(subject_dn.to_string()),
            tls_client_certificate_bound_access_tokens: true,
            with_secret: false,
            fapi_profile: Some(fapi_profile),
            dpop_bound_access_tokens,
            ..Default::default()
        },
    )
    .await
    .client_id
}

/// RFC 8705 §2.1 + §3: mTLS-authenticated client exchanges authorization code
/// at `/oauth/token`, presenting a matching client certificate, and receives
/// a cert-bound (`cnf.x5t#S256`) Bearer access token.
#[tokio::test]
async fn test_rfc8705_token_mtls_authorization_code_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-token-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-token-ok");
    let parsed = crate::services::oidc::mtls::parse_client_certificate(&cert_der)
        .expect("parse generated cert");
    let subject_dn = parsed.subject_dn.expect("generated cert has subject DN");
    let thumbprint = cert_thumbprint(&cert_der);

    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn,
        db::FapiProfile::None,
        false,
    )
    .await;

    let code = issue_code(&state, &user, &auth_id, &client_id, TestCodeSpec::default()).await;
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "mTLS client with matching cert must receive 200: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["token_type"].as_str(), Some("Bearer"));

    let access_token = json["access_token"].as_str().expect("access_token present");
    let claims = decode_jwt_payload(access_token);
    let x5t = claims["cnf"]["x5t#S256"]
        .as_str()
        .expect("cnf.x5t#S256 must be present in mTLS-bound token");
    assert_eq!(x5t, thumbprint.as_str());
}

/// RFC 8705 §2.1: An already-consumed authorization code must be rejected
/// with `invalid_grant` even when client authentication via mTLS succeeds.
#[tokio::test]
async fn test_rfc8705_token_mtls_invalid_grant_when_code_already_used() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-token-reuse@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-token-reuse");
    let parsed = crate::services::oidc::mtls::parse_client_certificate(&cert_der)
        .expect("parse generated cert");
    let subject_dn = parsed.subject_dn.expect("subject DN");
    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn,
        db::FapiProfile::None,
        false,
    )
    .await;

    let code = issue_code(&state, &user, &auth_id, &client_id, TestCodeSpec::default()).await;
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );

    // First exchange — consumes the code.
    let (status1, _b1) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der.clone())).await;
    assert_eq!(status1, StatusCode::OK);

    // Second exchange with the same code — must fail.
    let (status2, response_body2) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "Code reuse must return 400: {response_body2}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body2).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_grant");
}

/// RFC 8705 §2.1: When the client registers a subject DN for `tls_client_auth`
/// but the presented certificate's subject DN does not match, the token
/// endpoint must reject with `invalid_client`.
#[tokio::test]
async fn test_rfc8705_token_mtls_invalid_client_when_cert_mismatch() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-token-wrong-cert@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Client is registered against cert A's subject DN.
    let cert_a_der = make_test_cert_der("registered");
    let parsed_a =
        crate::services::oidc::mtls::parse_client_certificate(&cert_a_der).expect("parse cert A");
    let subject_dn_a = parsed_a.subject_dn.expect("cert A has subject DN");
    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn_a,
        db::FapiProfile::None,
        false,
    )
    .await;

    let code = issue_code(&state, &user, &auth_id, &client_id, TestCodeSpec::default()).await;

    // Caller presents cert B — different subject DN.
    let cert_b_der = make_test_cert_der("imposter");

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );
    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_b_der)).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Cert subject mismatch must return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}

/// RFC 9449 §5: When the client has `dpop_bound_access_tokens=true` but the
/// token request omits the DPoP proof, the token endpoint must reject with
/// `invalid_request` even if the client successfully authenticates via mTLS.
#[tokio::test]
async fn test_rfc8705_token_mtls_invalid_request_when_dpop_required_but_missing() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-token-needs-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-needs-dpop");
    let parsed =
        crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");
    let subject_dn = parsed.subject_dn.expect("subject DN");
    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn,
        db::FapiProfile::Fapi2Security,
        true,
    )
    .await;

    let code = issue_code(&state, &user, &auth_id, &client_id, TestCodeSpec::default()).await;
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP-required client without proof must return 400: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_request");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("DPoP"),
        "error_description must reference DPoP: {response_body}"
    );
}

/// RFC 8705 §3 + RFC 9449 §5: mTLS-authenticated client with DPoP-bound and
/// cert-bound tokens exchanges code with a matching cert + DPoP proof + nonce.
/// Returns a DPoP-token-type access token with `cnf.jkt` (and may include
/// `cnf.x5t#S256`).
#[tokio::test]
async fn test_rfc8705_token_mtls_plus_dpop_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-dpop-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-dpop-ok");
    let parsed =
        crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");
    let subject_dn = parsed.subject_dn.expect("subject DN");
    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn,
        db::FapiProfile::Fapi2Security,
        true,
    )
    .await;

    let (dpop_key, dpop_jwk) = generate_dpop_key_pair();
    let jkt = dpop_jkt(&dpop_jwk);
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &dpop_key, &dpop_jwk, "POST", &token_uri).await;
    let proof = create_dpop_proof(&dpop_key, &dpop_jwk, "POST", &token_uri, Some(&nonce), None);

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client_id,
        TestCodeSpec {
            dpop_jkt: Some(&jkt),
            ..Default::default()
        },
    )
    .await;
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) = http_post_form_with_cert(
        &app,
        "/oauth/token",
        &body,
        &[("DPoP", &proof)],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "mTLS + DPoP exchange must succeed: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["token_type"].as_str(), Some("DPoP"));

    let access_token = json["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(jkt.as_str()),
        "cnf.jkt must match DPoP proof key thumbprint"
    );
}

/// RFC 9449 §10.1: When the authorization code was bound to a `dpop_jkt`
/// but the token request presents a DPoP proof signed with a different key,
/// the token endpoint must reject with `invalid_grant`.
#[tokio::test]
async fn test_rfc8705_token_mtls_plus_dpop_invalid_grant_when_jkt_mismatch() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-dpop-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-dpop-mismatch");
    let parsed =
        crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");
    let subject_dn = parsed.subject_dn.expect("subject DN");
    let client_id = create_mtls_client_with_cert_binding(
        &state.store,
        &user.id,
        &subject_dn,
        db::FapiProfile::Fapi2Security,
        true,
    )
    .await;

    // Authorization bound to key A.
    let (_key_a, jwk_a) = generate_dpop_key_pair();
    let jkt_a = dpop_jkt(&jwk_a);
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client_id,
        TestCodeSpec {
            dpop_jkt: Some(&jkt_a),
            ..Default::default()
        },
    )
    .await;

    // Token request signs with a different key B.
    let (key_b, jwk_b) = generate_dpop_key_pair();
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &key_b, &jwk_b, "POST", &token_uri).await;
    let proof_b = create_dpop_proof(&key_b, &jwk_b, "POST", &token_uri, Some(&nonce), None);

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}",
        urlencoding::encode("https://example.com/callback"),
    );

    let (status, response_body) = http_post_form_with_cert(
        &app,
        "/oauth/token",
        &body,
        &[("DPoP", &proof_b)],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP jkt mismatch must return 400: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_grant");
}

/// Create an OAuth client authenticated via `private_key_jwt` whose access
/// tokens are additionally bound to the client's mTLS certificate (RFC 8705 §3).
async fn create_private_key_jwt_client_with_cert_binding(
    store: &db::store::DocumentStore,
    user_id: &str,
) -> (TestOAuthClient, Vec<u8>) {
    let (client, pkcs8_bytes) = create_test_jwt_client(store, user_id).await;
    let oauth = db::get_oauth_client_by_client_id(store, &client.client_id)
        .await
        .expect("DB error")
        .expect("client");
    store
        .modify::<crate::db::documents::oauth::OAuthClientDoc, _>(&oauth.id, |data| {
            data.tls_client_certificate_bound_access_tokens = true;
        })
        .await
        .expect("enable cert binding");
    (client, pkcs8_bytes)
}

/// RFC 8705 §3 + RFC 7523: `private_key_jwt` client authenticates with a JWT
/// assertion at `/oauth/token` while also presenting a client certificate.
/// Result: `cnf.x5t#S256` bound to the certificate, token_type Bearer.
#[tokio::test]
async fn test_rfc8705_token_mtls_plus_private_key_jwt_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-mtls-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let (client, pkcs8_bytes) =
        create_private_key_jwt_client_with_cert_binding(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("pkjwt-mtls-ok");
    let thumbprint = cert_thumbprint(&cert_der);

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_id={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
        urlencoding::encode("https://example.com/callback"),
        client.client_id,
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "private_key_jwt + mTLS cert binding must succeed: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["token_type"].as_str(), Some("Bearer"));

    let access_token = json["access_token"].as_str().expect("access_token");
    let claims = decode_jwt_payload(access_token);
    assert_eq!(
        claims["cnf"]["x5t#S256"].as_str(),
        Some(thumbprint.as_str()),
        "cnf.x5t#S256 must match cert thumbprint"
    );
}

/// RFC 7523 §3: When `private_key_jwt` is the configured auth method and the
/// client_assertion is malformed or signed with the wrong key, the token
/// endpoint must return `invalid_client` even if mTLS is also present.
#[tokio::test]
async fn test_rfc8705_token_mtls_plus_private_key_jwt_invalid_client_when_jwt_bad() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-mtls-badjwt@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let (client, _pkcs8_bytes) =
        create_private_key_jwt_client_with_cert_binding(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("pkjwt-mtls-badjwt");
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

    // Sign the assertion with a wrong key.
    let (wrong_pkcs8, _wrong_jwk) = generate_es256_signing_key();
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let bad_assertion =
        build_client_assertion(&client.client_id, &token_endpoint, &wrong_pkcs8, None);

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_id={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={bad_assertion}",
        urlencoding::encode("https://example.com/callback"),
        client.client_id,
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Bad client_assertion must return 401: {response_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client");
}

/// RFC 8705 §3 + RFC 9449 §7.1: When a token is cert-bound (`cnf.x5t#S256`)
/// but the caller uses the `Authorization: DPoP <token>` scheme without
/// supplying a `DPoP` proof header, the userinfo endpoint must reject with
/// `400 invalid_dpop_proof` "DPoP scheme requires DPoP proof header".
#[tokio::test]
async fn test_rfc8705_userinfo_mtls_bound_token_with_dpop_scheme_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-token-dpop-scheme@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-token-dpop-scheme");
    let thumbprint = cert_thumbprint(&cert_der);
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // DPoP authorization scheme but no DPoP header.
    let (status, body) = http_get_with_cert(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("DPoP {token}"))],
        Some(cert_der),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "DPoP scheme without proof must return 400: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_dpop_proof");
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("DPoP scheme requires DPoP proof header"),
        "error_description must mention DPoP proof requirement: {body}"
    );
}

/// One response, one binding. A certificate-bound client used to receive
/// `cnf.x5t#S256` in its access token and no `cnf` at all in the ID token
/// issued beside it, because the ID token's confirmation was built from the
/// DPoP proof alone. Both tokens now carry the binding the client actually
/// proved.
///
/// RFC 8705 §3.1 defines `x5t#S256` for certificate-bound tokens; RFC 7800
/// §3.1 permits `cnf` in any JWT ("The 'cnf' claim is used in the JWT to
/// contain members used to identify the proof-of-possession key"). Neither
/// requires it on an ID token — binding the token that goes to the party that
/// proved the key is this server's rule, and this test is what keeps the two
/// token kinds from drifting apart again.
#[tokio::test]
async fn test_rfc8705_id_token_carries_the_same_binding_as_the_access_token() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-id-token-cnf@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    let (client, pkcs8_bytes) =
        create_private_key_jwt_client_with_cert_binding(&state.store, &user.id).await;

    let cert_der = make_test_cert_der("mtls-id-token-cnf");
    let thumbprint = cert_thumbprint(&cert_der);

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let assertion = build_client_assertion(&client.client_id, &token_endpoint, &pkcs8_bytes, None);

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &client_id={}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}",
        urlencoding::encode("https://example.com/callback"),
        client.client_id,
    );

    let (status, response_body) =
        http_post_form_with_cert(&app, "/oauth/token", &body, &[], Some(cert_der)).await;
    assert_eq!(status, StatusCode::OK, "{response_body}");

    let json: serde_json::Value = serde_json::from_str(&response_body).expect("Valid JSON");
    let access_claims = decode_jwt_payload(json["access_token"].as_str().expect("access_token"));
    let id_claims = decode_jwt_payload(json["id_token"].as_str().expect("id_token"));

    assert_eq!(
        access_claims["cnf"]["x5t#S256"].as_str(),
        Some(thumbprint.as_str()),
        "the access token must be certificate-bound"
    );
    assert_eq!(
        id_claims["cnf"]["x5t#S256"].as_str(),
        Some(thumbprint.as_str()),
        "the ID token must carry the same confirmation as the access token"
    );
    assert!(
        id_claims["cnf"]["jkt"].is_null(),
        "no DPoP proof was presented, so there is no jkt to confirm"
    );
}
