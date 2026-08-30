// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7515 — JSON Web Signature (JWS) header processing.
//!
//! Every JWS Vouch accepts from a client arrives at one of three endpoints:
//! a DPoP proof on the token endpoint, a Request Object at the authorization
//! endpoint, or an RFC 7523 client assertion. These tests drive all three
//! through real requests, because the JOSE header is parsed in three separate
//! places and a requirement met in one of them is not met in the others.

use super::helpers::*;

/// Build a DPoP proof with an arbitrary protected header.
///
/// `create_dpop_proof` fixes the header at `typ`/`alg`/`jwk`, which is what
/// every other DPoP test wants. These tests vary the header itself, so they
/// sign through `sign_jwt_assertion`, which takes the header verbatim.
fn dpop_proof_with_header(
    pkcs8_bytes: &[u8],
    header: &serde_json::Value,
    uri: &str,
    nonce: &str,
) -> String {
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "POST",
        "htu": uri,
        "iat": jiff::Timestamp::now().as_second(),
        "nonce": nonce,
    });
    sign_jwt_assertion(pkcs8_bytes, header, &claims)
}

/// Exchange an access token at `/oauth/token`, presenting `proof` as the DPoP
/// header. Returns the raw response so a test can assert on status and body.
async fn token_exchange_with_dpop(
    app: &axum::Router,
    client: &TestOAuthClient,
    access_token: &str,
    proof: &str,
) -> HttpResponse {
    http_post_form_full(
        app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={access_token}&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[
            ("Authorization", &client.basic_auth_header()),
            ("DPoP", proof),
        ],
    )
    .await
}

/// Redeem `code` at the token endpoint, authenticating with `assertion`
/// (RFC 7523 `private_key_jwt`).
async fn redeem_code_with_assertion(
    app: &axum::Router,
    code: &str,
    assertion: &str,
) -> (StatusCode, String) {
    http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}\
             &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
             &client_assertion={assertion}",
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await
}

/// Build an RFC 7523 client assertion with an arbitrary protected header.
fn client_assertion_with_header(
    pkcs8_bytes: &[u8],
    client_id: &str,
    audience: &str,
    header: &serde_json::Value,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    sign_jwt_assertion(
        pkcs8_bytes,
        header,
        &serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + 60,
            "jti": uuid::Uuid::now_v7().to_string(),
        }),
    )
}

/// Build a DPoP proof over a header supplied as raw JSON text.
///
/// `serde_json::json!` cannot express a duplicate member name, and the
/// duplicate is the whole point of the RFC 7515 §10.12 test, so the header is
/// written out and signed verbatim.
fn dpop_proof_with_raw_header(
    key_pair: &EcdsaKeyPair,
    header_json: &str,
    uri: &str,
    nonce: &str,
) -> String {
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": "POST",
        "htu": uri,
        "iat": jiff::Timestamp::now().as_second(),
        "nonce": nonce,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("encode claims"));
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = key_pair
        .sign(
            &aws_lc_rs::rand::SystemRandom::new(),
            signing_input.as_bytes(),
        )
        .expect("sign proof");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
}

/// Build a Request Object (RFC 9101) with an arbitrary protected header.
fn request_object_with_header(
    pkcs8_bytes: &[u8],
    client_id: &str,
    issuer: &str,
    header: &serde_json::Value,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    sign_jwt_assertion(
        pkcs8_bytes,
        header,
        &serde_json::json!({
            "iss": client_id,
            "aud": issuer,
            "exp": now + 300,
            "iat": now,
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
            "state": "rfc7515-state",
            "nonce": "rfc7515-nonce",
        }),
    )
}

/// Drive `/oauth/authorize` with a Request Object, returning the `Location`
/// header (empty when the response carries none).
async fn authorize_with_request_object(
    app: &axum::Router,
    client: &TestOAuthClient,
    session_token: &str,
    request_jwt: &str,
) -> String {
    let response = http_get_full(
        app,
        &format!(
            "/oauth/authorize?client_id={}&request={}",
            client.client_id,
            urlencoding::encode(request_jwt),
        ),
        &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
    )
    .await;

    response
        .headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// ============================================================================
// RFC 7515 §4.1.11 — the "crit" Header Parameter
//
// "If any of the listed extension Header Parameters are not understood and
// supported by the recipient, then the JWS is invalid", and "This Header
// Parameter MUST be understood and processed by implementations."
//
// Vouch implements no `crit` extension, so every name a client could list is
// one Vouch does not understand and the JWS is invalid. Before the check
// existed, the proof in the first test below was accepted at `/oauth/token`
// and a DPoP-bound access token was issued for it (issue #1094).
// ============================================================================

/// RFC 7515 §4.1.11: a DPoP proof listing an extension in `crit` is invalid,
/// and the same proof without `crit` is not — so it is the critical header
/// that is refused here, not the request around it.
#[tokio::test]
async fn test_rfc7515_crit_header_rejected_on_dpop_proof() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "crit-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (pkcs8, jwk) = generate_es256_signing_key();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse generated ES256 key");
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // The example header of RFC 7515 §4.1.11: a "crit" list naming "exp", and
    // the "exp" extension parameter it declares.
    let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;
    let critical = dpop_proof_with_header(
        &pkcs8,
        &serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
            "crit": ["exp"],
            "exp": 1_363_284_000,
        }),
        &token_uri,
        &nonce,
    );
    let response = token_exchange_with_dpop(&app, &client, &access_token, &critical).await;
    assert_ne!(
        response.status,
        StatusCode::OK,
        "RFC 7515 §4.1.11: a proof listing an unsupported crit extension is invalid: {}",
        response.body
    );

    // Control: the same flow, same key, header without `crit`, succeeds. The
    // DPoP nonce is single-use, so this leg acquires its own.
    let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;
    let plain = dpop_proof_with_header(
        &pkcs8,
        &serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk }),
        &token_uri,
        &nonce,
    );
    let response = token_exchange_with_dpop(&app, &client, &access_token, &plain).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "the same proof without crit must still be accepted: {}",
        response.body
    );
}

/// RFC 7515 §4.1.11: an empty `crit` list is refused on the same path. The
/// section forbids producing one — "Producers MUST NOT use the empty list
/// '[]' as the 'crit' value" — and Vouch refuses on the presence of the
/// member, so it never has to decide what an empty list would mean.
#[tokio::test]
async fn test_rfc7515_empty_crit_list_rejected_on_dpop_proof() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "crit-empty@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (pkcs8, jwk) = generate_es256_signing_key();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse generated ES256 key");
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;

    let proof = dpop_proof_with_header(
        &pkcs8,
        &serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
            "crit": [],
        }),
        &token_uri,
        &nonce,
    );

    let response = token_exchange_with_dpop(&app, &client, &access_token, &proof).await;
    assert_ne!(
        response.status,
        StatusCode::OK,
        "RFC 7515 §4.1.11: an empty crit list must not be accepted: {}",
        response.body
    );
}

/// RFC 7515 §4.1.11: a `crit`-bearing RFC 7523 client assertion is invalid.
///
/// The assertion is otherwise valid — correct issuer, audience, and signing
/// key — so `invalid_client` here is the critical header and nothing else.
#[tokio::test]
async fn test_rfc7515_crit_header_rejected_on_client_assertion() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "crit-assertion@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let token_endpoint = format!("{}/oauth/token", state.config().base_url);

    let critical = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1",
        "crit": ["vouch-unknown-extension"],
        "vouch-unknown-extension": "value",
    });
    let plain = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "test-key-1" });

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;
    let assertion =
        client_assertion_with_header(&pkcs8, &client.client_id, &token_endpoint, &critical);
    let (status, body) = redeem_code_with_assertion(&app, &code, &assertion).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "RFC 7515 §4.1.11: a client assertion listing an unsupported crit extension is invalid: {body}"
    );

    // Control: the same assertion without `crit` authenticates the client and
    // the grant succeeds, so the rejection above is the critical header.
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;
    let assertion =
        client_assertion_with_header(&pkcs8, &client.client_id, &token_endpoint, &plain);
    let (status, body) = redeem_code_with_assertion(&app, &code, &assertion).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same assertion without crit must authenticate: {body}"
    );
}

/// RFC 7515 §4.1.11: a `crit`-bearing Request Object is invalid.
///
/// RFC 9101 carries the request through the `request` parameter, so the JOSE
/// header reaches a third parser with its own error mapping — the client is
/// told the Request Object is at fault, not its authentication.
#[tokio::test]
async fn test_rfc7515_crit_header_rejected_on_request_object() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "crit-jar@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (pkcs8, jwk) = generate_es256_signing_key();
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Custom(serde_json::json!({ "keys": [jwk] })),
            ..Default::default()
        },
    )
    .await;
    let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    let critical = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "test-key-1",
        "crit": ["vouch-unknown-extension"],
        "vouch-unknown-extension": "value",
    });
    let plain =
        serde_json::json!({ "alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": "test-key-1" });

    let request_jwt = request_object_with_header(
        &pkcs8,
        &client.client_id,
        &state.config().base_url,
        &critical,
    );
    let location = authorize_with_request_object(&app, &client, &session_token, &request_jwt).await;
    assert!(
        !location.contains("code="),
        "RFC 7515 §4.1.11: a Request Object listing an unsupported crit extension must not \
         produce an authorization code: {location}"
    );

    // Control: the same Request Object without `crit` is accepted and does
    // produce a code, so the refusal above is the critical header.
    let request_jwt =
        request_object_with_header(&pkcs8, &client.client_id, &state.config().base_url, &plain);
    let location = authorize_with_request_object(&app, &client, &session_token, &request_jwt).await;
    assert!(
        location.contains("code="),
        "the same Request Object without crit must be accepted: {location}"
    );
}

// ============================================================================
// RFC 7515 §4.1 — Registered Header Parameter Names
// ============================================================================

/// RFC 7515 §4.1: a JWS header may carry `jku`, `x5u`, and `x5c`, each of
/// which names key material for the recipient to verify with. Vouch resolves
/// verification keys only from the JWKS registered for the client, so none of
/// the three is a key source and an assertion signed by an unregistered key is
/// refused however it advertises that key.
///
/// This is a deliberate security property, not an omission: dereferencing a
/// header-supplied `jku`/`x5u` URL would make every JWS-accepting endpoint an
/// SSRF vector, and honoring a header-supplied `x5c` would let a client bring
/// its own chain. `grep -rn 'jku\|x5u' crates/*/src` returns nothing, and the
/// only `x5c` reader is `services/oidc/mtls.rs`, which reads it from the
/// registered JWKS (RFC 7517 §4.7) and never from a JOSE header.
///
/// The requirements of §4.1 that apply to a recipient dereferencing those URLs
/// — that the retrieval use TLS and validate the server identity — are
/// therefore not obligations Vouch has; it never retrieves.
#[tokio::test]
async fn test_rfc7515_header_supplied_key_material_is_not_a_key_source() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "jku-x5u@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, registered_pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    // A key the client never registered. If any header parameter below were
    // honored, this key would verify the assertion.
    let (unregistered_pkcs8, unregistered_jwk) = generate_es256_signing_key();

    let token_endpoint = format!("{}/oauth/token", state.config().base_url);
    let cert_b64 = base64::engine::general_purpose::STANDARD
        .encode(make_test_cert_der("attacker-supplied-chain"));
    // Every way RFC 7515 §4.1 lets a producer point at its key.
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "test-key-1",
        "jku": "https://attacker.example.com/jwks.json",
        "jwk": unregistered_jwk,
        "x5u": "https://attacker.example.com/chain.pem",
        "x5c": [cert_b64],
    });

    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;
    let assertion = client_assertion_with_header(
        &unregistered_pkcs8,
        &client.client_id,
        &token_endpoint,
        &header,
    );
    let (status, body) = redeem_code_with_assertion(&app, &code, &assertion).await;

    assert_ne!(
        status,
        StatusCode::OK,
        "a key advertised by jku, jwk, x5u or x5c is not a key source; the assertion is \
         signed by a key the client never registered and must be rejected: {body}"
    );

    // Control: the identical header, signed by the key the client did
    // register, authenticates. The four parameters are inert — they neither
    // supply a key nor reject one — so the failure above is the signing key.
    let code = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec {
            scope: "openid",
            ..Default::default()
        },
    )
    .await;
    let assertion = client_assertion_with_header(
        &registered_pkcs8,
        &client.client_id,
        &token_endpoint,
        &header,
    );
    let (status, body) = redeem_code_with_assertion(&app, &code, &assertion).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the registered key must still authenticate with the same header: {body}"
    );
}

// ============================================================================
// RFC 7515 §4 and §10.12 — Header Parameter names, duplicate and unknown
//
// §10.12: "The Header Parameter names within the JOSE Header MUST be unique;
// JWS parsers MUST either reject JWSs with duplicate Header Parameter names or
// use a JSON parser that returns only the lexically last duplicate member
// name."
//
// §4: "Unless listed as a critical Header Parameter, per Section 4.1.11, all
// Header Parameters not defined by this specification MUST be ignored when not
// understood."
//
// The two together are what makes `crit` meaningful: an unrecognized parameter
// is ignored, and `crit` is how a producer says it must not be.
// ============================================================================

/// RFC 7515 §10.12: Vouch takes the first of the two options — a duplicated
/// header parameter name is rejected — and the order of the duplicates does
/// not change that.
///
/// Both parses of the header refuse it, by different routes: the DPoP header
/// pre-parse deserializes into a struct, where serde reports `duplicate field
/// 'alg'`, and `jsonwebtoken` fails on `none` as an algorithm it does not
/// know. Either ordering is refused, which is what the section requires; the
/// two orderings are tested because a rule that held in only one of them would
/// be an algorithm-confusion vulnerability rather than a conformance detail.
#[tokio::test]
async fn test_rfc7515_duplicate_header_parameter_name_is_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "dup-alg@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (pkcs8, jwk) = generate_es256_signing_key();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse generated ES256 key");
    let token_uri = format!("{}/oauth/token", state.config().base_url);
    let jwk_json = serde_json::to_string(&jwk).expect("serialize JWK");

    for header_json in [
        format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk_json},"alg":"none"}}"#),
        format!(r#"{{"typ":"dpop+jwt","alg":"none","jwk":{jwk_json},"alg":"ES256"}}"#),
    ] {
        let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;
        let proof = dpop_proof_with_raw_header(&key_pair, &header_json, &token_uri, &nonce);
        let response = token_exchange_with_dpop(&app, &client, &access_token, &proof).await;
        assert_ne!(
            response.status,
            StatusCode::OK,
            "RFC 7515 §10.12: a duplicate header parameter name must be rejected, \
             whichever value comes last — header was {header_json}: {}",
            response.body
        );
    }
}

/// RFC 7515 §4: a header parameter Vouch does not understand is ignored when
/// it is not listed in `crit`, and refused when it is. The proof is otherwise
/// identical across the two legs, so the pair isolates `crit` as the thing
/// that turns an ignorable parameter into a fatal one — which is the whole
/// function of §4.1.11.
#[tokio::test]
async fn test_rfc7515_unknown_header_parameter_ignored_unless_listed_in_crit() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "unknown-hdr@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (pkcs8, jwk) = generate_es256_signing_key();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .expect("parse generated ES256 key");
    let token_uri = format!("{}/oauth/token", state.config().base_url);

    // Not listed in `crit`: "MUST be ignored when not understood".
    let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;
    let proof = dpop_proof_with_header(
        &pkcs8,
        &serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
            "https://vouch.sh/unknown-extension": "ignored",
        }),
        &token_uri,
        &nonce,
    );
    let response = token_exchange_with_dpop(&app, &client, &access_token, &proof).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "RFC 7515 §4: an unrecognized header parameter not listed in crit must be ignored: {}",
        response.body
    );

    // The same parameter, now listed in `crit`: no longer ignorable.
    let nonce = acquire_dpop_nonce(&app, &key_pair, &jwk, "POST", &token_uri).await;
    let proof = dpop_proof_with_header(
        &pkcs8,
        &serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
            "crit": ["https://vouch.sh/unknown-extension"],
            "https://vouch.sh/unknown-extension": "not ignorable",
        }),
        &token_uri,
        &nonce,
    );
    let response = token_exchange_with_dpop(&app, &client, &access_token, &proof).await;
    assert_ne!(
        response.status,
        StatusCode::OK,
        "RFC 7515 §4.1.11: the same parameter listed in crit makes the JWS invalid: {}",
        response.body
    );
}
