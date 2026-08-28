// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9700 — OAuth 2.0 Security Best Current Practice tests.

use super::helpers::*;

/// Issue an authorization code for `client`, optionally bound to a PKCE
/// `code_challenge`, using the real service path so the code is stored
/// server-side and single-use enforcement applies.
async fn issue_code_for(
    state: &std::sync::Arc<crate::AppState>,
    user: &crate::db::User,
    authenticator_id: &str,
    client: &TestOAuthClient,
    code_challenge: Option<&str>,
) -> String {
    let scope_set = ScopeSet::parse("openid email");
    issue_authorization_code(
        state,
        AuthorizationCodeParams {
            client_id: &client.client_id,
            redirect_uri: "https://example.com/callback",
            user_id: &user.id,
            email: &user.email,
            authenticator_id,
            aaguid: None,
            scope: &scope_set,
            nonce: None,
            code_challenge,
            code_challenge_method: code_challenge.map(|_| CodeChallengeMethod::S256),
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            auth_code_lifetime_seconds:
                crate::services::oidc::fapi::STANDARD_AUTH_CODE_LIFETIME_SECONDS,
            authorization_details: None,
            auth_time: None,
            par: crate::db::ParConsumptionProof::not_pushed(),
        },
    )
    .await
    .expect("Failed to issue authorization code")
}

// ============================================================================
// RFC 9700 — PKCE Enforcement
// ============================================================================

#[tokio::test]
async fn test_rfc9700_pkce_required_for_public_clients() {
    // RFC 9700: Public clients (token_endpoint_auth_method=none) MUST provide PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-required@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

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
async fn test_rfc9700_pkce_optional_for_confidential_clients() {
    // Confidential clients (client_secret_basic, Web type) do not require PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-optional@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Authorize request without code_challenge — should NOT get PKCE error
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

    // Should proceed past PKCE check (gets redirect to login, not an error redirect)
    // Either 200 (login page) or 303 (redirect to login) — but NOT an error=invalid_request
    if response.status == StatusCode::SEE_OTHER {
        let location = response
            .headers
            .get("Location")
            .expect("Should have Location header")
            .to_str()
            .expect("Valid header");
        assert!(
            !location.contains("error=invalid_request"),
            "Confidential client should not get PKCE error: {}",
            location
        );
    }
}

// ============================================================================
// RFC 9700 — Token Endpoint Security
// ============================================================================

#[tokio::test]
async fn test_rfc9700_client_id_matching_at_token_endpoint() {
    // RFC 9700 Section 2.2: client_id at token endpoint must match authorization.
    // Code issued to client A cannot be exchanged by client B.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "client-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client_a = create_test_oauth_client(&state.store, &user.id).await;
    let client_b = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code_for(&state, &user, &auth_id, &client_a, None).await;

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

    let user = create_test_user(&state.store, "redirect-mismatch@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;

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

    let user = create_test_user(&state.store, "redirect-required@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;

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

// ============================================================================
// RFC 9700 — Authorization Code Security
// ============================================================================

#[tokio::test]
async fn test_rfc9700_authorization_code_single_use() {
    // RFC 9700 Section 2.1 / RFC 6749 Section 10.5:
    // Using the same authorization code twice must fail.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "single-use@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;

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
async fn test_rfc9700_authorize_pkce_required_for_public_client_without_challenge() {
    // RFC 9700: Public clients MUST provide PKCE.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "authorize-nopkce@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;
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

// ============================================================================
// RFC 9700 — Code Challenge Method Validation
// ============================================================================

#[tokio::test]
async fn test_rfc9700_pkce_plain_method_rejected() {
    // RFC 9700 Section 2.1.1: Only S256 code_challenge_method is acceptable.
    // The "plain" method MUST be rejected as it provides no security benefit.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "pkce-plain@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &code_challenge_method=plain&state=plain-test",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;

    // Should redirect with error (not succeed)
    assert!(
        response.status == StatusCode::FOUND || response.status == StatusCode::SEE_OTHER,
        "plain code_challenge_method must produce an error redirect, got: {}",
        response.status
    );

    let location = response
        .headers
        .get("Location")
        .expect("Must have Location header")
        .to_str()
        .expect("Valid UTF-8");

    assert!(
        location.contains("error="),
        "Redirect must contain error parameter for plain PKCE method: {location}"
    );
}

// ============================================================================
// RFC 9700 Section 2 — Best Practices
// ============================================================================

/// RFC 9700 §2.1.2: "clients SHOULD NOT use the implicit grant (response type
/// token) or other response types issuing access tokens in the authorization
/// response". Vouch removes the choice: `code` is the only response type it
/// advertises or accepts, so no client can reach the implicit grant.
#[tokio::test]
async fn test_rfc9700_implicit_grant_is_not_offered() {
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let response_types: Vec<&str> = discovery["response_types_supported"]
        .as_array()
        .expect("response_types_supported is an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        response_types,
        vec!["code"],
        "only the code response type may be advertised"
    );

    let user = create_test_user(&state.store, "implicit@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid\
             &state=implicit-state",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;
    let location = response
        .headers
        .get("Location")
        .expect("error redirect has a Location header")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        location.contains("error=unsupported_response_type"),
        "response_type=token must be refused: {location}"
    );
    assert!(
        !location.contains("access_token"),
        "no access token may appear in the authorization response: {location}"
    );
}

/// RFC 9700 §2.2.1: "Authorization and resource servers SHOULD use mechanisms
/// for sender-constraining access tokens, such as mutual TLS for OAuth 2.0
/// [RFC8705] or OAuth 2.0 Demonstrating Proof of Possession (DPoP) [RFC9449]".
/// RFC 9700 §4.10 repeats it as the countermeasure for stolen tokens:
/// "Authorization servers therefore SHOULD ensure that access tokens are
/// sender-constrained and audience-restricted".
///
/// Both mechanisms are implemented; this pins that both are advertised, which
/// is how a client discovers it can ask for a constrained token.
#[tokio::test]
async fn test_rfc9700_sender_constraining_mechanisms_are_advertised() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let dpop_algs = discovery["dpop_signing_alg_values_supported"]
        .as_array()
        .expect("dpop_signing_alg_values_supported is advertised");
    assert!(
        !dpop_algs.is_empty(),
        "DPoP must offer at least one signing algorithm: {discovery}"
    );

    // The mTLS mechanism is advertised too, as a boolean whose value follows
    // the deployment's mTLS configuration -- false in this test server, which
    // terminates no client certificates. Its presence is the discoverable
    // signal; DPoP is the mechanism available unconditionally.
    assert!(
        discovery["tls_client_certificate_bound_access_tokens"].is_boolean(),
        "certificate-bound access token support must be advertised: {discovery}"
    );
}

/// RFC 9700 §2.3: "The privileges associated with an access token SHOULD be
/// restricted to the minimum required for the particular application or use
/// case" and "access tokens SHOULD be audience-restricted to a specific
/// resource server". An issued token carries exactly the granted scope and an
/// `aud` naming the party it was issued for — never a wildcard.
#[tokio::test]
async fn test_rfc9700_access_token_carries_restricted_scope_and_audience() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "privilege@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (access_token, _id_token) =
        issue_oauth_access_token_with_scope(&app, &state, &user, &auth_id, &client, "openid").await;
    let claims = decode_jwt_payload(&access_token);

    assert_eq!(
        claims["scope"], "openid",
        "the token must carry only the requested scope, not every scope the \
         client could ever hold: {claims}"
    );
    assert_eq!(
        claims["aud"],
        serde_json::Value::String(client.client_id.clone()),
        "the token must be audience-restricted: {claims}"
    );
}

/// RFC 9700 §2.4: "The resource owner password credentials grant [RFC6749]
/// MUST NOT be used."
#[tokio::test]
async fn test_rfc9700_password_grant_is_not_supported() {
    let (app, state) = test_app().await;

    let (_status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let grant_types: Vec<&str> = discovery["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported is an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        !grant_types.contains(&"password"),
        "the password grant must not be advertised: {grant_types:?}"
    );

    let user = create_test_user(&state.store, "ropc@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=password&username=ropc@example.com&password=hunter2",
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "unsupported_grant_type");
}

/// RFC 9700 §2.5: "Authorization servers SHOULD enforce client authentication
/// if it is feasible" and "It is RECOMMENDED to use asymmetric cryptography
/// for client authentication, such as mutual TLS for OAuth 2.0 [RFC8705] or
/// signed JWTs ("Private Key JWT")".
#[tokio::test]
async fn test_rfc9700_client_authentication_offers_asymmetric_methods() {
    let (app, state) = test_app().await;

    let (_status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let methods: Vec<&str> = discovery["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("token_endpoint_auth_methods_supported is an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        methods.contains(&"private_key_jwt"),
        "an asymmetric client authentication method must be offered: {methods:?}"
    );

    // Enforcement: a confidential client's code is not redeemable without
    // presenting that client's credentials.
    let user = create_test_user(&state.store, "clientauth@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback&client_id={}",
            client.client_id
        ),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unauthenticated token request must be refused: {body}"
    );
}

// ============================================================================
// RFC 9700 Section 2.6 — Other Recommendations
// ============================================================================

/// RFC 9700 §2.6: "It is therefore RECOMMENDED that authorization servers
/// publish OAuth Authorization Server Metadata according to [RFC8414]".
///
/// RFC 9700 §4.7.1 turns the same document into a requirement for one field:
/// "The authorization server therefore MUST provide a way to detect their
/// support for PKCE. Using Authorization Server Metadata according to
/// [RFC8414] is RECOMMENDED". `code_challenge_methods_supported` is that
/// signal, and its presence is what lets a client rely on PKCE for CSRF
/// protection instead of `state`.
#[tokio::test]
async fn test_rfc9700_metadata_advertises_pkce_support() {
    let (app, _state) = test_app().await;

    // RFC 8414 §3: the metadata is published at the oauth-authorization-server
    // well-known URI as well as the OIDC one.
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let (status, body) = http_get(&app, path, &[]).await;
        assert_eq!(status, StatusCode::OK, "{path} must serve AS metadata");
        let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let empty = Vec::new();
        let methods: Vec<&str> = discovery["code_challenge_methods_supported"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(
            methods,
            vec!["S256"],
            "{path} must advertise PKCE support so a client can detect it"
        );
    }
}

/// RFC 9700 §2.6: "authorization servers MUST NOT allow redirection URIs that
/// use the http scheme except for native clients that use loopback interface
/// redirection as described in Section 7.3 of [RFC8252]."
#[tokio::test]
async fn test_rfc9700_http_redirect_uri_is_rejected_except_on_loopback() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        r#"{"client_name":"Cleartext","redirect_uris":["http://app.example.com/cb"]}"#,
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an http:// redirect URI on a public host must be refused: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_redirect_uri");

    // The RFC 8252 §7.3 loopback exception, and only it, is allowed through.
    for uri in [
        "http://127.0.0.1:8080/cb",
        "http://localhost:8080/cb",
        "http://[::1]:8080/cb",
    ] {
        let (status, body) = http_post_json(
            &app,
            "/oauth/register",
            &format!(r#"{{"client_name":"Loopback","redirect_uris":["{uri}"]}}"#),
            &[],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "loopback redirect URI {uri} must be accepted: {body}"
        );
    }
}

/// RFC 9700 §2.6: "However, CORS MUST NOT be supported at the authorization
/// endpoint, as the client does not access this endpoint directly; instead,
/// the client redirects the user agent to it."
///
/// The authorization endpoint is reached by top-level browser navigation,
/// which does not consult CORS, so answering a cross-origin `Origin` with
/// `Access-Control-Allow-Origin` would grant script read access for nothing in
/// return. `infra/router.rs` keeps it outside both CORS layers.
#[tokio::test]
async fn test_rfc9700_authorization_endpoint_does_not_support_cors() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cors@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[("Origin", "https://attacker.example")],
    )
    .await;
    assert!(
        response
            .headers
            .get("access-control-allow-origin")
            .is_none(),
        "the authorization endpoint must not answer a cross-origin request \
         with CORS headers: {:?}",
        response.headers
    );

    // The token endpoint is the opposite case: browser-based clients do call
    // it directly, and RFC 9700 §2.6 lists it among the endpoints that MAY
    // support CORS.
    let (_status, body) =
        http_post_form(&app, "/oauth/token", "grant_type=client_credentials", &[]).await;
    assert!(!body.is_empty(), "token endpoint still answers");
}

/// The authorization endpoint sits outside the API router so that no CORS
/// layer reaches it (see the test above). Leaving that group must not cost it
/// the no-store cache headers: an authorization response carries a code in its
/// `Location`, and the pages it renders carry session state.
#[tokio::test]
async fn test_authorization_endpoint_responses_are_not_cacheable() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "nocache@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let authorize_url = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    for path in [authorize_url.as_str(), "/oauth/logout"] {
        let response = http_get_full(&app, path, &[]).await;
        let cache_control = response
            .headers
            .get("cache-control")
            .expect("Cache-Control is set")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            cache_control.contains("no-store"),
            "{path} must not be cacheable: {cache_control}"
        );
        assert_eq!(
            response
                .headers
                .get("pragma")
                .map(|v| v.to_str().expect("Valid UTF-8")),
            Some("no-cache"),
            "{path} must set Pragma: no-cache for HTTP/1.0 caches"
        );
    }
}

/// RFC 9700 §2.6: "Under the conditions described in Section 4.15.1,
/// authorization servers SHOULD NOT allow clients to influence their client_id
/// or any other claim that could cause confusion with a genuine resource
/// owner." RFC 9700 §4.15.1 states the same countermeasure.
///
/// Registration ignores a client-supplied `client_id`; the server mints its
/// own, so a client cannot claim a user's identifier.
#[tokio::test]
async fn test_rfc9700_client_cannot_choose_its_own_client_id() {
    let (app, state) = test_app().await;

    let victim = create_test_user(&state.store, "victim@example.com").await;
    let (status, body) = http_post_json(
        &app,
        "/oauth/register",
        &format!(
            r#"{{"client_name":"Impersonator",
                 "redirect_uris":["https://attacker.example/cb"],
                 "client_id":"{id}","sub":"{id}"}}"#,
            id = victim.id
        ),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "registration should succeed: {body}"
    );
    let registered: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_ne!(
        registered["client_id"],
        serde_json::Value::String(victim.id.clone()),
        "the client must not be able to claim a resource owner's identifier: {registered}"
    );
}

/// RFC 9700 §2.6 conditions its in-browser-communication requirement on the
/// authorization response actually being sent that way: "If the authorization
/// response is sent with in-browser communication techniques like postMessage
/// [WHATWG.postmessage_api] instead of HTTP redirects, both the initiator and
/// receiver of the in-browser message MUST be strictly verified".
///
/// Vouch delivers authorization responses only by redirect or form post, so
/// the condition never holds. This pins that: `web_message` is not among the
/// response modes, and a client cannot ask for one.
#[tokio::test]
async fn test_rfc9700_authorization_response_is_never_delivered_in_browser() {
    let (app, state) = test_app().await;

    let (_status, body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    let discovery: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let modes: Vec<&str> = discovery["response_modes_supported"]
        .as_array()
        .expect("response_modes_supported is an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        !modes.iter().any(|m| m.contains("web_message")),
        "no in-browser response mode may be advertised: {modes:?}"
    );

    // No code path can select one either: the parser has no such variant, so
    // `response_mode=web_message` cannot reach a delivery branch.
    assert!(
        crate::db::ResponseMode::parse("web_message").is_none(),
        "web_message must not parse to a delivery mode"
    );

    let user = create_test_user(&state.store, "webmessage@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &response_mode=web_message&state=wm",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "the flow continues over HTTP redirects, not in-browser messaging"
    );
    assert!(
        !response.body.contains("postMessage"),
        "no in-browser delivery document may be produced: {}",
        response.body
    );
}

// ============================================================================
// RFC 9700 Section 4.1.3 — Redirection URI Validation
// ============================================================================

/// RFC 9700 §4.1.3: "This means the authorization server MUST ensure that the
/// two URIs are equal; see Section 6.2.1 of [RFC3986], Simple String
/// Comparison, for details."
///
/// Every near-miss of a registered URI is refused, and refused on the error
/// page rather than by redirecting to the near-miss.
#[tokio::test]
async fn test_rfc9700_redirect_uri_uses_simple_string_comparison() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "exactmatch@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    for uri in [
        // A registered prefix is not a match.
        "https://example.com/callback/extra",
        // Nor is the same path with a query appended.
        "https://example.com/callback?next=https://attacker.example",
        // Nor a different host that merely contains the registered one.
        "https://example.com.attacker.example/callback",
        // Nor a case variation of the path.
        "https://example.com/CALLBACK",
    ] {
        let response = http_get_full(
            &app,
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
                 &state=exact",
                client.client_id,
                urlencoding::encode(uri),
            ),
            &[],
        )
        .await;
        assert!(
            response.headers.get("Location").is_none(),
            "an unregistered redirect_uri must not be redirected to: {uri}"
        );
        assert_eq!(
            response.status,
            StatusCode::OK,
            "the mismatch must surface on the error page: {uri}"
        );
    }
}

/// RFC 9700 §4.1.3: "The only exception is native apps using a localhost URI:
/// In this case, the authorization server MUST allow variable port numbers as
/// described in Section 7.3 of [RFC8252]."
///
/// The exception is scoped to the port. A loopback URI whose path or query
/// differs from the registered one is still a mismatch.
#[tokio::test]
async fn test_rfc9700_loopback_redirect_uri_allows_a_variable_port() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "loopback@example.com").await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Native App".to_string(),
            application_type: crate::db::OAuthClientType::Native,
            redirect_uris: vec!["http://127.0.0.1:8080/callback".to_string()],
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::None),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    let authorize = |uri: &str| {
        format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &state=loopback&code_challenge={}&code_challenge_method=S256",
            client.client_id,
            urlencoding::encode(uri),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
    };

    // A different port on the same loopback host is accepted: the request gets
    // as far as the login page instead of the redirect_uri error page.
    let response = http_get_full(&app, &authorize("http://127.0.0.1:54321/callback"), &[]).await;
    let location = response
        .headers
        .get("Location")
        .expect("an accepted redirect_uri continues into the login flow")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        location.starts_with("/login"),
        "a variable port on a loopback redirect URI must be allowed: {location}"
    );

    // The exception covers the port and nothing else.
    for uri in [
        "http://127.0.0.1:8080/callback/extra",
        "http://127.0.0.1:8080/callback?x=1",
    ] {
        let response = http_get_full(&app, &authorize(uri), &[]).await;
        assert!(
            response.headers.get("Location").is_none(),
            "the loopback exception covers the port only, not {uri}"
        );
    }
}

// ============================================================================
// RFC 9700 Section 4.2.4 / 4.3.2 — Credential Leakage
// ============================================================================

/// RFC 9700 §4.2.4: "authorization codes MUST be invalidated by the
/// authorization server after their first use at the token endpoint", and
/// "when an attempt is made to redeem a code twice, the authorization server
/// SHOULD revoke all tokens issued previously based on that code."
///
/// The second half is what makes the first useful against an attacker who
/// redeems the code before the legitimate client does.
#[tokio::test]
async fn test_rfc9700_code_replay_revokes_the_tokens_it_issued() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "replay@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;

    let auth_header = client.basic_auth_header();
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https://example.com/callback"
    );

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &form,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first redemption succeeds: {body}");
    let issued: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let access_token = issued["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let bearer = format!("Bearer {access_token}");
    let (status, _body) = http_get(&app, "/oauth/userinfo", &[("Authorization", &bearer)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the issued token works before the replay"
    );

    let (status, _body) = http_post_form(
        &app,
        "/oauth/token",
        &form,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the code is invalidated after its first use"
    );

    let (status, body) = http_get(&app, "/oauth/userinfo", &[("Authorization", &bearer)]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the replay must revoke the token the first redemption issued: {body}"
    );
}

/// RFC 9700 §4.2.4: "Suppress the Referer header by applying an appropriate
/// Referrer Policy ... (either as part of the "referrer" meta attribute or by
/// setting a Referrer-Policy header)."
///
/// The policy Vouch sets never sends a path or query cross-origin, so an
/// authorization code or state value in the URL cannot leak through `Referer`
/// to a third-party site.
#[tokio::test]
async fn test_rfc9700_authorization_pages_set_a_referrer_policy() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "referrer@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;
    let policy = response
        .headers
        .get("referrer-policy")
        .expect("the authorization endpoint sets Referrer-Policy")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        matches!(
            policy,
            "no-referrer" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin"
        ),
        "the policy must not send the full URL cross-origin: {policy}"
    );
}

/// RFC 9700 §4.3.2: "Clients MUST NOT pass access tokens in a URI query
/// parameter in the way described in Section 2.3 of [RFC6750]."
///
/// Vouch closes the loop from the server side: a token offered as a query
/// parameter is not accepted at all, so a client cannot fall into the habit.
#[tokio::test]
async fn test_rfc9700_access_token_in_a_query_parameter_is_not_accepted() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "queryparam@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let (status, _body) = http_get(
        &app,
        &format!("/oauth/userinfo?access_token={access_token}"),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token in the query string must not authenticate the request"
    );

    let (status, _body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the same token works in the header");
}

// ============================================================================
// RFC 9700 Section 4.8.2 — PKCE Downgrade Attack
// ============================================================================

/// RFC 9700 §4.8.2: "Beyond this, to prevent PKCE downgrade attacks, the
/// authorization server MUST ensure that if there was no code_challenge in the
/// authorization request, a request to the token endpoint containing a
/// code_verifier is rejected."
///
/// The attack in §4.8.1 strips `code_challenge` from the authorization
/// request; the client, unaware, still sends `code_verifier` at the token
/// endpoint. Silently ignoring that verifier is what lets the injected code
/// through — so it is a hard failure.
#[tokio::test]
async fn test_rfc9700_code_verifier_without_a_bound_challenge_is_rejected() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "downgrade@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // A confidential Web client: the one shape for which Vouch does not
    // mandate PKCE, and therefore the shape this requirement is about.
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://example.com/callback\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code_verifier against a code with no bound challenge must be \
         rejected, not ignored: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant");
}

/// RFC 9700 §4.8.2: "an authorization server that supports PKCE MUST check
/// whether a code challenge is contained in the authorization request and bind
/// this information to the code that is issued".
///
/// The binding is what the rejection above rests on: a code issued *with* a
/// challenge still requires the matching verifier, and a code issued without
/// one still redeems cleanly when no verifier is sent.
#[tokio::test]
async fn test_rfc9700_challenge_presence_is_bound_to_the_code() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "binding@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_base64url(verifier);

    // Bound to a challenge: the verifier is required.
    let code = issue_code_for(&state, &user, &auth_id, &client, Some(&challenge)).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code bound to a challenge must not redeem without a verifier: {body}"
    );

    // Not bound: redeeming without a verifier is the only accepted shape.
    let code = issue_code_for(&state, &user, &auth_id, &client, None).await;
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri=https://example.com/callback"
        ),
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a code with no bound challenge redeems without a verifier: {body}"
    );
}

// ============================================================================
// RFC 9700 Section 4.9.3 / 4.11.2 / 4.15 / 4.16
// ============================================================================

/// RFC 9700 §4.9.3: "The resource server MUST treat access tokens like other
/// sensitive secrets and not store or transfer them in plaintext."
///
/// The session record that backs an access token holds only its SHA-256 hash,
/// so a database read does not yield a usable token.
#[tokio::test]
async fn test_rfc9700_access_tokens_are_not_stored_in_plaintext() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "plaintext@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    let now = jiff::Timestamp::now();
    let by_hash =
        db::get_session_by_token_hash(&state.store, &crate::crypto::hash_token(&access_token), now)
            .await
            .expect("session lookup succeeds");
    assert!(by_hash.is_some(), "the token is recorded under its hash");

    let by_plaintext = db::get_session_by_token_hash(&state.store, &access_token, now)
        .await
        .expect("session lookup succeeds");
    assert!(
        by_plaintext.is_none(),
        "the token itself must not be a stored key"
    );
}

/// RFC 9700 §4.11.2: "Section 4.1.2.1 of [RFC6749] already prevents open
/// redirects by stating that the authorization server MUST NOT automatically
/// redirect the user agent in case of an invalid combination of client_id and
/// redirect_uri", and "The authorization server SHOULD only automatically
/// redirect the user agent if it trusts the redirection URI."
#[tokio::test]
async fn test_rfc9700_invalid_client_and_redirect_uri_never_redirect() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "openredirect@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    let phish = urlencoding::encode("https://attacker.example/phish");

    // A registered client paired with an unregistered redirect_uri.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={phish}&scope=openid\
             &state=phish",
            client.client_id,
        ),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.headers.get("Location").is_none(),
        "an unregistered redirect_uri must never be used as a redirect target"
    );

    // An unknown client_id: the same, with nothing registered to compare to.
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id=not-a-client&redirect_uri={phish}\
             &scope=openid&state=phish",
        ),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.headers.get("Location").is_none(),
        "an unknown client_id must never redirect to the supplied URI"
    );
}

/// RFC 9700 §4.11.2: "Authorization servers that redirect a request that
/// potentially contains the user's credentials therefore MUST NOT use the HTTP
/// 307 status code for redirection. If an HTTP redirection ... is used for such
/// a request, the authorization server SHOULD use HTTP status code 303 (See
/// Other)."
///
/// RFC 9700 §4.12 gives the reason: "only the status code 303 unambiguously
/// enforces rewriting the HTTP POST request to an HTTP GET request. For all
/// other status codes, including the popular 302, user agents can opt not to
/// rewrite POST to GET requests, thereby causing the user's credentials to be
/// revealed to the client."
#[tokio::test]
async fn test_rfc9700_authorization_redirects_use_303_see_other() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "seeother@example.com").await;
    let client = create_test_public_oauth_client(&state.store, &user.id).await;

    // An error redirect to the registered redirect_uri (missing PKCE).
    let response = http_get_full(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid\
             &state=seeother",
            client.client_id,
            urlencoding::encode("https://example.com/callback"),
        ),
        &[],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::SEE_OTHER,
        "authorization redirects must be 303, never 307"
    );
    assert_ne!(response.status, StatusCode::TEMPORARY_REDIRECT);
}

/// RFC 9700 §4.15: an access token from the client credentials grant carries a
/// `sub` naming the client, quoting RFC 9068 — "In cases of access tokens
/// obtained through grants where no resource owner is involved, such as the
/// client credentials grant, the value of "sub" SHOULD correspond to an
/// identifier the authorization server uses to indicate the client
/// application" — while a code-grant token carries the resource owner's.
///
/// A resource server can therefore tell the two apart, which is the confusion
/// §4.15 describes.
#[tokio::test]
async fn test_rfc9700_client_credentials_sub_names_the_client_not_a_user() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "impersonate@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Machine Client".to_string(),
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &client.basic_auth_header())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials succeeds: {body}"
    );
    let issued: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let claims = decode_jwt_payload(issued["access_token"].as_str().expect("access_token"));
    assert_eq!(
        claims["sub"],
        serde_json::Value::String(client.client_id.clone()),
        "sub must name the client, not a resource owner: {claims}"
    );
    assert_ne!(
        claims["sub"],
        serde_json::Value::String(user.id.clone()),
        "sub must not collide with a user identifier: {claims}"
    );

    // The resource-owner grant puts the user in `sub`, so the two namespaces
    // stay distinguishable.
    let code_client = create_test_oauth_client(&state.store, &user.id).await;
    let (access_token, _id_token) =
        issue_oauth_access_token(&app, &state, &user, &auth_id, &code_client).await;
    let user_claims = decode_jwt_payload(&access_token);
    assert_eq!(
        user_claims["sub"],
        serde_json::Value::String(user.id.clone()),
        "the authorization code grant puts the resource owner in sub: {user_claims}"
    );
}

/// RFC 9700 §4.16: "Authorization servers MUST prevent clickjacking attacks"
/// and "In addition to those, authorization servers SHOULD also use Content
/// Security Policy (CSP) level 2 [W3C.CSP-2] or greater."
///
/// Both countermeasures are set, on the authorization endpoint and on the
/// login page it hands the user to — §4.16 asks for CSP on "other endpoints
/// used to authenticate the user and authorize the client".
///
/// The section's further SHOULD, that servers "allow administrators to
/// configure allowed origins for particular clients", is deliberately not
/// implemented: Vouch denies framing outright, which is the stricter answer to
/// the same threat and leaves no origin to configure.
#[tokio::test]
async fn test_rfc9700_authorization_pages_refuse_to_be_framed() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "clickjack@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let authorize_url = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid",
        client.client_id,
        urlencoding::encode("https://example.com/callback"),
    );

    for path in [authorize_url.as_str(), "/login"] {
        let response = http_get_full(&app, path, &[]).await;
        assert_eq!(
            response
                .headers
                .get("x-frame-options")
                .expect("X-Frame-Options is set")
                .to_str()
                .expect("Valid UTF-8"),
            "DENY",
            "{path} must refuse framing"
        );
        let csp = response
            .headers
            .get("content-security-policy")
            .expect("Content-Security-Policy is set")
            .to_str()
            .expect("Valid UTF-8");
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "{path} must restrict frame-ancestors: {csp}"
        );
        assert!(
            csp.contains("script-src 'self'"),
            "{path} must restrict script sources: {csp}"
        );
    }
}
