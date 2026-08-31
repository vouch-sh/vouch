// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7592 — OAuth 2.0 Dynamic Client Registration Management tests.
//!
//! Tests for `PUT /oauth/register/:client_id` and `DELETE /oauth/register/:client_id`.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7592>

use super::helpers::*;

/// Register a client via POST /oauth/register, return (client_id, registration_access_token).
async fn register_dynamic_client(app: &axum::Router) -> (String, String) {
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "RFC7592 Test Client"
    });

    let (status, body) = http_post_json(app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    (client_id, token)
}

/// Register a FAPI 2.0 client (`dpop_bound_access_tokens`, the given
/// `auth_method`, and the given inline JWKS) via POST /oauth/register.
/// Returns `(client_id, registration_access_token)`.
async fn register_fapi_dynamic_client(
    app: &axum::Router,
    auth_method: &str,
    jwks: serde_json::Value,
) -> (String, String) {
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "dpop_bound_access_tokens": true,
        "token_endpoint_auth_method": auth_method,
        "jwks": jwks,
        "client_name": "RFC7592 FAPI Test Client"
    });

    let (status, body) = http_post_json(app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "FAPI registration failed: {body}"
    );

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    (client_id, token)
}

/// A valid ES256 JWK — usable with FAPI 2.0's algorithm allowlist.
fn es256_jwk() -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "use": "sig",
        "alg": "ES256"
    })
}

// =========================================================================
// FAPI 2.0 JWKS algorithm usability on PUT — RFC 7592 §2.2 is a full
// replacement, so a PUT that swaps in an RS256-only JWKS must be rejected
// exactly like initial registration. See JwkSet::has_fapi_allowed_key.
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_rejects_rs256_only_jwks_for_fapi_client() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "private_key_jwt",
        serde_json::json!({"keys": [es256_jwk()]}),
    )
    .await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {
            "keys": [{"kty": "RSA", "alg": "RS256", "n": "n", "e": "AQAB"}]
        }
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "RS256-only JWKS must be rejected on a FAPI client's PUT: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7592_put_accepts_unpinned_rsa_jwks_for_fapi_client() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "private_key_jwt",
        serde_json::json!({"keys": [es256_jwk()]}),
    )
    .await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {
            "keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]
        }
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an unpinned RSA key must pass a FAPI client's PUT: {body}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_accepts_rs256_only_jwks_for_non_fapi_client() {
    let (app, _state) = test_app().await;
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [es256_jwk()]}
    });
    let (status, reg_body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "registration failed: {reg_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&reg_body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id");
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token");

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {
            "keys": [{"kty": "RSA", "alg": "RS256", "n": "n", "e": "AQAB"}]
        }
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "RS256 must remain unrestricted for a non-FAPI client's PUT: {body}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_fapi_mtls_client_clearing_jwks() {
    // RFC 7592 §2.2 full replacement: an update that omits both jwks and
    // jwks_uri must not silently clear a FAPI client's key material, even
    // for an mTLS auth method the algorithm-usability guard doesn't apply to
    // (that guard is private_key_jwt-only; this presence check is not).
    let (app, _state) = test_app().await;
    let cert_der = make_test_cert_der("fapi-mtls-put-client");
    let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "self_signed_tls_client_auth",
        serde_json::json!({"keys": [{"kty": "RSA", "x5c": [x5c_b64]}]}),
    )
    .await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a FAPI mTLS client's PUT must not be able to clear its key material: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7592_put_accepts_jwks_uri_only_for_fapi_client() {
    // A remote jwks_uri can't be inspected synchronously, so the algorithm
    // guard only applies to an inline jwks — documented scope limit.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "private_key_jwt",
        serde_json::json!({"keys": [es256_jwk()]}),
    )
    .await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks_uri": "https://example.com/.well-known/jwks.json"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a jwks_uri-only PUT must not be blocked by the inline-only guard: {body}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_accepts_rs256_alg_pinned_x5c_jwks_for_fapi_mtls_client() {
    // RFC 8705 §2.2.2: a self_signed_tls_client_auth JWKS conveys the
    // client's certificate via x5c; alg/kty are not utilized in this
    // context. The FAPI client-assertion algorithm guard must not apply to
    // this auth method on PUT either — same carve-out as registration.
    let (app, _state) = test_app().await;
    let initial_cert = make_test_cert_der("fapi-mtls-put-initial");
    let initial_x5c = base64::engine::general_purpose::STANDARD.encode(&initial_cert);
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "self_signed_tls_client_auth",
        serde_json::json!({"keys": [{"kty": "RSA", "x5c": [initial_x5c]}]}),
    )
    .await;

    let new_cert = make_test_cert_der("fapi-mtls-put-updated");
    let new_x5c = base64::engine::general_purpose::STANDARD.encode(&new_cert);
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {
            "keys": [{"kty": "RSA", "alg": "RS256", "x5c": [new_x5c]}]
        }
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an alg-pinned RS256 x5c JWKS must pass a FAPI mTLS client's PUT: {body}"
    );
}

// =========================================================================
// RFC 8705 §2.2.2: self_signed_tls_client_auth's certificate is carried in
// the JWKS's x5c member, so a PUT that clears it must be rejected even for
// a non-FAPI client — the earlier test above only covered the FAPI case.
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_rejects_non_fapi_self_signed_client_clearing_jwks() {
    let (app, _state) = test_app().await;
    let cert_der = make_test_cert_der("non-fapi-self-signed-put-client");
    let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "jwks": {"keys": [{"kty": "RSA", "x5c": [x5c_b64]}]}
    });
    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-FAPI self_signed_tls_client_auth client's PUT must not be able to clear its \
         key material: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn test_rfc7592_put_rejects_self_signed_client_swapping_in_certificate_less_jwks() {
    // `JwkSet::has_x5c`: a PUT can replace the inline JWKS with one that still
    // satisfies the bare presence check but carries no x5c anywhere — must
    // be rejected the same as clearing it outright.
    let (app, _state) = test_app().await;
    let cert_der = make_test_cert_der("self-signed-put-swap-client");
    let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "jwks": {"keys": [{"kty": "RSA", "x5c": [x5c_b64]}]}
    });
    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {"keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]}
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a certificate-less JWKS must be rejected on PUT for self_signed_tls_client_auth: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

// =========================================================================
// JWKS write-path shape validation — a type-invalid member must be rejected
// on PUT through the same typed representation registration uses.
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_rejects_jwks_with_type_invalid_key_member() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": {"keys": [{"kty": "EC", "use": 123}]}
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a type-invalid JWK member must be rejected: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata");
}

// =========================================================================
// PUT /oauth/register/:client_id — Update Client Configuration
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_updates_redirect_uris() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://new-callback.example.com/callback"],
        "client_name": "Updated Client"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["client_id"].as_str().unwrap(), client_id);
    let uris = json["redirect_uris"]
        .as_array()
        .expect("redirect_uris array");
    assert_eq!(uris.len(), 1, "Old URI should be gone");
    assert_eq!(
        uris[0].as_str().unwrap(),
        "https://new-callback.example.com/callback"
    );
    // The PUT body includes `client_name`; it MUST be echoed back rather
    // than silently ignored (RFC 7592 §2.2 — accepted fields replace).
    assert_eq!(
        json["client_name"].as_str().unwrap(),
        "Updated Client",
        "PUT must persist the client_name it accepted"
    );
    // PUT must return a new registration_access_token (token rotation)
    let new_token = json["registration_access_token"]
        .as_str()
        .expect("PUT response must include a new registration_access_token");

    // Verify stored state via GET with the new token
    let (status, body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET after PUT failed: {body}");
    let get_json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        get_json["redirect_uris"][0].as_str().unwrap(),
        "https://new-callback.example.com/callback",
        "Stored redirect_uri should match the PUT update"
    );
}

/// Register a dynamically registered client whose `client_name` is `name`,
/// returning `(client_id, registration_access_token)`.
async fn register_named_client(app: &axum::Router, name: &str) -> (String, String) {
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": name
    });

    let (status, body) = http_post_json(app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    (client_id, token)
}

#[tokio::test]
async fn test_rfc7592_put_updates_client_name() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_named_client(&app, "Original Client Name").await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Updated Client Name"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["client_name"].as_str().unwrap(),
        "Updated Client Name",
        "PUT response must echo updated client_name"
    );

    // The rotated token must be used to read back the persisted name.
    let new_token = json["registration_access_token"]
        .as_str()
        .expect("PUT response must include a new registration_access_token")
        .to_string();

    let (status, body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET after PUT failed: {body}");
    let get_json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        get_json["client_name"].as_str().unwrap(),
        "Updated Client Name",
        "Stored client_name must match the PUT update"
    );
}

#[tokio::test]
async fn test_rfc7592_put_omitting_client_name_reverts_to_default() {
    // RFC 7592 §2.2 is a full replacement: a PUT that omits `client_name`
    // clears it. The `name` column is non-nullable, so the server reverts
    // to the registration default ("Unnamed Client"), the same fallback
    // `register_client` applies for an initial registration.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_named_client(&app, "Branded Client").await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["client_name"].as_str().unwrap(),
        "Unnamed Client",
        "Omitting client_name on a full-replacement PUT must revert to the default"
    );

    let new_token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // Read back via GET to confirm the default was persisted, not just echoed.
    let (status, body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET after PUT failed: {body}");
    let get_json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        get_json["client_name"].as_str().unwrap(),
        "Unnamed Client",
        "Persisted client_name must be the default after being omitted on PUT"
    );
}

// ========================================================================
// RFC 7592 §2.2 full replacement — every metadata field with a dedicated
// column, and the fields a PUT may not change.
// ========================================================================

/// PUT `body` to a client's configuration endpoint, returning `(status, body)`.
async fn put_client_config(
    app: &axum::Router,
    client_id: &str,
    token: &str,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    http_request(
        app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await
}

/// GET a client's configuration with `token`, returning the parsed body.
async fn get_client_config(app: &axum::Router, client_id: &str, token: &str) -> serde_json::Value {
    let (status, body) = http_request(
        app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET failed: {body}");
    serde_json::from_str(&body).expect("Valid JSON")
}

/// The rotated registration access token from a successful PUT response.
fn rotated_token(response: &serde_json::Value) -> String {
    response["registration_access_token"]
        .as_str()
        .expect("PUT response must include a new registration_access_token")
        .to_string()
}

/// Register a client carrying every metadata field with a dedicated column
/// that an RFC 7592 PUT may replace. Returns `(client_id, token)`.
async fn register_fully_specified_client(app: &axum::Router) -> (String, String) {
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Fully Specified Client",
        "software_id": "urn:example:software",
        "software_version": "1.0.0",
        "id_token_signed_response_alg": "ES256",
        "authorization_signed_response_alg": "ES256",
        "introspection_signed_response_alg": "ES256",
        "tls_client_auth_subject_dn": "CN=original.example.com",
        "tls_client_auth_san_dns": "original.example.com",
        "tls_client_auth_san_uri": "https://original.example.com/id",
        "tls_client_auth_san_ip": "198.51.100.1",
        "tls_client_auth_san_email": "original@example.com"
    });

    let (status, body) = http_post_json(app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    (client_id, token)
}

#[tokio::test]
async fn test_rfc7592_put_updates_software_id_and_version() {
    // RFC 7592 §2.2: "Valid values of client metadata fields in this request
    // MUST replace, not augment, the values previously associated with this
    // client."
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fully_specified_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "software_id": "urn:example:software-v2",
        "software_version": "2.5.1"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["software_id"].as_str(),
        Some("urn:example:software-v2"),
        "PUT response must echo the updated software_id: {json}"
    );
    assert_eq!(
        json["software_version"].as_str(),
        Some("2.5.1"),
        "PUT response must echo the updated software_version: {json}"
    );

    let stored = get_client_config(&app, &client_id, &rotated_token(&json)).await;
    assert_eq!(
        stored["software_id"].as_str(),
        Some("urn:example:software-v2"),
        "software_id must be persisted, not just echoed: {stored}"
    );
    assert_eq!(
        stored["software_version"].as_str(),
        Some("2.5.1"),
        "software_version must be persisted, not just echoed: {stored}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_omitting_software_fields_clears_them() {
    // RFC 7592 §2.2: "Omitted fields MUST be treated as null or empty values
    // by the server, indicating the client's request to delete them from the
    // client's registration."
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fully_specified_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let stored = get_client_config(&app, &client_id, &rotated_token(&json)).await;
    for field in ["software_id", "software_version"] {
        assert!(
            stored.get(field).is_none_or(serde_json::Value::is_null),
            "{field} must be cleared by a PUT that omits it, got: {stored}"
        );
    }
}

#[tokio::test]
async fn test_rfc7592_put_rejects_software_id_containing_nul() {
    // software_id is an indexed field and the store refuses a NUL byte in an
    // index value. That is a malformed metadata value, so it is reported as
    // RFC 7591 Section 3.2.2 `invalid_client_metadata`, not as a server fault.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "software_id": "urn:example:soft\u{0}ware"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a NUL byte in software_id is a client error, not a 500: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"].as_str(), Some("invalid_client_metadata"));
}

#[tokio::test]
async fn test_rfc7592_put_updates_signed_response_algs() {
    // RFC 7592 §2.2 replacement applied to the JARM Section 2.3.2 and
    // RFC 9701 Section 6.1 signing algorithms, which have dedicated columns.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "id_token_signed_response_alg": "ES256",
        "authorization_signed_response_alg": "ES256",
        "introspection_signed_response_alg": "ES256"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let stored = get_client_config(&app, &client_id, &rotated_token(&json)).await;
    for field in [
        "id_token_signed_response_alg",
        "authorization_signed_response_alg",
        "introspection_signed_response_alg",
    ] {
        assert_eq!(
            stored[field].as_str(),
            Some("ES256"),
            "{field} must be persisted by PUT: {stored}"
        );
    }
}

#[tokio::test]
async fn test_rfc7592_put_omitting_signed_response_algs_clears_them() {
    // The JARM and RFC 9701 algorithms are nullable and clear on omission.
    // `id_token_signed_response_alg` cannot: OIDC Core Section 3.1.3.7 gives it a
    // default, so an omitted field resolves to the server default (ES256
    // here, with no RSA signing key configured) rather than to null.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fully_specified_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let stored = get_client_config(&app, &client_id, &rotated_token(&json)).await;
    for field in [
        "authorization_signed_response_alg",
        "introspection_signed_response_alg",
    ] {
        assert!(
            stored.get(field).is_none_or(serde_json::Value::is_null),
            "{field} must be cleared by a PUT that omits it, got: {stored}"
        );
    }
    assert_eq!(
        stored["id_token_signed_response_alg"].as_str(),
        Some("ES256"),
        "id_token_signed_response_alg must fall back to the server default: {stored}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_omitting_id_token_alg_keeps_the_registered_one() {
    // A server with an RSA key defaults new registrations to RS256 (OIDC Core
    // Section 3.1.3.7), which every deployment has — `oidc_rsa_key` is always
    // initialized at startup. Re-deriving that default for a PUT that omits
    // the field would move a client that chose ES256 onto RS256, so an
    // omitted value keeps what the client registered instead. RFC 7592 §2.2:
    // "The authorization server MAY ignore any null or empty value in the
    // request just as any other value."
    let state = crate::test_utils::test_app_state_with_rsa_key().await;
    let config = state.config();
    let app = crate::infra::router::build_app(state.clone(), &config)
        .expect("Failed to build test app router");

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "ES256 Client",
        "id_token_signed_response_alg": "ES256"
    });
    let (status, reg_body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration failed: {reg_body}"
    );
    let reg: serde_json::Value = serde_json::from_str(&reg_body).expect("Valid JSON");
    assert_eq!(
        reg["id_token_signed_response_alg"].as_str(),
        Some("ES256"),
        "setup: the client must start on ES256, not the RS256 default: {reg}"
    );
    let client_id = reg["client_id"].as_str().expect("client_id").to_string();
    let token = rotated_token(&reg);

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback2"]
    });
    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["id_token_signed_response_alg"].as_str(),
        Some("ES256"),
        "a PUT that omits id_token_signed_response_alg must not downgrade the \
         client from ES256 to the server's RS256 default: {json}"
    );

    let stored = get_client_config(&app, &client_id, &rotated_token(&json)).await;
    assert_eq!(
        stored["id_token_signed_response_alg"].as_str(),
        Some("ES256"),
        "the registered algorithm must survive the update: {stored}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_id_token_signing_alg() {
    // RFC 7592 §2.2: "If the client attempts to set an invalid metadata field
    // and the authorization server does not set a default value, the
    // authorization server responds with an error as described in [RFC7591]."
    // PS256 parses as a JWS algorithm but is not offered for ID tokens.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "id_token_signed_response_alg": "PS256"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unsupported id_token_signed_response_alg must be rejected, not \
         accepted and dropped: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"].as_str(), Some("invalid_client_metadata"));
}

#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_introspection_signing_alg() {
    // RFC 9701 Section 6.1 responses are signed with the server's P-256 key, so
    // ES256 is the only value this server accepts.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "introspection_signed_response_alg": "RS256"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unsupported introspection_signed_response_alg must be rejected: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"].as_str(), Some("invalid_client_metadata"));
}

#[tokio::test]
async fn test_rfc7592_put_rejects_rs256_id_token_alg_for_fapi_client() {
    // FAPI 2.0 Section 5.4 forbids RS256 for a FAPI client. The profile is fixed at
    // registration, so the update path re-applies the restriction.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_fapi_dynamic_client(
        &app,
        "private_key_jwt",
        serde_json::json!({"keys": [es256_jwk()]}),
    )
    .await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "dpop_bound_access_tokens": true,
        "jwks": {"keys": [es256_jwk()]},
        "id_token_signed_response_alg": "RS256"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "RS256 must stay refused for a FAPI client on PUT: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"].as_str(), Some("invalid_client_metadata"));
}

#[tokio::test]
async fn test_rfc7592_put_updates_mtls_client_auth_fields() {
    // RFC 8705 Section 2.1.1 certificate-matching metadata. Each has a
    // dedicated column, so RFC 7592 §2.2 replacement applies to all five.
    let (app, state) = test_app().await;
    let (client_id, token) = register_fully_specified_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "tls_client_auth_subject_dn": "CN=rotated.example.com",
        "tls_client_auth_san_dns": "rotated.example.com",
        "tls_client_auth_san_uri": "https://rotated.example.com/id",
        "tls_client_auth_san_ip": "203.0.113.9",
        "tls_client_auth_san_email": "rotated@example.com"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    // These five are not echoed in the client information response, so the
    // stored record is the only place the update is observable.
    let stored = crate::db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup ok")
        .expect("client exists");
    assert_eq!(
        stored.tls_client_auth_subject_dn.as_deref(),
        Some("CN=rotated.example.com")
    );
    assert_eq!(
        stored.tls_client_auth_san_dns.as_deref(),
        Some("rotated.example.com")
    );
    assert_eq!(
        stored.tls_client_auth_san_uri.as_deref(),
        Some("https://rotated.example.com/id")
    );
    assert_eq!(
        stored.tls_client_auth_san_ip.as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(
        stored.tls_client_auth_san_email.as_deref(),
        Some("rotated@example.com")
    );
}

#[tokio::test]
async fn test_rfc7592_put_omitting_mtls_client_auth_fields_clears_them() {
    // RFC 7592 §2.2 full replacement, applied to the RFC 8705 Section 2.1.1 fields.
    let (app, state) = test_app().await;
    let (client_id, token) = register_fully_specified_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let stored = crate::db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup ok")
        .expect("client exists");
    assert_eq!(stored.tls_client_auth_subject_dn, None);
    assert_eq!(stored.tls_client_auth_san_dns, None);
    assert_eq!(stored.tls_client_auth_san_uri, None);
    assert_eq!(stored.tls_client_auth_san_ip, None);
    assert_eq!(stored.tls_client_auth_san_email, None);
}

#[tokio::test]
async fn test_rfc7592_put_accepts_restated_immutable_fields() {
    // RFC 7592 §2.2: "This request MUST include all client metadata fields as
    // returned to the client from a previous registration, read, or update
    // operation." A conforming client restates the immutable fields on every
    // update, so restating them must succeed.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
        "dpop_bound_access_tokens": false,
        "tls_client_certificate_bound_access_tokens": false
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "restating a client's registered immutable values must not be an error: {body}"
    );
}

/// Every field an RFC 7592 PUT refuses to change, with the value that differs
/// from what `register_dynamic_client` registers.
///
/// Each fixes the client's security class rather than describing it, so a PUT
/// that changes one is refused with RFC 7591 Section 3.2.2 `invalid_client_metadata`
/// instead of returning 200 for an update that did nothing.
#[tokio::test]
async fn test_rfc7592_put_rejects_changed_immutable_fields() {
    let (app, _state) = test_app().await;

    let changes = [
        ("token_endpoint_auth_method", serde_json::json!("none")),
        ("application_type", serde_json::json!("native")),
        ("dpop_bound_access_tokens", serde_json::json!(true)),
        (
            "tls_client_certificate_bound_access_tokens",
            serde_json::json!(true),
        ),
    ];

    for (field, changed) in changes {
        let (client_id, token) = register_dynamic_client(&app).await;
        let mut update_body = serde_json::json!({
            "redirect_uris": ["https://example.com/callback"]
        });
        update_body[field] = changed.clone();

        let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "changing {field} to {changed} must be refused, not silently \
             dropped behind a 200: {body}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            json["error"].as_str(),
            Some("invalid_client_metadata"),
            "changing {field} must report invalid_client_metadata: {json}"
        );
        assert!(
            json["error_description"]
                .as_str()
                .is_some_and(|d| d.contains(field)),
            "the error must name the field that was refused: {json}"
        );
    }
}

#[tokio::test]
async fn test_rfc7592_put_rejects_native_redirect_scheme_for_web_client() {
    // `application_type` is immutable, so a web client cannot declare itself
    // native to slip a private-use URI scheme past the redirect URI rules
    // (OIDC Core Section 3.1.2.1 permits the scheme for native clients only).
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["com.example.app://callback"],
        "application_type": "native"
    });

    let (status, body) = put_client_config(&app, &client_id, &token, &update_body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a web client must not register a private-use URI scheme by \
         redeclaring itself native: {body}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rotates_token() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback2"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let new_token = json["registration_access_token"]
        .as_str()
        .expect("new token")
        .to_string();

    // Old token must no longer work
    let response = http_request_full(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Old token should be rejected after rotation"
    );
    // RFC 7592 §2.1 / RFC 6750 §3.1: a rotated (now-invalid) registration
    // access token MUST return `invalid_token`, not `invalid_client`.
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Rotated token must return invalid_token: {}",
        response.body
    );

    // New token must work
    let (status, _body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "New token should work");
}

#[tokio::test]
async fn test_rfc7592_put_missing_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let response = http_request_full(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_bare_bearer_challenge(&response);
    // RFC 6750 §3.1: no error information, so no JSON error body.
    assert!(
        response.body.is_empty(),
        "Missing bearer must not carry a JSON error body: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc7592_put_invalid_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let response = http_request_full(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", "Bearer invalid_token_value"),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    // RFC 7592 §2.2 / RFC 6750 §3.1: an invalid bearer token MUST return
    // `invalid_token` (not `invalid_client`).
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Invalid bearer must return invalid_token: {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

#[tokio::test]
async fn test_rfc7592_put_nonexistent_client() {
    // RFC 7592 §2.2 + §5: a `client_id` that does not exist must be
    // indistinguishable from an invalid-token case — both return 401
    // `invalid_token`, never 404 (which would disclose client existence).
    let (app, _state) = test_app().await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let response = http_request_full(
        &app,
        "PUT",
        "/oauth/register/nonexistent-client-id",
        Some(update_body.to_string()),
        &[
            ("Authorization", "Bearer some_token"),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Non-existent client must return 401, not 404: {}",
        response.body
    );
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Non-existent client must return invalid_token: {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

// =========================================================================
// GET /oauth/register/:client_id — Read Client Configuration
// =========================================================================

#[tokio::test]
async fn test_rfc7592_get_missing_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let response = http_get_full(&app, &format!("/oauth/register/{client_id}"), &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_bare_bearer_challenge(&response);
    // RFC 6750 §3.1: no error information, so no JSON error body.
    assert!(
        response.body.is_empty(),
        "Missing bearer must not carry a JSON error body: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc7592_get_invalid_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let response = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", "Bearer invalid_token_value")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    // RFC 7592 §2.1 / RFC 6750 §3.1: an invalid bearer token MUST return
    // `invalid_token` (not `invalid_client`).
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Invalid bearer must return invalid_token: {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

// =========================================================================
// DELETE /oauth/register/:client_id — Delete Client Configuration
// =========================================================================

#[tokio::test]
async fn test_rfc7592_delete_client_succeeds() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // DELETE with valid token — expect 204
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // GET after delete — RFC 7592 §2.1/§5: the client no longer exists, so the
    // response must be 401 `invalid_token`, indistinguishable from any other
    // token-validation failure (not 404, which would disclose the deletion).
    let (status, _body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Deleted client must return 401, not 404"
    );
}

#[tokio::test]
async fn test_rfc7592_delete_client_missing_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    // DELETE without Authorization header — expect 401
    let response = http_delete_full(&app, &format!("/oauth/register/{client_id}"), &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_bare_bearer_challenge(&response);
    // RFC 6750 §3.1: no error information, so no JSON error body.
    assert!(
        response.body.is_empty(),
        "Missing bearer must not carry a JSON error body: {}",
        response.body
    );
}

#[tokio::test]
async fn test_rfc7592_delete_client_invalid_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    // DELETE with wrong token — expect 401
    let response = http_delete_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", "Bearer invalid_token_value")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    // RFC 7592 §2.3 / RFC 6750 §3.1: invalid bearer token MUST return
    // `invalid_token` (not `invalid_client`).
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Invalid bearer must return invalid_token: {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

#[tokio::test]
async fn test_rfc7592_delete_client_nonexistent() {
    // RFC 7592 §2.3 + §5: a `client_id` that does not exist must be
    // indistinguishable from an invalid-token case — both return 401
    // `invalid_token`, never 404 (which would disclose client existence).
    let (app, _state) = test_app().await;

    let response = http_delete_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer some_token")],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Non-existent client must return 401, not 404: {}",
        response.body
    );
    let json: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "Non-existent client must return invalid_token: {}",
        response.body
    );
    assert_invalid_token_challenge(&response);
}

#[tokio::test]
async fn test_rfc7592_delete_client_already_deleted() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // First delete — 204
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Second delete — RFC 7592 §2.3/§5: the client is gone, so the response
    // must be 401 `invalid_token` (indistinguishable from any other
    // token-validation failure), not 404.
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Second delete must return 401, not 404"
    );
}

// =========================================================================
// PUT /oauth/register/:client_id — userinfo_signed_response_alg + request_uris
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_sets_userinfo_signed_response_alg() {
    // RFC 7592 Section 2.2: PUT must allow setting userinfo_signed_response_alg.
    // The field must be stored and returned in the response.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "userinfo_signed_response_alg": "ES256"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["userinfo_signed_response_alg"].as_str(),
        Some("ES256"),
        "PUT response must echo userinfo_signed_response_alg: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_clears_userinfo_signed_response_alg() {
    // RFC 7592 Section 2.2: PUT is a full replacement. Omitting
    // userinfo_signed_response_alg must clear any previously set value.
    let (app, _state) = test_app().await;

    // Register with ES256 userinfo signing
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Userinfo Alg Clear Test",
        "userinfo_signed_response_alg": "ES256"
    });
    let (status, body_str) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration failed: {body_str}"
    );
    let reg_json: serde_json::Value = serde_json::from_str(&body_str).expect("Valid JSON");
    let client_id = reg_json["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let token = reg_json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // PUT without userinfo_signed_response_alg — must clear the field
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });
    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // Field must be absent or null — plain JSON response means unsigned userinfo
    assert!(
        json.get("userinfo_signed_response_alg").is_none()
            || json["userinfo_signed_response_alg"].is_null(),
        "PUT without userinfo_signed_response_alg must clear the field, got: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_sets_request_uris() {
    // RFC 7592 Section 2.2: PUT must store request_uris (OIDC Core Section 6.2 allowlist).
    // The field must be present in the response when set.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "request_uris": ["https://example.com/requests/req1.jwt"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let uris = json["request_uris"]
        .as_array()
        .expect("request_uris must be a JSON array in PUT response");
    assert_eq!(uris.len(), 1, "Must store exactly one request_uri");
    assert_eq!(
        uris[0].as_str(),
        Some("https://example.com/requests/req1.jwt"),
        "Stored request_uri must match the PUT value"
    );
}

#[tokio::test]
async fn test_rfc7592_put_clears_request_uris() {
    // RFC 7592 Section 2.2: PUT is a full replacement. Omitting request_uris
    // in a subsequent PUT must clear the allowlist (revert to "accept any").
    let (app, _state) = test_app().await;

    // Register with a request_uri allowlist
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Request URIs Clear Test",
        "request_uris": ["https://example.com/requests/req1.jwt"]
    });
    let (status, body_str) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration failed: {body_str}"
    );
    let reg_json: serde_json::Value = serde_json::from_str(&body_str).expect("Valid JSON");
    let client_id = reg_json["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let token = reg_json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // PUT without request_uris — must clear the allowlist
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });
    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // Field must be absent or null — no allowlist means any HTTPS request_uri accepted
    assert!(
        json.get("request_uris").is_none() || json["request_uris"].is_null(),
        "PUT without request_uris must clear the allowlist, got: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_non_https_request_uri() {
    // RFC 7592 Section 2.2 + OIDC Core Section 6.2: request_uris must be HTTPS.
    // An HTTP URI in request_uris must be rejected with 400.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "request_uris": ["http://evil.example.com/request.jwt"]
    });

    let (status, _body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-HTTPS request_uri in PUT must be rejected with 400"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_userinfo_signing_alg() {
    // RFC 7592 Section 2.2: Invalid userinfo_signed_response_alg must return 400.
    // Only RS256 and ES256 are accepted.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "userinfo_signed_response_alg": "HS256"
    });

    let (status, _body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid userinfo_signed_response_alg (HS256) in PUT must return 400"
    );
}

// =========================================================================
// PUT /oauth/register/:client_id — contacts and URI validation
//
// The create path (POST /oauth/register) runs validate_contacts_and_uris.
// The update path (PUT /oauth/register/:client_id) must apply the same
// rules: non-HTTPS logo_uri and non-@ contacts are rejected at update time,
// not silently stored.
// =========================================================================

/// RFC 7592 PUT with an invalid `logo_uri` (HTTP, not HTTPS) must be rejected
/// with 400 `invalid_client_metadata`, matching the create-path behaviour.
#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_logo_uri() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "logo_uri": "http://insecure.example.com/logo.png"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-HTTPS logo_uri in PUT must return 400, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "logo_uri rejection must use invalid_client_metadata: {body}"
    );
}

/// RFC 7592 PUT with a contact that lacks an `@` sign must be rejected with
/// 400 `invalid_client_metadata`, matching the create-path behaviour.
#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_contact() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "contacts": ["not-an-email-address"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Contact without @ in PUT must return 400, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "contact rejection must use invalid_client_metadata: {body}"
    );
}

/// RFC 7592 PUT with a valid `logo_uri` (HTTPS) must succeed.
/// Confirms the validation is not over-restrictive.
#[tokio::test]
async fn test_rfc7592_put_accepts_valid_logo_uri() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "logo_uri": "https://example.com/logo.png"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Valid HTTPS logo_uri in PUT must succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["logo_uri"].as_str(),
        Some("https://example.com/logo.png"),
        "logo_uri must be echoed back in PUT response"
    );
}

/// RFC 7592 PUT with valid contacts must succeed.
#[tokio::test]
async fn test_rfc7592_put_accepts_valid_contacts() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "contacts": ["admin@example.com"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Valid contact in PUT must succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let contacts = json["contacts"].as_array().expect("contacts must be array");
    assert_eq!(contacts.len(), 1, "PUT response must echo the contact list");
    assert_eq!(contacts[0].as_str(), Some("admin@example.com"));
}

// ========================================================================
// RP-Initiated Logout 1.0 — post_logout_redirect_uris management
// ========================================================================

#[tokio::test]
async fn test_rfc7592_put_post_logout_redirect_uris_roundtrip() {
    // PUT must accept post_logout_redirect_uris and echo them in the response.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "post_logout_redirect_uris": ["https://example.com/logged-out"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PUT with post_logout_redirect_uris must succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let post_logout = json["post_logout_redirect_uris"]
        .as_array()
        .expect("post_logout_redirect_uris must be echoed in PUT response");
    assert_eq!(
        post_logout.len(),
        1,
        "Expected 1 post_logout_redirect_uri, got {post_logout:?}"
    );
    assert_eq!(
        post_logout[0].as_str().unwrap(),
        "https://example.com/logged-out"
    );
}

#[tokio::test]
async fn test_rfc7592_put_post_logout_redirect_uris_clears_on_omit() {
    // A PUT without post_logout_redirect_uris must clear the field (full-replacement semantics).
    // Note: RFC 7592 §3 says PUT may rotate registration_access_token. We read the new
    // token from the first PUT response and use it for the second PUT.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // First PUT: set post_logout_redirect_uris; read back the (possibly rotated) token.
    let set_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "post_logout_redirect_uris": ["https://example.com/logged-out"]
    });
    let (status, first_resp) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(set_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "First PUT must succeed: {first_resp}"
    );

    // Extract the possibly-rotated token from the response.
    let first_json: serde_json::Value =
        serde_json::from_str(&first_resp).expect("Valid JSON from first PUT");
    let token2 = first_json["registration_access_token"]
        .as_str()
        .unwrap_or(&token)
        .to_string();

    // Second PUT: omit post_logout_redirect_uris → field should be cleared.
    let clear_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });
    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(clear_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token2}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Second PUT must succeed: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let post_logout = json.get("post_logout_redirect_uris");
    // Field should be absent or null/empty after full-replacement without it.
    assert!(
        post_logout.is_none()
            || post_logout.is_some_and(|v| v.is_null() || v == &serde_json::json!([])),
        "post_logout_redirect_uris must be cleared when omitted from PUT: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_post_logout_redirect_uris_invalid_rejected() {
    // PUT with an invalid post_logout_redirect_uri must be rejected with 400.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "post_logout_redirect_uris": ["ftp://not-allowed.example.com/"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid post_logout_redirect_uri must be rejected: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // RFC 7591/7592: registration management errors use `invalid_client_metadata`.
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "Error code must be invalid_client_metadata: {json}"
    );
}

/// PUT is a full replacement, so omitting `jwks`/`jwks_uri` clears them.
/// For a `private_key_jwt` client that would leave it unable to
/// authenticate, so the auth-method/JWKS consistency rule from initial
/// registration must also be enforced on update (#719).
#[tokio::test]
async fn test_rfc7592_put_cannot_clear_jwks_for_private_key_jwt_client() {
    let (app, _state) = test_app().await;

    let jwks = serde_json::json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig",
            "alg": "ES256"
        }]
    });
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": jwks,
        "client_name": "PKJ App"
    });
    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // PUT without jwks/jwks_uri must be rejected, not clear the keys.
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "PKJ App v2"
    });
    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PUT clearing JWKS for a private_key_jwt client must fail: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["error"], "invalid_client_metadata", "{json}");

    // PUT that keeps a JWKS still succeeds (with the original token — the
    // rejected PUT must not have rotated it).
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "jwks": serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "use": "sig",
                "alg": "ES256"
            }]
        }),
        "client_name": "PKJ App v2"
    });
    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PUT keeping JWKS must succeed: {body}"
    );
}

// =========================================================================
// RFC 7592 §2.1/2.2/2.3 + §5 — uniform 401 across all token-validation
// failures (no information disclosure).
//
// A `client_id` is a public identifier, so the configuration endpoints must
// not let a caller distinguish between:
//   (a) a `client_id` that does not exist,
//   (b) a dynamically-registered client presented with the wrong bearer token,
//   (c) an admin-created client (no registration access token), and
//   (d) a deprovisioned (inactive) client, even presented with the right token.
// Every case returns the same 401 `invalid_token` response with the same
// `error_description`; the only diagnostics live in the server log.
// =========================================================================

/// Assert the response is the canonical, uniform RFC 7592 §5 rejection:
/// 401, `error="invalid_token"`, `error_description="Invalid registration
/// access token"`, no `error_uri`, and a matching `WWW-Authenticate` challenge.
///
/// Asserting the *full* `error_description` (not just `error`) is what locks
/// the differing-message leak in place — the old "Client has no registration
/// access token" string disclosed that a client was admin-created.
fn assert_uniform_invalid_token_401(label: &str, status: StatusCode, body: &str, www_auth: &str) {
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{label}: must be 401, not 404 or any other status (body: {body})"
    );
    let json: serde_json::Value = serde_json::from_str(body).expect("body must be valid JSON");
    assert_eq!(
        json["error"], "invalid_token",
        "{label}: error must be invalid_token: {body}"
    );
    assert_eq!(
        json["error_description"], "Invalid registration access token",
        "{label}: error_description must be the uniform string — differing messages leak client \
         type: {body}"
    );
    assert!(
        json.get("error_uri").is_none(),
        "{label}: no error_uri expected: {body}"
    );
    assert!(
        www_auth.contains("error=\"invalid_token\""),
        "{label}: WWW-Authenticate must carry error=\"invalid_token\": {www_auth}"
    );
    assert!(
        www_auth.contains("error_description=\"Invalid registration access token\""),
        "{label}: WWW-Authenticate must mirror the uniform error_description: {www_auth}"
    );
}

/// Create an admin-created client (no registration access token) and return
/// its public `client_id` for probing the configuration endpoints.
async fn make_admin_client(state: &crate::AppState) -> String {
    let user = create_test_user(&state.store, "rfc7592-admin@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    client.client_id
}

#[tokio::test]
async fn test_rfc7592_get_nonexistent_client() {
    // RFC 7592 §2.1 + §5: GET for a `client_id` that does not exist must
    // return 401 `invalid_token`, not 404.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer some_token")],
    )
    .await;
    assert_uniform_invalid_token_401(
        "GET nonexistent",
        response.status,
        &response.body,
        www_authenticate(&response),
    );
}

#[tokio::test]
async fn test_rfc7592_admin_created_client_rejected_uniformly() {
    // RFC 7592 §5: an admin-created client has no registration access token,
    // so every configuration request must fail with the *same* 401
    // `invalid_token` response as any other invalid token — and must NOT carry
    // the old "Client has no registration access token" message that disclosed
    // the client's admin-created type. Probe all three endpoints.
    let (app, state) = test_app().await;
    let client_id = make_admin_client(&state).await;

    // GET
    let response = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", "Bearer any_token")],
    )
    .await;
    assert_uniform_invalid_token_401(
        "GET admin-created",
        response.status,
        &response.body,
        www_authenticate(&response),
    );

    // PUT — well-formed body so the JSON extractor succeeds and we reach auth.
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });
    let response = http_request_full(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", "Bearer any_token"),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_uniform_invalid_token_401(
        "PUT admin-created",
        response.status,
        &response.body,
        www_authenticate(&response),
    );

    // DELETE
    let response = http_delete_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", "Bearer any_token")],
    )
    .await;
    assert_uniform_invalid_token_401(
        "DELETE admin-created",
        response.status,
        &response.body,
        www_authenticate(&response),
    );
}

#[tokio::test]
async fn test_rfc7592_inactive_client_rejected_uniformly() {
    // RFC 7592 §2.1/2.2/2.3 + §5: a deprovisioned (inactive) client must be
    // indistinguishable from any other token-validation failure — even when
    // the caller presents the *correct* registration access token. The old
    // behaviour (404 for inactive clients) disclosed that the client once
    // existed.
    let (app, state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // Look up the internal doc id and deactivate the client.
    let stored = db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("client lookup must succeed")
        .expect("registered client must exist");
    db::set_oauth_client_active(&state.store, &stored.id, false)
        .await
        .expect("deactivate client");

    // GET with the correct token — must be 401 invalid_token, not 404.
    let response = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "GET inactive (correct token)",
        response.status,
        &response.body,
        www_authenticate(&response),
    );

    // PUT with the correct token — must be 401 invalid_token, not 404.
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });
    let response = http_request_full(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_uniform_invalid_token_401(
        "PUT inactive (correct token)",
        response.status,
        &response.body,
        www_authenticate(&response),
    );

    // DELETE with the correct token — must be 401 invalid_token, not 404.
    let response = http_delete_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "DELETE inactive (correct token)",
        response.status,
        &response.body,
        www_authenticate(&response),
    );
}

#[tokio::test]
async fn test_rfc7592_failures_indistinguishable_across_client_types() {
    // RFC 7592 §5: the four token-validation failure classes must be
    // byte-for-byte indistinguishable on the wire. Probe GET in each class and
    // assert the status, body, and WWW-Authenticate challenge are all
    // identical — no message, header, or status difference an attacker could
    // use as a distinguisher.
    let (app, state) = test_app().await;

    // (a) Non-existent client_id.
    let a = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer some_token")],
    )
    .await;

    // (b) Existing dynamically-registered client with the wrong bearer token.
    let (dyn_client_id, _dyn_token) = register_dynamic_client(&app).await;
    let b = http_get_full(
        &app,
        &format!("/oauth/register/{dyn_client_id}"),
        &[("Authorization", "Bearer the_wrong_token")],
    )
    .await;

    // (c) Admin-created client (no registration access token hash).
    let admin_client_id = make_admin_client(&state).await;
    let c = http_get_full(
        &app,
        &format!("/oauth/register/{admin_client_id}"),
        &[("Authorization", "Bearer some_token")],
    )
    .await;

    // (d) Inactive dynamically-registered client presented with its (now
    // rejected) correct token.
    let (inactive_client_id, inactive_token) = register_dynamic_client(&app).await;
    let stored = db::get_oauth_client_by_client_id(&state.store, &inactive_client_id)
        .await
        .expect("client lookup must succeed")
        .expect("registered client must exist");
    db::set_oauth_client_active(&state.store, &stored.id, false)
        .await
        .expect("deactivate client");
    let d = http_get_full(
        &app,
        &format!("/oauth/register/{inactive_client_id}"),
        &[("Authorization", &format!("Bearer {inactive_token}"))],
    )
    .await;

    // All four must be valid, uniform 401 invalid_token responses...
    assert_uniform_invalid_token_401("non-existent", a.status, &a.body, www_authenticate(&a));
    assert_uniform_invalid_token_401("wrong-token", b.status, &b.body, www_authenticate(&b));
    assert_uniform_invalid_token_401("admin-created", c.status, &c.body, www_authenticate(&c));
    assert_uniform_invalid_token_401("inactive", d.status, &d.body, www_authenticate(&d));

    // ...and byte-for-byte identical to one another.
    assert_eq!(
        a.status, b.status,
        "status must be uniform across failure types"
    );
    assert_eq!(
        a.status, c.status,
        "status must be uniform across failure types"
    );
    assert_eq!(
        a.status, d.status,
        "status must be uniform across failure types"
    );
    assert_eq!(a.body, b.body, "body must be uniform across failure types");
    assert_eq!(a.body, c.body, "body must be uniform across failure types");
    assert_eq!(a.body, d.body, "body must be uniform across failure types");
    assert_eq!(
        www_authenticate(&a),
        www_authenticate(&b),
        "WWW-Authenticate must be uniform across failure types"
    );
    assert_eq!(
        www_authenticate(&a),
        www_authenticate(&c),
        "WWW-Authenticate must be uniform across failure types"
    );
    assert_eq!(
        www_authenticate(&a),
        www_authenticate(&d),
        "WWW-Authenticate must be uniform across failure types"
    );
}

// =========================================================================
// RFC 7592 §2.1/2.2/2.3 — revoke a registration access token presented
// against a client_id that does not exist.
//
// §2.1 (identically §2.2, and §2.3 with "if possible"):
//   "If the client does not exist on this server, the server MUST respond
//    with HTTP 401 Unauthorized and the registration access token used to
//    make this request SHOULD be immediately revoked."
// =========================================================================

#[tokio::test]
async fn test_rfc7592_misdirected_token_is_revoked() {
    // RFC 7592 §2.1: a live registration access token presented against a
    // client_id that does not exist is revoked, so it can no longer manage the
    // client it actually belongs to.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // The token works for its own client before the misdirected request.
    let before = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        before.status,
        StatusCode::OK,
        "token must work for its own client first: {}",
        before.body
    );

    // Present that same token against a client_id that does not exist.
    let misdirected = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "misdirected live token",
        misdirected.status,
        &misdirected.body,
        www_authenticate(&misdirected),
    );

    // The token is now revoked for its real client too.
    let after = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "token after revocation",
        after.status,
        &after.body,
        www_authenticate(&after),
    );
}

#[tokio::test]
async fn test_rfc7592_revocation_does_not_disturb_other_clients() {
    // Revocation is keyed on the presented token's hash, so it must clear
    // exactly one client's token and leave every other registration alone.
    let (app, _state) = test_app().await;
    let (victim_id, victim_token) = register_dynamic_client(&app).await;
    let (bystander_id, bystander_token) = register_dynamic_client(&app).await;

    let misdirected = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", &format!("Bearer {victim_token}"))],
    )
    .await;
    assert_eq!(misdirected.status, StatusCode::UNAUTHORIZED);

    let victim = http_get_full(
        &app,
        &format!("/oauth/register/{victim_id}"),
        &[("Authorization", &format!("Bearer {victim_token}"))],
    )
    .await;
    assert_eq!(
        victim.status,
        StatusCode::UNAUTHORIZED,
        "the presented token must be the one revoked: {}",
        victim.body
    );

    let bystander = http_get_full(
        &app,
        &format!("/oauth/register/{bystander_id}"),
        &[("Authorization", &format!("Bearer {bystander_token}"))],
    )
    .await;
    assert_eq!(
        bystander.status,
        StatusCode::OK,
        "an unrelated client's token must survive: {}",
        bystander.body
    );
}

#[tokio::test]
async fn test_rfc7592_unknown_token_against_unknown_client_still_401() {
    // The common case: a token that matches no client at all. Revocation finds
    // nothing to clear and the response is the same uniform 401 as every other
    // failure — the revocation SHOULD must not become a distinguisher.
    let (app, _state) = test_app().await;

    let response = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer vouch_reg_not_a_real_token")],
    )
    .await;
    assert_uniform_invalid_token_401(
        "unknown token, unknown client",
        response.status,
        &response.body,
        www_authenticate(&response),
    );
}

#[tokio::test]
async fn test_rfc7592_wrong_token_for_existing_client_is_not_revoked() {
    // The revocation SHOULD is scoped to the "client does not exist" branch.
    // A live token presented against a *real* client that it does not own is
    // rejected, but must not be revoked — §2.1 attaches revocation only to the
    // non-existent-client case, and revoking here would let any caller who
    // learns two client_ids disable a token by pointing it at the wrong one.
    let (app, _state) = test_app().await;
    let (own_id, own_token) = register_dynamic_client(&app).await;
    let (other_id, _other_token) = register_dynamic_client(&app).await;

    let crossed = http_get_full(
        &app,
        &format!("/oauth/register/{other_id}"),
        &[("Authorization", &format!("Bearer {own_token}"))],
    )
    .await;
    assert_eq!(crossed.status, StatusCode::UNAUTHORIZED);

    let still_valid = http_get_full(
        &app,
        &format!("/oauth/register/{own_id}"),
        &[("Authorization", &format!("Bearer {own_token}"))],
    )
    .await;
    assert_eq!(
        still_valid.status,
        StatusCode::OK,
        "a token pointed at another existing client must not be revoked: {}",
        still_valid.body
    );
}

// =========================================================================
// RFC 7592 §5 — Security Considerations for the registration access token.
// =========================================================================

#[tokio::test]
async fn test_rfc7592_registration_access_token_has_sufficient_entropy() {
    // RFC 7592 §5: "Since possession of the registration access token
    // authorizes the holder to potentially read, modify, or delete a client's
    // registration (including its credentials such as a client_secret), the
    // registration access token MUST contain sufficient entropy to prevent a
    // random guessing attack of this token, such as described in Section 5.2
    // of [RFC6750] and Section 5.1.4.2.2 of [RFC6819]."
    //
    // The OAuth 2.0 core specification supplies the numeric floor those
    // sections point at: "The probability of an attacker guessing generated
    // tokens (and other credentials not intended for handling by end-users)
    // MUST be less than or equal to 2^(-128) and SHOULD be less than or equal
    // to 2^(-160)." Only the registration access token is asserted here, so
    // this test claims no coverage of that broader requirement.
    use base64::Engine as _;

    let (app, _state) = test_app().await;

    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        let (_client_id, token) = register_dynamic_client(&app).await;

        let random_part = token
            .strip_prefix("vouch_reg_")
            .expect("registration access token must carry the vouch_reg_ prefix");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(random_part)
            .expect("the random part must be base64url");

        assert!(
            decoded.len() >= 20,
            "token entropy is {} bits, below the 160-bit floor OAuth 2.0 recommends",
            decoded.len().saturating_mul(8)
        );
        assert!(
            seen.insert(token.clone()),
            "registration access tokens must never repeat: {token}"
        );
    }
}

#[tokio::test]
async fn test_rfc7592_registration_access_token_does_not_expire_while_registered() {
    // RFC 7592 §5: "While the client secret can expire, the registration access
    // token SHOULD NOT expire while a client is still actively registered. If
    // this token were to expire, a developer or client could be left in a
    // situation where they have no means of retrieving, updating, or deleting
    // the client's registration information."
    //
    // Vouch stores only the token's hash, with no expiry alongside it, so the
    // token stays usable for the life of the registration. Two observable
    // consequences pin that: the registration response advertises no expiry for
    // the token, and the token keeps authenticating across repeated use.
    let (app, _state) = test_app().await;

    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "RFC7592 Token Lifetime Client"
    });
    let (status, body) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // RFC 7591 §3.2.1 defines `client_secret_expires_at` for the secret. There
    // is no counterpart for the registration access token, and inventing one
    // would be the expiry §5 warns against.
    for member in [
        "registration_access_token_expires_at",
        "registration_access_token_expires_in",
    ] {
        assert!(
            json.get(member).is_none(),
            "the registration access token must carry no expiry, found {member}: {json}"
        );
    }

    // Repeated use keeps working, and each PUT-rotated token is itself durable.
    for round in 0..3 {
        let response = http_get_full(
            &app,
            &format!("/oauth/register/{client_id}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "round {round}: the registration access token must not expire while the client is \
             actively registered: {}",
            response.body
        );
    }
}

// =========================================================================
// RFC 7592 §2.1 — end-to-end (full axum router) regression for the
// misdirected-token revoke vs. concurrent PUT rotation race.
//
// `db::revoke_registration_access_token` resolves the owner of a presented
// token by hash, then clears the stored hash inside `store.modify`. The OCC
// loop re-reads the latest document on every attempt, so a client that
// concurrently rotates its registration access token via a PUT can land a
// fresh hash between the revoke's read and its compare-and-update. With the
// pre-fix unconditional clear, the retry wiped the rotated token — locking
// the legitimate owner out of all RFC 7592 operations until an admin
// reissued a token. The fix conditions the clear on the stored hash still
// equaling the presented hash, making a rotate-then-racing-revoke a no-op.
//
// This test drives the race through the real HTTP handler path
// (`GET /oauth/register/<nonexistent>` → `lookup_and_verify_registration_token`
// → `revoke_token_for_unknown_client` → `revoke_registration_access_token`),
// using `test_app_with_modify_hook` to rotate the victim's token inside the
// revoke's OCC window deterministically. It is the HTTP-layer analogue of
// `db::tests::occ_modify::test_revoke_registration_access_token_does_not_clobber_concurrently_rotated_token`.
// =========================================================================

#[tokio::test]
async fn test_rfc7592_misdirected_revoke_does_not_lock_out_concurrent_rotation_e2e() {
    use std::sync::{Arc, Mutex};

    // The victim rotates from T_old (the token the server mints at registration,
    // captured by the attacker) to T_new (chosen by the test, known only to the
    // legitimate owner after the PUT returns it).
    let t_new = "vouch_reg_NEW_TOKEN_rotated_e2e".to_string();
    let new_hash = crate::crypto::hash_token(&t_new);
    let redirect_uris = vec!["https://example.com/callback".to_string()];

    // The victim's internal doc id is only known after registration, which
    // runs after the app (and hook) are built. The hook gates on this slot so
    // it only fires for the victim doc, and only while the slot is set.
    let slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slot_for_hook = Arc::clone(&slot);
    let new_hash_for_hook = new_hash.clone();
    let redirect_uris_for_hook = redirect_uris.clone();
    let (app, state) = test_app_with_modify_hook(move |store| {
        // Hookless writer clone for the in-hook rotation: must not re-enter
        // the hook when it writes through the store.
        let writer = store.clone();
        let new_hash = new_hash_for_hook.clone();
        let redirect_uris = redirect_uris_for_hook.clone();
        let slot = Arc::clone(&slot_for_hook);
        store.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
            let writer = writer.clone();
            let new_hash = new_hash.clone();
            let redirect_uris = redirect_uris.clone();
            let slot = Arc::clone(&slot);
            let doc_id = doc_id.to_string();
            Box::pin(async move {
                if attempt != 0 {
                    return;
                }
                // Only rotate the victim doc, and only once the slot is set.
                let victim = slot.lock().expect("slot lock").clone();
                if victim.as_deref() != Some(doc_id.as_str()) {
                    return;
                }
                // Run the victim's RFC 7592 PUT (rotating to T_new) inside the
                // attacker's revoke `modify`'s first attempt — after it read
                // the pre-rotation doc but before its compare-and-update. The
                // PUT commits version V+1 (hash T_new), so the revoke's first
                // CAS loses the version race and the modify loop retries
                // against the freshly rotated document.
                crate::db::update_oauth_client_registration(
                    &writer,
                    &doc_id,
                    &crate::db::UpdateClientRegistrationParams {
                        redirect_uris: &redirect_uris,
                        grant_types: None,
                        response_types: None,
                        keys: None,
                        registration_access_token_hash: &new_hash,
                        registration_metadata: None,
                        userinfo_signed_response_alg: None,
                        request_uris: None,
                        post_logout_redirect_uris: None,
                    },
                )
                .await
                .expect("hook rotation must succeed");
            })
        }));
    })
    .await;

    // Register the victim dynamically; the server mints T_old, which the
    // attacker has captured.
    let (client_id, t_old) = register_dynamic_client(&app).await;

    // Resolve the victim's internal doc id and arm the hook slot.
    let victim = db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup")
        .expect("client must exist");
    let victim_id = victim.id.clone();
    *slot.lock().expect("slot lock") = Some(victim_id.clone());

    // The attacker replays the leaked T_old against a non-existent client_id;
    // the misdirected-token path revokes whichever client holds hash(T_old),
    // racing the victim's concurrent rotation. The 401 is uniform regardless.
    let misdirected = http_get_full(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", &format!("Bearer {t_old}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "misdirected live token (e2e race)",
        misdirected.status,
        &misdirected.body,
        www_authenticate(&misdirected),
    );

    // The owner must NOT be locked out: the rotated T_new — which only the
    // legitimate owner holds — must still authenticate against the real
    // client.
    let after = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {t_new}"))],
    )
    .await;
    assert_eq!(
        after.status,
        StatusCode::OK,
        "the concurrently rotated T_new must not be wiped by the racing revoke; \
         otherwise the legitimate owner is locked out of all RFC 7592 operations: {}",
        after.body,
    );

    // Rotation still neutralises the leaked T_old: it must now fail with the
    // uniform 401 `invalid_token`.
    let old_after = http_get_full(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {t_old}"))],
    )
    .await;
    assert_uniform_invalid_token_401(
        "old token after rotation (e2e race)",
        old_after.status,
        &old_after.body,
        www_authenticate(&old_after),
    );

    // The stored hash must reflect the rotated token, not None.
    let stored = db::get_oauth_client_by_client_id(&state.store, &client_id)
        .await
        .expect("lookup after")
        .expect("client must still exist");
    assert_eq!(
        stored.registration_access_token_hash.as_deref(),
        Some(new_hash.as_str()),
        "the stored registration_access_token_hash must be hash(T_new), not None"
    );
}
