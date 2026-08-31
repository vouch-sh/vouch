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
    let (app, _state) = test_app().await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, _body) = http_request(
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
    assert_eq!(status, StatusCode::NOT_FOUND);
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

    // GET after delete — expect 404
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
        StatusCode::NOT_FOUND,
        "Deleted client should return 404"
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
    let (app, _state) = test_app().await;

    // DELETE for a client_id that doesn't exist — expect 404
    let (status, _body) = http_delete(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer some_token")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

    // Second delete — 404 (idempotent)
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Second delete should return 404"
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
