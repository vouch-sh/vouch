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
// exactly like initial registration. See db::jwks_has_fapi_allowed_key.
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
    // `jwks_has_x5c`: a PUT can replace the inline JWKS with one that still
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
