// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 assertion grant flow tests.
//!
//! Tests cover the challenge endpoint and the token endpoint error paths for the
//! `urn:ietf:params:oauth:grant-type:fido2-assertion` grant type. Full happy-path
//! assertion verification requires a physical YubiKey and has no automated
//! coverage; it is exercised by running `vouch login` against a real device.

use super::helpers::*;
use crate::db::documents::user::UserDoc;
use crate::db::{self, TokenEndpointAuthMethod};
use vouch_common::encoding::Raw;
use vouch_common::fido2_types::Challenge;

// ========================================================================
// Challenge endpoint — POST /oauth/fido2/challenge
// ========================================================================

#[tokio::test]
async fn test_fido2_challenge_endpoint_exists() {
    // The challenge endpoint must return 200 with a JSON body containing
    // "challenge", "rp_id", and "state" fields when authenticated.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-exists@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let (status, body) = post_challenge(&app, &client.client_id, &pkcs8).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Challenge endpoint must return 200: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Response must be JSON");
    assert!(
        response["challenge"].is_string(),
        "Response must contain 'challenge' string field"
    );
    assert!(
        response["rp_id"].is_string(),
        "Response must contain 'rp_id' string field"
    );
    assert!(
        response["state"].is_string(),
        "Response must contain 'state' JWT field"
    );
}

#[tokio::test]
async fn test_fido2_challenge_response_has_no_cache_headers() {
    // Challenge responses must not be cached — they contain one-time-use material.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-cache@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );
    let body = format!(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}"
    );

    let resp = http_post_form_full(&app, "/oauth/fido2/challenge", &body, &[]).await;

    assert_eq!(resp.status, StatusCode::OK);
    let cache_control = resp
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache_control.contains("no-store"),
        "Challenge response must have Cache-Control: no-store, got: {cache_control}"
    );
}

#[tokio::test]
async fn test_fido2_challenge_state_is_valid_jwt() {
    // The state field must be a three-part dot-separated JWT string.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-jwt@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let (status, body) = post_challenge(&app, &client.client_id, &pkcs8).await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let state_jwt = response["state"].as_str().expect("state must be a string");

    let parts: Vec<&str> = state_jwt.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "State must be a three-part JWT, got: {state_jwt}"
    );
}

// ========================================================================
// Token endpoint — FIDO2 assertion grant error paths
// ========================================================================

#[tokio::test]
async fn test_fido2_token_missing_assertion_rejected() {
    // The assertion parameter is REQUIRED per the grant spec.
    // A request with grant_type but no assertion must return invalid_request.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion",
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Missing assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_request",
        "Missing assertion must return invalid_request, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_missing_client_auth_rejected() {
    // The FIDO2 grant requires private_key_jwt client authentication, so a
    // request carrying an assertion but no client credentials is
    // `invalid_client`. RFC 6749 Section 5.2 permits 401 for that code, and
    // `OAuthErrorCode::status_code` is what decides it.
    let (app, _state) = test_app().await;

    let garbage_assertion = URL_SAFE_NO_PAD.encode(b"not-a-real-assertion");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={garbage_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Missing client auth must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Missing client auth must return invalid_client, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_assertion_encoding_rejected() {
    // An assertion that is not valid base64url must return invalid_grant.
    // We submit a properly-authenticated client but a garbage assertion value.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-b64@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // "!not-base64url!" is not valid base64url
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion=%21not-base64url%21\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid base64 in assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid base64 assertion must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_assertion_json_rejected() {
    // An assertion that decodes from base64url but is not valid JSON must
    // return invalid_grant (not a server error).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-json@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // Valid base64url but not JSON
    let garbage_assertion = URL_SAFE_NO_PAD.encode(b"this-is-not-json{{{");

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={garbage_assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-JSON assertion must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Non-JSON assertion must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_state_jwt_rejected() {
    // A well-formed assertion JSON with a tampered/invalid state JWT must
    // return invalid_grant (state JWT verification fails).
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "fido2-bad-state@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    // Build a structurally valid assertion payload but with a tampered state JWT.
    // The state JWT signature is wrong so the server must reject it.
    let tampered_state = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
        .eyJjaGFsbGVuZ2UiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJwX2lkIjoidGFtcGVyZWQiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0\
        .tampered_signature_invalid";

    let assertion_payload = serde_json::json!({
        "state": tampered_state,
        "credential_id": URL_SAFE_NO_PAD.encode(b"fake-credential-id"),
        "authenticator_data": URL_SAFE_NO_PAD.encode(b"fake-auth-data"),
        "signature": URL_SAFE_NO_PAD.encode(b"fake-signature"),
        "client_data_json": URL_SAFE_NO_PAD.encode(b"fake-client-data"),
        "user_handle": URL_SAFE_NO_PAD.encode(b"fake-user-handle")
    });

    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Tampered state JWT must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Tampered state JWT must return invalid_grant, got: {}",
        error["error"]
    );
}

// ========================================================================
// Negative: Individual field encoding validation
// ========================================================================

/// Helper: build a `private_key_jwt`-authenticated form body for
/// `POST /oauth/fido2/challenge`. The challenge endpoint now requires
/// client authentication, so a valid `client_assertion` is needed to obtain
/// a state JWT at all.
async fn post_challenge(app: &axum::Router, client_id: &str, pkcs8: &[u8]) -> (StatusCode, String) {
    let client_assertion = build_client_assertion(
        client_id,
        "https://test.example.com/oauth/token",
        pkcs8,
        None,
    );
    let body = format!(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}"
    );
    http_post_form(app, "/oauth/fido2/challenge", &body, &[]).await
}

/// Helper: get a real state JWT from the challenge endpoint, authenticated
/// as `client_id` so the state is bound to the same client that redeems it.
async fn get_real_state_jwt(app: &axum::Router, client_id: &str, pkcs8: &[u8]) -> String {
    let (status, body) = post_challenge(app, client_id, pkcs8).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Challenge endpoint must return 200: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    response["state"]
        .as_str()
        .expect("state must be a string")
        .to_string()
}

/// Helper: post a FIDO2 assertion grant carrying `credential_id` and
/// `user_handle`, with every other field a well-formed placeholder. Returns the challenge state JWT the
/// assertion referenced, so a caller can check whether it was consumed.
async fn post_assertion_with_credential_id(
    app: &axum::Router,
    state: &std::sync::Arc<crate::AppState>,
    email: &str,
    credential_id: &str,
    user_handle: uuid::Uuid,
) -> (String, StatusCode, String) {
    let user = create_test_user(&state.store, email).await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(app, &client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": credential_id,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": URL_SAFE_NO_PAD.encode(user_handle.as_bytes()),
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    (state_jwt, status, body)
}

/// Assert the challenge state is still unconsumed by spending it directly.
async fn assert_challenge_unspent(state: &crate::AppState, state_jwt: &str) {
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .expect("expiry in range");
    let consume = db::consume_challenge_state_for_test(&state.store, state_jwt, expires_at).await;
    assert!(
        consume.is_ok(),
        "a rejected assertion consumed the challenge state: {consume:?}"
    );
}

#[tokio::test]
async fn test_fido2_token_short_credential_id_leaves_challenge_unconsumed() {
    // A credential ID below the 16-byte floor must be rejected while the
    // challenge state is still unconsumed, so the CLI can retry the assertion
    // without a fresh challenge round-trip.
    let (app, state) = test_app().await;
    let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
    let (state_jwt, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-short-cred@example.com",
        &short,
        uuid::Uuid::now_v7(),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Short credential_id must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Short credential_id must return invalid_grant, got: {}",
        error["error"]
    );

    assert_challenge_unspent(&state, &state_jwt).await;
}

#[tokio::test]
async fn test_fido2_token_oversized_credential_id_leaves_challenge_unconsumed() {
    // The 1023-byte ceiling is the other half of the same bound.
    let (app, state) = test_app().await;
    let oversized = URL_SAFE_NO_PAD.encode(vec![
        0u8;
        <vouch_common::CredentialIdData as vouch_common::Bounds>::MAX_BYTES
            + 1
    ]);
    let (state_jwt, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-long-cred@example.com",
        &oversized,
        uuid::Uuid::now_v7(),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Oversized credential_id must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Oversized credential_id must return invalid_grant, got: {}",
        error["error"]
    );

    assert_challenge_unspent(&state, &state_jwt).await;
}

// RFC 6749 §5.2: `invalid_grant` means "The provided authorization grant ...
// is invalid", so it fits an unknown credential. A storage fault says nothing
// about the grant and must stay a server error.
#[tokio::test]
async fn test_fido2_token_unknown_credential_is_invalid_grant() {
    let (app, state) = test_app().await;
    let unknown = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let (_, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-unknown-cred@example.com",
        &unknown,
        uuid::Uuid::now_v7(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "{body}");
}

#[tokio::test]
async fn test_fido2_token_authenticator_storage_fault_is_server_error() {
    let (app, state) = test_app().await;
    let owner = create_test_user(&state.store, "fido2-storage-fault@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &owner.id).await;
    let authenticator = db::get_authenticator_by_id(&state.store, &auth_id)
        .await
        .expect("load authenticator")
        .expect("authenticator exists");
    corrupt_document(&state.store, &owner.id).await;
    assert!(
        db::get_authenticator_with_user_by_credential_id(
            &state.store,
            &authenticator.credential_id
        )
        .await
        .is_err(),
        "the lookup must fail at the storage layer"
    );

    let (_, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-storage-fault-client@example.com",
        &URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        uuid::Uuid::now_v7(),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "server_error", "{body}");

    // A storage fault is not a login failure, so it leaves no row at all.
    let rows = login_failed_rows(&state, None).await;
    assert!(rows.is_empty(), "no login_failed row for a 5xx: {rows:?}");
}

/// Register an authenticator for `owner_id` and return its base64url
/// credential ID.
async fn owner_credential_id(state: &crate::AppState, owner_id: &str) -> String {
    let auth_id = create_test_authenticator(&state.store, owner_id).await;
    let authenticator = db::get_authenticator_by_id(&state.store, &auth_id)
        .await
        .expect("load authenticator")
        .expect("authenticator exists");
    URL_SAFE_NO_PAD.encode(&authenticator.credential_id)
}

/// Every `login_failed` audit row, filtered to an email domain when given.
async fn login_failed_rows(
    state: &crate::AppState,
    email_domains: Option<Vec<String>>,
) -> Vec<db::AuditEvent> {
    state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["login_failed".to_string()]),
            email_domains,
            ..db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
}

fn payload(row: &db::AuditEvent) -> serde_json::Value {
    serde_json::from_str(&row.data).expect("event data JSON")
}

fn failure_reason(row: &db::AuditEvent) -> String {
    payload(row)["failure_reason"]
        .as_str()
        .expect("failure_reason is a string")
        .to_string()
}

/// Assert `row` names no user: a NULL `user_id` column (what per-user
/// temporal policies such as `failed_login_burst` count) and no `user_id`
/// payload key, with the request's `user_handle` kept as `asserted_user_id`.
fn assert_unattributed(row: &db::AuditEvent, asserted: &str) {
    assert_eq!(row.user_id, None, "row must not be attributed: {row:?}");
    let data = payload(row);
    assert!(data.get("user_id").is_none(), "{data}");
    assert_eq!(data["asserted_user_id"].as_str(), Some(asserted), "{data}");
}

#[tokio::test]
async fn test_fido2_token_deactivated_owner_is_audited_in_org_feed() {
    // The CLI grant records the same refusal row as browser login. The row
    // carries the owner's domain, so an org-scoped query finds it, but no
    // signature has been checked, so it is not attributed to the owner.
    let (app, state) = test_app().await;
    let owner = create_test_user(&state.store, "fido2-deactivated@example.com").await;
    let credential_id = owner_credential_id(&state, &owner.id).await;
    state
        .store
        .modify::<UserDoc, _>(&owner.id, |d| d.active = false)
        .await
        .expect("deactivate user");

    let owner_uuid = uuid::Uuid::parse_str(&owner.id).expect("user id is a uuid");
    let (_, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-deactivated-client@example.com",
        &credential_id,
        owner_uuid,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "{body}");

    let rows = login_failed_rows(&state, Some(vec!["example.com".to_string()])).await;
    assert_eq!(rows.len(), 1, "one org-visible login_failed row: {rows:?}");
    let row = rows.first().expect("one row");
    assert_eq!(failure_reason(row), "user_deactivated");
    assert_eq!(row.email_domain.as_deref(), Some("example.com"));
    assert_unattributed(row, &owner.id);
}

#[tokio::test]
async fn test_fido2_token_owner_mismatch_is_audited_without_principal() {
    // The asserted `user_handle` is not the credential's owner, and no
    // signature has been checked. A credential ID is not a secret, so
    // presenting one proves nothing about its owner either: the row names
    // neither account, carries no email, and records which credential was
    // presented.
    let (app, state) = test_app().await;
    let owner = create_test_user(&state.store, "fido2-mismatch-owner@example.com").await;
    let credential_id = owner_credential_id(&state, &owner.id).await;
    let asserted = uuid::Uuid::now_v7();

    let (_, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-mismatch-client@example.com",
        &credential_id,
        asserted,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let rows = login_failed_rows(&state, None).await;
    assert_eq!(rows.len(), 1, "one login_failed row: {rows:?}");
    let row = rows.first().expect("one row");
    assert_eq!(failure_reason(row), "user_mismatch");
    assert_eq!(row.email_domain, None);
    assert_unattributed(row, &asserted.to_string());
    let authenticator = db::get_authenticator_by_credential_id(
        &state.store,
        &URL_SAFE_NO_PAD.decode(&credential_id).expect("base64url"),
    )
    .await
    .expect("load authenticator")
    .expect("authenticator exists");
    assert_eq!(
        payload(row)["authenticator_id"].as_str(),
        Some(authenticator.id.as_str()),
        "the presented credential is recorded for forensics"
    );
}

#[tokio::test]
async fn test_fido2_token_unknown_credential_writes_no_user_attributed_row() {
    // A `credential_id` that names no stored credential is refused before any
    // signature is checked, so the row must not count against the user the
    // request's `user_handle` names.
    let (app, state) = test_app().await;
    let victim = create_test_user(&state.store, "fido2-unknown-cred@example.com").await;
    let bogus = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let asserted = uuid::Uuid::parse_str(&victim.id).expect("victim id is a uuid");

    let (_, status, body) = post_assertion_with_credential_id(
        &app,
        &state,
        "fido2-unknown-cred-client@example.com",
        &bogus,
        asserted,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["error"], "invalid_grant", "{body}");

    let rows = login_failed_rows(&state, None).await;
    assert_eq!(rows.len(), 1, "one login_failed row: {rows:?}");
    let row = rows.first().expect("one row");
    assert_eq!(failure_reason(row), "credential_not_found");
    assert_unattributed(row, &victim.id);
}

#[tokio::test]
async fn test_fido2_token_invalid_credential_id_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-cred-id@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": "!!!invalid!!!",
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid credential_id encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid credential_id encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_authenticator_data_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-auth-data@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": "!!!invalid!!!",
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid authenticator_data encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid authenticator_data encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_signature_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-sig@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": "!!!invalid!!!",
        "client_data_json": placeholder,
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid signature encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid signature encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_client_data_json_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-cdj@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": "!!!invalid!!!",
        "user_handle": placeholder,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid client_data_json encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid client_data_json encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_user_handle_encoding_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-uh-enc@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": "!!!invalid!!!",
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid user_handle encoding must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Invalid user_handle encoding must return invalid_grant, got: {}",
        error["error"]
    );
}

#[tokio::test]
async fn test_fido2_token_invalid_user_handle_uuid_rejected() {
    // user_handle decodes successfully from base64url but is only 8 bytes —
    // not a valid UUID (which requires exactly 16 bytes).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-bad-uh-uuid@example.com").await;
    let (_client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;
    let client_assertion = build_client_assertion(
        &_client.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8,
        None,
    );

    let state_jwt = get_real_state_jwt(&app, &_client.client_id, &pkcs8).await;
    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    // 8 bytes decodes fine from base64url but cannot be a UUID (needs 16 bytes)
    let short_user_handle = URL_SAFE_NO_PAD.encode(b"8bytesok");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": short_user_handle,
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-UUID user_handle must return 400: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Non-UUID user_handle must return invalid_grant, got: {}",
        error["error"]
    );
}

// ========================================================================
// Positive: Challenge endpoint properties
// ========================================================================

#[tokio::test]
async fn test_fido2_challenge_returns_unique_challenges() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-uniq@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let (status1, body1) = post_challenge(&app, &client.client_id, &pkcs8).await;
    let (status2, body2) = post_challenge(&app, &client.client_id, &pkcs8).await;

    assert_eq!(
        status1,
        StatusCode::OK,
        "First challenge must return 200: {body1}"
    );
    assert_eq!(
        status2,
        StatusCode::OK,
        "Second challenge must return 200: {body2}"
    );

    let resp1: serde_json::Value = serde_json::from_str(&body1).expect("Valid JSON");
    let resp2: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");

    let challenge1 = resp1["challenge"]
        .as_str()
        .expect("challenge1 must be a string");
    let challenge2 = resp2["challenge"]
        .as_str()
        .expect("challenge2 must be a string");

    assert_ne!(
        challenge1, challenge2,
        "Each challenge must be unique — replay attack prevention requires different nonces"
    );
}

#[tokio::test]
async fn test_fido2_challenge_rp_id_matches_config() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-rpid@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let (status, body) = post_challenge(&app, &client.client_id, &pkcs8).await;
    assert_eq!(status, StatusCode::OK, "Challenge must return 200: {body}");

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let rp_id = response["rp_id"].as_str().expect("rp_id must be a string");

    assert_eq!(
        rp_id, "test.example.com",
        "rp_id in challenge response must match server configuration"
    );
}

// ========================================================================
// Challenge endpoint client authentication (cross-client binding)
// ========================================================================

/// A request with no client credentials at all is still accepted during the
/// staged rollout — the released CLI's `/oauth/fido2/challenge` request
/// carries none — and mints a state JWT with no `client_id` claim, matching
/// this endpoint's behavior before the binding fix.
#[tokio::test]
async fn test_fido2_challenge_unauthenticated_request_still_succeeds() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_form(&app, "/oauth/fido2/challenge", "", &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Unauthenticated challenge must still succeed during the rollout: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let state_jwt = response["state"].as_str().expect("state must be a string");
    let claims = decode_state_jwt_claims(state_jwt);
    assert!(
        claims.get("client_id").is_none(),
        "unauthenticated challenge must mint a state JWT with no client_id: {claims}"
    );
}

/// The released CLI's `/oauth/fido2/challenge` request is a JSON `{}` body
/// with no client authentication (see `vouch-cli` before this fix). The
/// challenge endpoint must still accept it during the rollout so already-
/// installed CLIs keep working.
#[tokio::test]
async fn test_fido2_challenge_legacy_json_body_still_succeeds() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(&app, "/oauth/fido2/challenge", "{}", &[]).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Legacy JSON challenge body must still succeed during the rollout: {body}"
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["challenge"].is_string(),
        "Response must contain 'challenge' string field"
    );
}

/// A state JWT minted by a server version that predates the `client_id`
/// field entirely must still decode — the rolling-deploy case where an
/// instance running the old binary issued the token and a new instance
/// redeems it. `#[serde(default)]` on `Fido2ChallengeState::client_id` is
/// what makes this work: the field is simply absent from the JSON payload,
/// not present-and-null.
#[tokio::test]
async fn test_fido2_challenge_state_decodes_without_client_id_field() {
    use crate::crypto::jwt::JwtType;
    use crate::handlers::generate_challenge;
    use crate::services::oidc::fido2_grant::Fido2ChallengeState;

    /// Mirrors the pre-fix `Fido2ChallengeState` shape: no `client_id` field
    /// at all, as a server running before this change would have minted.
    #[derive(serde::Serialize)]
    struct LegacyFido2ChallengeState {
        challenge: Challenge<Raw>,
        rp_id: String,
        iat: i64,
        exp: i64,
    }

    let (_app, state) = test_app().await;
    let now = jiff::Timestamp::now().as_second();
    let legacy = LegacyFido2ChallengeState {
        challenge: generate_challenge().expect("generate challenge").into(),
        rp_id: "test.example.com".to_string(),
        iat: now,
        exp: now.saturating_add(300),
    };

    let token = state
        .state_signer
        .encode_state_token(&legacy, JwtType::Fido2ChallengeState)
        .await
        .expect("encode legacy state token");

    let decoded: Fido2ChallengeState = state
        .state_signer
        .decode_state_token(&token, JwtType::Fido2ChallengeState, now)
        .await
        .expect("decode legacy state token");

    assert_eq!(
        decoded.client_id, None,
        "a state token minted with no client_id field must decode to None"
    );
}

/// The challenge endpoint must require `private_key_jwt`. A client
/// authenticating with a shared secret (even a valid one) must be rejected,
/// matching the token endpoint's auth-method requirement for this grant.
#[tokio::test]
async fn test_fido2_challenge_requires_private_key_jwt() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-secret@example.com").await;
    // A client registered for `client_secret_basic` rather than
    // `private_key_jwt`.
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretBasic),
            with_secret: true,
            ..Default::default()
        },
    )
    .await;

    let auth = client.basic_auth_header();
    let (status, body) = http_post_form(
        &app,
        "/oauth/fido2/challenge",
        "",
        &[("Authorization", auth.as_str())],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Secret-based challenge auth must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Secret auth must return invalid_client, got: {}",
        error["error"]
    );
}

/// A client not registered for the `fido2-assertion` grant must not be able
/// to start the ceremony. RFC 6749 §5.2 `unauthorized_client` — mirroring
/// `ValidatedOAuthClient::for_grant` at the token endpoint.
#[tokio::test]
async fn test_fido2_challenge_rejects_client_unauthorized_for_grant() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-unauth@example.com").await;
    // `private_key_jwt` but authorized for `authorization_code` only.
    let (client, pkcs8) =
        create_jwt_client_with_grants(&state.store, &user.id, &["authorization_code"]).await;

    let (status, body) = post_challenge(&app, &client.client_id, &pkcs8).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Unauthorized client must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "unauthorized_client",
        "Client without fido2-assertion grant must return unauthorized_client, got: {}",
        error["error"]
    );
}

/// The challenge state JWT must carry the authenticated `client_id`, so a
/// cross-client replay at the token endpoint is rejected. Decoding the
/// state JWT (HS256, signed by the server's state signer) and reading the
/// `client_id` claim verifies the binding at issuance.
#[tokio::test]
async fn test_fido2_challenge_state_carries_client_id() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fido2-challenge-cid@example.com").await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let (status, body) = post_challenge(&app, &client.client_id, &pkcs8).await;
    assert_eq!(status, StatusCode::OK, "Challenge must succeed: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let state_jwt = response["state"].as_str().expect("state must be a string");
    let claims = decode_state_jwt_claims(state_jwt);

    assert_eq!(
        claims["client_id"].as_str(),
        Some(client.client_id.as_str()),
        "state JWT must be bound to the authenticated client_id: {}",
        claims
    );
}

/// A state JWT issued to one client must not be redeemable by a different
/// client. The cross-client check in `exchange_fido2_assertion` rejects the
/// token request with `invalid_grant` before consuming the challenge state,
/// so the legitimate client can still redeem it (no denial of service).
#[tokio::test]
async fn test_fido2_grant_rejects_cross_client_replay_before_consume() {
    let (app, state) = test_app().await;

    // Client A initiates the ceremony and obtains a state JWT bound to A.
    let user_a = create_test_user(&state.store, "fido2-xclient-a@example.com").await;
    let (client_a, pkcs8_a) = create_test_jwt_client(&state.store, &user_a.id).await;
    let state_jwt = get_real_state_jwt(&app, &client_a.client_id, &pkcs8_a).await;

    // Client B (separately registered, also authorized for fido2-assertion)
    // tries to redeem A's state+assertion under its own credentials.
    let user_b = create_test_user(&state.store, "fido2-xclient-b@example.com").await;
    let (client_b, pkcs8_b) = create_test_jwt_client(&state.store, &user_b.id).await;
    let client_assertion_b = build_client_assertion(
        &client_b.client_id,
        "https://test.example.com/oauth/token",
        &pkcs8_b,
        None,
    );

    let placeholder = URL_SAFE_NO_PAD.encode(b"valid-placeholder");
    let assertion_payload = serde_json::json!({
        "state": state_jwt,
        "credential_id": placeholder,
        "authenticator_data": placeholder,
        "signature": placeholder,
        "client_data_json": placeholder,
        "user_handle": URL_SAFE_NO_PAD.encode(uuid::Uuid::now_v7().as_bytes()),
    });
    let assertion =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion_payload).expect("JSON encode"));

    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Afido2-assertion\
             &assertion={assertion}\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={client_assertion_b}"
        ),
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Cross-client replay must be rejected: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_grant",
        "Cross-client replay must return invalid_grant, got: {}",
        error["error"]
    );

    // The rejected attempt did not consume the state, so client A can redeem.
    assert_challenge_unspent(&state, &state_jwt).await;
}

// ========================================================================
// Negative: Replay protection
// ========================================================================

#[tokio::test]
async fn test_client_assertion_jti_committed_on_success_and_rejected_on_replay() {
    // RFC 7523 §3 item 7: "The authorization server MAY ensure that JWTs are
    // not replayed". Two authorization_code exchanges with the same client
    // assertion JTI: the second is rejected with invalid_client.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "jti-replay-ac@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (client, pkcs8) = create_test_jwt_client(&state.store, &user.id).await;

    let fixed_jti = "fixed-jti-replay-test-value";
    let audience = "https://test.example.com/oauth/token";

    // First exchange: commit the JTI.
    let code1 = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

    let assertion1 = build_client_assertion(&client.client_id, audience, &pkcs8, Some(fixed_jti));
    let (status1, body1) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code\
             &code={code1}\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={assertion1}"
        ),
        &[],
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "First exchange must succeed (commits JTI): {body1}"
    );

    // Second exchange: same JTI must be rejected as a replay.
    let code2 = issue_code(
        &state,
        &user,
        &auth_id,
        &client.client_id,
        TestCodeSpec::default(),
    )
    .await;

    let assertion2 = build_client_assertion(&client.client_id, audience, &pkcs8, Some(fixed_jti));
    let (status2, body2) = http_post_form(
        &app,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code\
             &code={code2}\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion={assertion2}"
        ),
        &[],
    )
    .await;

    // RFC 6749 Section 5.2: invalid_client errors SHOULD use 401.
    assert!(
        status2 == StatusCode::BAD_REQUEST || status2 == StatusCode::UNAUTHORIZED,
        "Replayed JTI must return 400 or 401, got {status2}: {body2}"
    );
    let error: serde_json::Value = serde_json::from_str(&body2).expect("Valid JSON");
    assert_eq!(
        error["error"], "invalid_client",
        "Replayed client assertion JTI must return invalid_client, got: {}",
        error["error"]
    );
}

// ========================================================================
// Helpers local to this module
// ========================================================================

/// Decode the claims of a state JWT (the middle, base64url-encoded segment)
/// into a JSON value, for asserting on individual claims such as `client_id`.
fn decode_state_jwt_claims(state_jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = state_jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "state must be a JWT: {state_jwt}");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("JWT payload must be valid base64url");
    serde_json::from_slice(&payload).expect("JWT payload must be valid JSON")
}

/// Create a `private_key_jwt` client authorized for exactly `grants` (as
/// the wire strings stored in `grant_types`), returning the client and the
/// ES256 signing key. Used to exercise the challenge endpoint's
/// `unauthorized_client` check for a client lacking the `fido2-assertion`
/// grant.
async fn create_jwt_client_with_grants(
    store: &db::store::DocumentStore,
    user_id: &str,
    grants: &[&str],
) -> (TestOAuthClient, Vec<u8>) {
    let (pkcs8_bytes, jwk) = generate_es256_signing_key();
    let jwks_value = serde_json::json!({ "keys": [jwk] });

    let client = create_test_client(
        store,
        user_id,
        TestClientSpec {
            jwks: TestJwks::Custom(jwks_value),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            grant_types: Some(grants.iter().map(|g| (*g).to_string()).collect()),
            ..Default::default()
        },
    )
    .await;

    (client, pkcs8_bytes)
}
