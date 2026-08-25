// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use crate::test_utils::{
    create_test_authenticator, create_test_session, create_test_user, http_post_json, test_app,
    test_app_state,
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

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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
    let oversized = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_CREDENTIAL_ID_BYTES + 1]);

    let body = serde_json::json!({
        "state": valid_state,
        "credential_id": oversized,
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp_body.contains("invalid_credential"),
        "expected 'invalid_credential' in body, got: {resp_body}"
    );
}

// ── test_browser_register_complete_rejects_replayed_state ───────────────

#[tokio::test]
async fn test_browser_register_complete_rejects_replayed_state() {
    let (app, state) = test_app().await;

    // Build a valid BrowserRegistrationState JWT and record its expiry.
    let user_id = Uuid::now_v7();
    let (_ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, "replay@example.com", "replay@example.com", None)
        .expect("start_passkey_registration");

    let now = jiff::Timestamp::now();
    let exp = now.as_second() + 300;
    let reg_state = BrowserRegistrationState {
        device_auth_id: String::new(),
        user_id,
        user_email: "replay@example.com".to_string(),
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
    let _claim = crate::db::try_consume_challenge_state(&state.store, &state_jwt, expires_at)
        .await
        .expect("pre-consume must succeed");

    // POST to the complete endpoint with the already-consumed state.
    // The fields must be well-formed base64url to get past deserialization,
    // but their contents never matter — the replay check precedes every use.
    let body = serde_json::json!({
        "state": state_jwt,
        "credential_id": valid_credential_id(),
        "attestation_object": valid_attestation_object(),
        "client_data_json": valid_client_data_json(),
    })
    .to_string();

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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

    let (status, resp_body) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;

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

/// Seed an OIDC state row and atomically consume it, yielding the
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

/// Poll the audit store for events of `event_type` for the user. Audit
/// writes are spawned on a detached task, so the first read can race
/// the write; retry briefly before returning whatever was found.
async fn wait_for_audit_events(
    state: &AppState,
    event_type: &str,
    user_id: &str,
) -> Vec<crate::db::AuditEvent> {
    let mut events = Vec::new();
    for _ in 0..40 {
        events = state
            .audit
            .query_events(&crate::db::AuditEventFilter {
                event_types: Some(vec![event_type.to_string()]),
                user_id: Some(user_id.to_string()),
                ..Default::default()
            })
            .await
            .expect("query audit events");
        if !events.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    events
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

    let events = wait_for_audit_events(&state, "login_success", &user.id).await;
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

    let events = wait_for_audit_events(&state, "identity_bind_refused", &victim.id).await;
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

    let events = wait_for_audit_events(&state, "identity_bind_refused", &victim.id).await;
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

    let events = wait_for_audit_events(&state, "identity_bound", &user.id).await;
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

    // Audit writes are spawned; give the runtime a moment before
    // asserting absence.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

    let (status, body) =
        crate::test_utils::http_post_form(&app, "/device", "user_code=BCDF-GHJK", &[]).await;

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
        &[],
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
        &[],
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

    let resp =
        crate::test_utils::http_post_form_full(&app, "/device", "user_code=BCDF-GHJK", &[]).await;

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

    let (status, body) =
        crate::test_utils::http_post_form(&app, "/device", "user_code=BCDF-GHJK", &[]).await;

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

// ── Regression: browser_register_complete sets auth_time ────────────────
//
// The `browser_register_complete` handler issues a `HardwareVerification::Verified`
// session after FIDO2 WebAuthn registration. Before the fix it left `auth_time: None`,
// which caused the `require_fresh_timestamp(token.auth_time.unwrap_or(0), ...)`
// freshness gate on key deletion to treat the fresh session as Unix epoch, failing
// every immediate delete with `StepUpRequired`.
//
// This test drives the full handler with a cryptographically valid packed
// self-attestation (signed by a software ES256 key), then decodes the issued
// session JWT and asserts that `auth_time` is present, recent, and consistent
// with the `amr`/`acr`/`hardware_verified` claims.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "hand-built WebAuthn packed attestation payload is inherently linear"
)]
async fn test_browser_register_complete_sets_auth_time_on_session() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    let (app, state) = test_app().await;

    // Pre-create the user so `complete_enrollment_after_identity`-style rows
    // exist; `browser_register_complete` itself enrolls the authenticator
    // against `reg_state.user_id`.
    let user_id = Uuid::now_v7();
    let user_email = "auth-time-regression@example.com";

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
        &[("Content-Type", "application/json")],
    )
    .await;

    assert_eq!(
        resp.status,
        StatusCode::OK,
        "browser_register_complete should succeed, body: {}",
        resp.body
    );

    // 10. Extract the Set-Cookie header and decode the JWT payload.
    let set_cookie = resp
        .headers
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie header must be present")
        .to_str()
        .expect("ascii Set-Cookie");
    assert!(
        set_cookie.contains(vouch_common::SESSION_COOKIE_NAME),
        "Set-Cookie must set the session cookie: {set_cookie}"
    );
    // Cookie value is between `<cookie_name>=` and the first `;`.
    let cookie_value = set_cookie
        .split_once(&format!("{}=", vouch_common::SESSION_COOKIE_NAME))
        .and_then(|(_, rest)| rest.split(';').next())
        .expect("extract cookie value");
    let jwt_payload = decode_jwt_payload_claims(cookie_value);

    // G4: auth_time is present, recent, non-null.
    let auth_time = jwt_payload
        .get("auth_time")
        .and_then(|v| v.as_i64())
        .expect("auth_time must be present on the enrollment session JWT");
    let skew = 10_i64;
    let now_secs = jiff::Timestamp::now().as_second();
    assert!(
        (now_secs - skew..=now_secs + skew).contains(&auth_time),
        "auth_time ({auth_time}) should be within ±{skew}s of now ({now_secs})"
    );

    // G4: hardware_verified, amr, acr are consistent with Verified FIDO2.
    assert_eq!(
        jwt_payload
            .get("hardware_verified")
            .and_then(|v| v.as_bool()),
        Some(true),
        "hardware_verified must be true: {jwt_payload}"
    );
    let amr = jwt_payload
        .get("amr")
        .and_then(|v| v.as_array())
        .expect("amr must be present");
    let amr_values: Vec<&str> = amr.iter().map(|v| v.as_str().unwrap_or("")).collect();
    assert!(
        amr_values.contains(&"hwk") && amr_values.contains(&"pin") && amr_values.contains(&"user"),
        "amr must include hwk, pin, user: {amr:?}"
    );
    assert_eq!(
        jwt_payload.get("acr").and_then(|v| v.as_str()),
        Some(crate::services::auth::ACR_AAL3),
        "acr must be AAL3: {jwt_payload}"
    );

    // 11. G1: the fresh session must pass the freshness gate on key delete.
    // The "last key" guard refuses to delete the only key, so we cannot
    // drive DELETE to 200 here without a second authenticator — but the
    // freshness check itself runs *before* the last-key guard, so a 401
    // StepUpRequired response would prove the gate fails. Instead, we
    // verify via the unit-test coverage of `require_fresh_timestamp` plus
    // the auth_time claim being recent (above), which together pin the
    // fix. A stale-auth_time session (the bug) would have produced
    // auth_time=null and been rejected; here auth_time is present and
    // recent, so `unwrap_or(0)` is never taken.
}

/// Decode a JWT's payload (middle segment) as a JSON object without
/// verifying the signature — test-only helper for asserting claim values.
fn decode_jwt_payload_claims(jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert!(parts.len() >= 2, "JWT must have at least 2 parts");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[1]))
        .expect("decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("parse JWT payload JSON")
}

#[tokio::test]
async fn test_browser_register_start_refuses_deactivated_user() {
    // A deactivated user's surviving enrollment cookie must not begin
    // new hardware-key registration (issue #846).
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "deactivated-start@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, body) =
        http_post_json(&app, "/enroll/webauthn/start", "{}", &[("Cookie", &cookie)]).await;
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

    let (status, resp) = http_post_json(&app, "/enroll/webauthn/complete", &body, &[]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deactivated user must not complete key registration: {resp}"
    );
}
