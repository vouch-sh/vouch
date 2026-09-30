// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org-admin endpoints forward the request's client certificate to
//! `extract_org_admin`, so a certificate-bound (`cnf.x5t#S256`) access token
//! is accepted with its matching mTLS certificate.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use crate::AppState;
use crate::db;
use crate::test_utils::{
    TestClientSpec, create_test_client, create_test_org_admin, http_get_with_cert,
    http_post_form_with_cert, test_app, test_client_ca,
};
use axum::Router;
use axum::http::StatusCode;
use std::sync::Arc;

const ORIGIN: &str = "https://test.example.com";
const MISSING_CERT: &str = "mTLS certificate required for certificate-bound token";
const VALID_POLICY_TEXT: &str = "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };";

struct Fixture {
    app: Router,
    state: Arc<AppState>,
    org_id: String,
    token: String,
    cert: Vec<u8>,
}

fn decode_payload(jwt: &str) -> serde_json::Value {
    use base64::Engine;
    let part = jwt.split('.').nth(1).expect("payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("b64");
    serde_json::from_slice(&bytes).expect("json")
}

/// Mint a certificate-bound org-admin access token through the public token
/// endpoint: RFC 8693 exchange of the admin's unbound token by a client
/// registered with `tls_client_certificate_bound_access_tokens`, presenting a
/// client certificate. The issued token carries `cnf.x5t#S256` for that cert.
async fn fixture() -> Fixture {
    let (app, state) = test_app().await;
    let (admin, subject) = create_test_org_admin(&state).await;
    let client = create_test_client(
        &state.store,
        &admin.id,
        TestClientSpec {
            tls_client_certificate_bound_access_tokens: true,
            ..Default::default()
        },
    )
    .await;
    let cert = test_client_ca().issue("org-admin-cert");
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={subject}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
    );
    let (status, body) = http_post_form_with_cert(
        &app,
        "/oauth/token",
        &form,
        &[("Authorization", &client.basic_auth_header())],
        Some(cert.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token exchange setup: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token = json["access_token"].as_str().unwrap().to_string();
    assert!(
        decode_payload(&token)["cnf"]["x5t#S256"].is_string(),
        "setup: issued token must be certificate-bound: {body}"
    );
    Fixture {
        app,
        state,
        org_id: admin.org_id.expect("admin has org"),
        token,
        cert,
    }
}

fn assert_accepted(site: &str, status: StatusCode, body: &str) {
    assert!(
        status != StatusCode::UNAUTHORIZED,
        "{site}: a cnf.x5t#S256-bound org-admin token presented with its matching mTLS \
         certificate must be accepted ({status}): {body}"
    );
}

// ---- controls ----

// RFC 8705 §3: "The protected resource MUST obtain, from its TLS
// implementation layer, the client certificate used for mutual TLS and MUST
// verify that the certificate matches the certificate associated with the
// access token."
#[tokio::test]
async fn control_org_scim_tokens_list_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_get_with_cert(
        &f.app,
        "/api/v1/org/scim-tokens",
        &[("Authorization", &auth)],
        Some(f.cert.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "control: {body}");
}

// RFC 8705 §3: "If they do not match, the resource access attempt MUST be
// rejected with an error, per [RFC6750], using an HTTP 401 status code and the
// "invalid_token" error code."
#[tokio::test]
async fn control_org_scim_tokens_list_refuses_bound_token_without_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_get_with_cert(
        &f.app,
        "/api/v1/org/scim-tokens",
        &[("Authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "fail-closed: {body}");
    assert!(body.contains(MISSING_CERT), "{body}");
}

/// Admin-UI sibling that uses the `OrgAdmin` extractor (passes the cert).
#[tokio::test]
async fn control_admin_revoke_scim_token_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_post_form_with_cert(
        &f.app,
        "/admin/scim-tokens/00000000-0000-4000-8000-000000000000/revoke",
        "",
        &[("Authorization", &auth), ("Origin", ORIGIN)],
        Some(f.cert.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "control (OrgAdmin extractor): {body}"
    );
}

// ---- sites ----

#[tokio::test]
async fn site_org_audit_events_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_get_with_cert(
        &f.app,
        "/api/v1/org/audit-events",
        &[("Authorization", &auth)],
        Some(f.cert.clone()),
    )
    .await;
    assert_accepted(
        "handlers/api/org/audit.rs:218 (GET /api/v1/org/audit-events)",
        status,
        &body,
    );
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn site_admin_toggle_preconfigured_policy_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_post_form_with_cert(
        &f.app,
        "/admin/policies/preconfigured/disk_encryption/toggle",
        "",
        &[("Authorization", &auth), ("Origin", ORIGIN)],
        Some(f.cert.clone()),
    )
    .await;
    assert_accepted(
        "handlers/admin/policies.rs:193 (POST /admin/policies/preconfigured/{slug}/toggle)",
        status,
        &body,
    );
}

#[tokio::test]
async fn site_admin_create_custom_policy_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let form = format!(
        "policy_name=P&policy_text={}",
        urlencoding::encode(VALID_POLICY_TEXT)
    );
    let (status, body) = http_post_form_with_cert(
        &f.app,
        "/admin/policies/custom",
        &form,
        &[("Authorization", &auth), ("Origin", ORIGIN)],
        Some(f.cert.clone()),
    )
    .await;
    assert_accepted(
        "handlers/admin/policies.rs:401 (POST /admin/policies/custom)",
        status,
        &body,
    );
}

#[tokio::test]
async fn site_admin_update_custom_policy_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let created = db::create_custom_policy(
        &f.state.store,
        db::CreateCustomPolicyParams {
            name: "Original",
            description: None,
            policy_text: VALID_POLICY_TEXT,
            org_id: &f.org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create custom policy");
    let auth = format!("Bearer {}", f.token);
    let form = format!(
        "policy_name=P2&policy_text={}",
        urlencoding::encode(VALID_POLICY_TEXT)
    );
    let (status, body) = http_post_form_with_cert(
        &f.app,
        &format!("/admin/policies/custom/{}", created.id),
        &form,
        &[("Authorization", &auth), ("Origin", ORIGIN)],
        Some(f.cert.clone()),
    )
    .await;
    assert_accepted(
        "handlers/admin/policies.rs:510 (POST /admin/policies/custom/{id})",
        status,
        &body,
    );
}

#[tokio::test]
async fn site_admin_create_scim_token_accepts_bound_token_with_cert() {
    let f = fixture().await;
    let auth = format!("Bearer {}", f.token);
    let (status, body) = http_post_form_with_cert(
        &f.app,
        "/admin/scim-tokens",
        "description=ci&expires_in_days=30",
        &[("Authorization", &auth), ("Origin", ORIGIN)],
        Some(f.cert.clone()),
    )
    .await;
    assert_accepted(
        "handlers/admin/scim_tokens.rs:189 (POST /admin/scim-tokens)",
        status,
        &body,
    );
}
