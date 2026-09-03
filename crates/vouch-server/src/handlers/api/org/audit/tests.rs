// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

#[test]
fn parse_event_types_rejects_empty() {
    assert!(parse_event_types("").is_err());
    assert!(parse_event_types("  ").is_err());
}

#[test]
fn parse_event_types_rejects_unknown() {
    assert!(parse_event_types("login_success,not_a_real_type").is_err());
}

#[test]
fn parse_event_types_accepts_known_comma_separated() {
    let types = parse_event_types("login_success,login_failed").expect("both types are registered");
    assert_eq!(types, vec!["login_success", "login_failed"]);
}

#[test]
fn parse_timestamp_param_rejects_garbage() {
    assert!(parse_timestamp_param("since", "not-a-timestamp").is_err());
}

#[test]
fn parse_timestamp_param_accepts_rfc3339() {
    assert!(parse_timestamp_param("since", "2026-01-01T00:00:00Z").is_ok());
}

// ====================================================================
// HTTP-level tests: auth matrix, filters, cursor, lag window, formats
// ====================================================================

use crate::test_utils::*;

const PATH: &str = "/api/v1/org/audit-events";

async fn seed_org_admin(state: &AppState) -> (String, String, String) {
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    (org.id, admin.id, token)
}

#[tokio::test]
async fn audit_token_with_audit_read_scope_is_accepted() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let (status, _body) =
        http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::OK);
}

/// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
/// `BEARER`, `bearer`, and `BeArEr` must all authenticate the same as
/// `Bearer`. Regression test for the case-sensitive `strip_prefix`
/// pattern that incorrectly rejected uppercase/mixed-case schemes.
#[tokio::test]
async fn audit_token_accepts_bearer_scheme_case_variants() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    for scheme in ["BEARER", "bearer", "BeArEr", "bEaReR"] {
        let (status, _body) = http_get(
            &app,
            PATH,
            &[("Authorization", &format!("{scheme} {token}"))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{scheme} scheme must be accepted (RFC 9110 §11.1 case-insensitivity)"
        );
    }
}

/// An unrecognized scheme must still be rejected by the guard clause
/// even when it's a case variant of a scheme we don't support (e.g.
/// `Basic`). This confirms the guard didn't become overly permissive.
#[tokio::test]
async fn guard_clause_rejects_unrecognized_scheme_case_variants() {
    let (app, _state) = test_app().await;

    for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
        let (status, body) = http_get(
            &app,
            PATH,
            &[("Authorization", &format!("{scheme} dXNlcjpwYXNz"))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{scheme} must be rejected by the guard clause"
        );
        assert!(
            body.contains("Unsupported authorization scheme"),
            "{scheme} must be rejected as an unsupported scheme; got: {body}"
        );
    }
}

#[tokio::test]
async fn scim_scope_only_token_is_rejected() {
    // A token minted before this feature (or without the checkbox) has
    // the four SCIM scopes but not audit:read.
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_scim_token(&state.store, "scim-only", &org.id).await;

    let (status, _body) =
        http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn org_admin_user_jwt_is_accepted() {
    let (app, state) = test_app().await;
    let (_org_id, _admin_id, token) = seed_org_admin(&state).await;

    let (status, _body) =
        http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn non_admin_user_jwt_is_forbidden() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let member = create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
    let auth_id = create_test_authenticator(&state.store, &member.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &member.id,
            email: &member.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    let (status, _body) =
        http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cookie_auth_is_rejected() {
    let (app, state) = test_app().await;
    let (_org_id, _admin_id, token) = seed_org_admin(&state).await;
    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

    let (status, _body) = http_get(&app, PATH, &[("Cookie", &cookie)]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "cookie-only auth must be rejected even for a valid session"
    );
}

#[tokio::test]
async fn unrecognized_authorization_scheme_with_valid_cookie_is_rejected() {
    // Regression test: `session.rs`'s `extract_token_from_request`
    // only recognizes `DPoP `/`Bearer ` prefixes and silently falls back
    // to the session cookie for anything else (e.g. `Authorization:
    // Basic ...`). Without an explicit scheme check, that fallback would
    // let a request with a nonsense Authorization header plus a valid
    // admin session cookie authenticate anyway — defeating this
    // endpoint's cookie-rejection guarantee. `cookie_auth_is_rejected`
    // above only covers the "no header at all" case.
    let (app, state) = test_app().await;
    let (_org_id, _admin_id, token) = seed_org_admin(&state).await;
    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

    let (status, _body) = http_get(
        &app,
        PATH,
        &[("Authorization", "Basic dXNlcjpwYXNz"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unrecognized Authorization scheme must not fall back to the session cookie"
    );
}

#[tokio::test]
async fn missing_auth_is_unauthorized() {
    let (app, _state) = test_app().await;
    let (status, _body) = http_get(&app, PATH, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cross_org_isolation() {
    // Both events are backdated past the lag window with
    // `insert_event_for_test` — using plain `insert_event` here (which
    // always stamps `now`) would make this test pass vacuously: the
    // lag window alone would exclude org B's event regardless of
    // whether domain scoping filtered it out at all.
    let (app, state) = test_app().await;
    let org_a = create_test_org(&state.store, "a.example.com").await;
    let org_b = create_test_org(&state.store, "b.example.com").await;
    let token_a = create_test_audit_token(&state.store, "org-a", &org_a.id).await;

    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    state
        .audit
        .insert_event_for_test(AuditEventKind::LoginSuccess, Some(&org_a.domain), old, "{}")
        .await
        .expect("insert org a event");
    state
        .audit
        .insert_event_for_test(AuditEventKind::LoginSuccess, Some(&org_b.domain), old, "{}")
        .await
        .expect("insert org b event");

    let (status, body) = http_get(
        &app,
        PATH,
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        1,
        "org A's token must see exactly its own org's event; got {events:?}"
    );
    assert_eq!(events[0]["email_domain"], "a.example.com");
}

#[tokio::test]
async fn unknown_event_type_returns_400() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let (status, _body) = http_get(
        &app,
        &format!("{PATH}?event_type=not_a_real_type"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_event_type_returns_400() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let (status, _body) = http_get(
        &app,
        &format!("{PATH}?event_type="),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recent_event_is_excluded_by_the_lag_window() {
    // An event written "now" is always within the 30s lag window and
    // must never appear, regardless of any `until` the caller passes.
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    state
        .audit
        .insert_json_event_for_test(
            AuditEventKind::LoginSuccess,
            None,
            Some("a@example.com"),
            "{}",
        )
        .await
        .expect("insert event");

    let (status, body) =
        http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert!(
        events.is_empty(),
        "an event written moments ago must be held back by the lag window; got {events:?}"
    );
}

#[tokio::test]
async fn ndjson_format_returns_one_json_object_per_line() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    // Backdate the event so it clears the lag window (events inserted
    // via `insert_event`/`insert_event_with_domain` always stamp `now`,
    // which the lag window would hold back).
    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    state
        .audit
        .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
        .await
        .expect("insert event");

    let resp = http_get_full(
        &app,
        PATH,
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Accept", "application/x-ndjson"),
        ],
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-ndjson")
    );
    let lines: Vec<&str> = resp.body.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("line is valid JSON");
    assert_eq!(parsed["event_type"], "login_success");
}

#[tokio::test]
async fn ocsf_format_projects_class_uid() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    state
        .audit
        .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
        .await
        .expect("insert event");

    let (status, body) = http_get(
        &app,
        &format!("{PATH}?format=ocsf"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["class_uid"], 3002);
}

/// OCSF 1.9.0 MUST: events mapped to `activity_id: 99` (Other) must
/// emit a source-specific `activity_name` (not the literal "Other")
/// and preserve `event_type` in `unmapped`. End-to-end check through
/// the `?format=ocsf` HTTP endpoint, covering all five affected kinds
/// and confirming `AdminPromote`/`AdminDemote` are distinguishable.
#[tokio::test]
async fn ocsf_format_activity_id_99_events_carry_source_specific_name() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    // Seed one event of each activity_id: 99 kind.
    let cases: [(AuditEventKind, u16, &str); 5] = [
        (AuditEventKind::AdminPromote, 3001, "Admin Promote"),
        (AuditEventKind::AdminDemote, 3001, "Admin Demote"),
        (
            AuditEventKind::AdminRevokeCredentials,
            3001,
            "Admin Revoke Credentials",
        ),
        (
            AuditEventKind::OauthTokenRevoked,
            3003,
            "OAuth Token Revoked",
        ),
        (AuditEventKind::ScimOperation, 3004, "SCIM Operation"),
    ];
    for (kind, _, _) in &cases {
        state
            .audit
            .insert_event_for_test(*kind, Some("example.com"), old, "{}")
            .await
            .expect("insert event");
    }

    let (status, body) = http_get(
        &app,
        &format!("{PATH}?format=ocsf&limit=100"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert_eq!(events.len(), cases.len());

    // Build a lookup by event_type so order doesn't matter.
    use std::collections::HashMap;
    let mut by_type: HashMap<&str, &serde_json::Value> = HashMap::new();
    for ev in events {
        let et = ev["unmapped"]["event_type"]
            .as_str()
            .expect("event_type in unmapped");
        by_type.insert(et, ev);
    }

    for (kind, expected_class_uid, expected_activity_name) in &cases {
        let ev = by_type
            .get(kind.as_str())
            .expect("event_type must be present in response");
        assert_eq!(
            ev["activity_id"],
            99,
            "{}: activity_id must be 99",
            kind.as_str()
        );
        assert_ne!(
            ev["activity_name"],
            "Other",
            "{}: activity_name must not be the generic \"Other\"",
            kind.as_str()
        );
        assert_eq!(
            ev["activity_name"],
            *expected_activity_name,
            "{}: activity_name mismatch",
            kind.as_str()
        );
        assert_eq!(
            ev["class_uid"],
            *expected_class_uid,
            "{}: class_uid mismatch",
            kind.as_str()
        );
        assert_eq!(
            ev["unmapped"]["event_type"],
            kind.as_str(),
            "{}: unmapped.event_type must preserve source event_type",
            kind.as_str()
        );
        // type_uid = class_uid * 100 + activity_id
        let expected_type_uid = u32::from(*expected_class_uid) * 100 + 99;
        assert_eq!(
            ev["type_uid"],
            expected_type_uid,
            "{}: type_uid mismatch",
            kind.as_str()
        );
    }

    // Explicitly confirm the security-critical distinction: promote
    // vs demote must be distinguishable at the OCSF layer.
    let promote = by_type.get("admin_promote").expect("admin_promote present");
    let demote = by_type.get("admin_demote").expect("admin_demote present");
    assert_ne!(
        promote["activity_name"], demote["activity_name"],
        "admin_promote and admin_demote must be distinguishable by activity_name"
    );
}

#[tokio::test]
async fn forward_cursor_pages_without_gap_or_duplicate() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    for _ in 0..3 {
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
            .await
            .expect("insert event");
    }

    let (status, body) = http_get(
        &app,
        &format!("{PATH}?limit=2"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2, "page size must be respected");
    let cursor = resp["next_cursor"].as_str().expect("next_cursor present");

    let (status, body) = http_get(
        &app,
        &format!("{PATH}?limit=2&after={cursor}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events2 = resp["events"].as_array().expect("events array");
    assert_eq!(events2.len(), 1, "the remaining event must be on page two");
    assert_ne!(
        events[0]["id"], events2[0]["id"],
        "no event should repeat across pages"
    );
}

#[tokio::test]
async fn backward_cursor_pages_newest_first_without_gap_or_duplicate() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let token = create_test_audit_token(&state.store, "poller", &org.id).await;

    let old = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().minutes(5))
        .expect("valid timestamp");
    for _ in 0..3 {
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
            .await
            .expect("insert event");
    }

    // `before` set to a sentinel that sorts after every real UUID v7 id
    // (its characters are all outside the hex/dash alphabet) so the
    // first page starts from "now" and walks backward — the direction
    // `/admin/audit` uses.
    let sentinel = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
    let (status, body) = http_get(
        &app,
        &format!("{PATH}?limit=2&before={sentinel}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events = resp["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2, "page size must be respected");
    let cursor = resp["next_cursor"].as_str().expect("next_cursor present");

    let (status, body) = http_get(
        &app,
        &format!("{PATH}?limit=2&before={cursor}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let events2 = resp["events"].as_array().expect("events array");
    assert_eq!(events2.len(), 1, "the remaining event must be on page two");
    assert_ne!(
        events[0]["id"], events2[0]["id"],
        "no event should repeat across pages"
    );

    let newest_on_page_two = events[1]["id"].as_str().expect("id is a string");
    let only_id_on_page_two = events2[0]["id"].as_str().expect("id is a string");
    assert!(
        only_id_on_page_two < newest_on_page_two,
        "descending order: page two's event must be older than page one's oldest"
    );
}

fn sample_audit_event(id: &str, data: &str) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        event_type: AuditEventKind::LoginSuccess.as_str().to_string(),
        user_id: None,
        email_domain: Some("example.com".to_string()),
        email_hmac: None,
        data: data.to_string(),
        created_at: Timestamp::now(),
    }
}

#[test]
fn ndjson_body_stops_at_byte_budget_and_always_emits_one_line() {
    let events = vec![
        sample_audit_event("event-1", "{\"padding\":\"aaaaaaaaaa\"}"),
        sample_audit_event("event-2", "{\"padding\":\"bbbbbbbbbb\"}"),
        sample_audit_event("event-3", "{\"padding\":\"cccccccccc\"}"),
    ];
    // Smaller than any two lines combined but larger than one line, so
    // exactly the first event is emitted and the cap kicks in on the
    // second.
    let one_line_len = serialize_line(&events[0], false).expect("serialize").len();
    let budget = one_line_len + 5;

    let (body, next_cursor) = build_ndjson_body(&events, false, false, budget).expect("build body");
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "only the first event should fit under budget"
    );
    assert_eq!(
        next_cursor.as_deref(),
        Some("event-1"),
        "cursor must resume at the last emitted event"
    );
}

#[test]
fn ndjson_body_always_emits_at_least_one_line_even_over_budget() {
    let events = vec![sample_audit_event(
        "event-1",
        "{\"padding\":\"aaaaaaaaaaaaaaaaaaaa\"}",
    )];
    let (body, next_cursor) = build_ndjson_body(&events, false, false, 1).expect("build body");
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "a single event that alone exceeds the budget must still be emitted, \
         so a poller always makes forward progress"
    );
    assert_eq!(next_cursor.as_deref(), None, "no more events, so no cursor");
}
