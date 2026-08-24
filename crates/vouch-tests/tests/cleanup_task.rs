// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the background cleanup task (`infra/cleanup.rs`).
//!
//! Focuses on `run_cleanup` — the single-pass entry point that
//! `start_cleanup_task` drives in a loop. The task itself sleeps for several
//! minutes between ticks, so the test exercises `run_cleanup` directly to
//! confirm expired rows go and fresh rows stay.

#![expect(
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
)]

use jiff::{Span, Timestamp};
use vouch_server::db::{self, SessionPurpose};
use vouch_server::infra::cleanup;
use vouch_tests::TestHarness;

const TOKEN_HASH_EXPIRED: &str = "expired-token-hash";
const TOKEN_HASH_FRESH: &str = "fresh-token-hash";

/// Default retention windows used by these tests. Mirrors `test_config()` so
/// runs match what the server uses in unit tests.
const AUTH_EVENTS_DAYS: i64 = 90;
const OAUTH_EVENTS_DAYS: i64 = 30;

#[tokio::test]
async fn run_cleanup_on_empty_store_is_a_noop() {
    let harness = TestHarness::new().await;

    // No seeded data — every helper should run with zero work and not panic.
    cleanup::run_cleanup(
        &harness.state.store,
        &harness.state.audit,
        AUTH_EVENTS_DAYS,
        OAUTH_EVENTS_DAYS,
    )
    .await;
}

#[tokio::test]
async fn run_cleanup_removes_expired_sessions_and_keeps_fresh_ones() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("cleanup-sessions@example.com")
        .await
        .expect("create user");
    let auth_id = harness
        .create_authenticator(&user.id)
        .await
        .expect("create authenticator");

    let now = Timestamp::now();
    let past = now
        .checked_sub(Span::new().hours(1))
        .expect("1h subtraction");
    let future = now.checked_add(Span::new().hours(1)).expect("1h addition");

    // Two sessions: one already expired, one with a future expiry.
    db::create_session(
        &harness.state.store,
        &db::CreateSessionParams {
            user_id: &user.id,
            user_email: &user.email,
            token_hash: TOKEN_HASH_EXPIRED,
            authenticator_id: Some(&auth_id),
            expires_at: past,
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
        },
    )
    .await
    .expect("create expired session");
    db::create_session(
        &harness.state.store,
        &db::CreateSessionParams {
            user_id: &user.id,
            user_email: &user.email,
            token_hash: TOKEN_HASH_FRESH,
            authenticator_id: Some(&auth_id),
            expires_at: future,
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
        },
    )
    .await
    .expect("create fresh session");

    cleanup::run_cleanup(
        &harness.state.store,
        &harness.state.audit,
        AUTH_EVENTS_DAYS,
        OAUTH_EVENTS_DAYS,
    )
    .await;

    // `get_session_by_token_hash` already filters out expired sessions, so
    // both calls should return None for the expired one and Some for the
    // fresh one. We additionally confirm the fresh one is still there to
    // prove cleanup didn't sweep too aggressively.
    let fresh =
        db::get_session_by_token_hash(&harness.state.store, TOKEN_HASH_FRESH, Timestamp::now())
            .await
            .expect("query fresh");
    assert!(fresh.is_some(), "fresh session must survive cleanup");

    // For the expired one we want to assert the row is truly gone (not just
    // filtered by the read API). Re-running `delete_expired_sessions` and
    // expecting 0 deletions confirms cleanup already removed it.
    let now_str = Timestamp::now().to_string();
    let count = db::delete_expired_sessions(&harness.state.store, &now_str)
        .await
        .expect("second sweep");
    assert_eq!(
        count, 0,
        "first run_cleanup should have removed the expired row"
    );
}

#[tokio::test]
async fn run_cleanup_tolerates_zero_retention_for_audit_events() {
    let harness = TestHarness::new().await;

    // Seed a single audit event so the retention sweep has something to
    // evaluate against the cutoff.
    harness
        .state
        .audit
        .insert_json_event_for_test(
            db::AuditEventKind::LoginSuccess,
            Some("user-1"),
            Some("user-1@example.com"),
            "{}",
        )
        .await
        .expect("seed audit event");

    // Retention = 0 means anything older than `now - 0 days` is eligible.
    // The cutoff math must not overflow and run_cleanup must complete.
    cleanup::run_cleanup(&harness.state.store, &harness.state.audit, 0, 0).await;
}
