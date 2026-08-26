// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 challenge state single-use enforcement.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// FIDO2 Challenge State Single-Use Tests
// ========================================================================

#[tokio::test]
async fn test_challenge_state_mark_used() {
    let (store, _audit) = test_db().await;

    let state_jwt = "test-jwt-mark-used";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    // First use should succeed and return a witness
    let _claim = consume_challenge_state_for_test(&store, state_jwt, expires_at)
        .await
        .expect("First use should succeed");
}

#[tokio::test]
async fn test_challenge_state_replay_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let state_jwt = "test-jwt-replay";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    // First use succeeds
    let _first = consume_challenge_state_for_test(&store, state_jwt, expires_at)
        .await
        .expect("First use should succeed");

    // Second use must fail (replay)
    let second = consume_challenge_state_for_test(&store, state_jwt, expires_at).await;
    assert!(
        matches!(second, Err(ClaimError::AlreadyConsumed)),
        "Second use (replay) should be rejected, got: {second:?}"
    );
}

#[tokio::test]
async fn test_challenge_state_new_hash_succeeds() {
    let (store, _audit) = test_db().await;

    // A never-seen hash should succeed on first use
    let _claim = consume_challenge_state_for_test(
        &store,
        "never_seen_hash",
        jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(300))
            .unwrap(),
    )
    .await
    .expect("New challenge hash should succeed");
}

#[tokio::test]
async fn test_challenge_state_concurrent_calls_produce_one_row() {
    use crate::db::claim::ClaimError;
    // Two concurrent calls with the same state_jwt must produce exactly one
    // winner — deterministic ID ensures they collide on the PRIMARY KEY
    // rather than creating two rows.
    let (store, _audit) = test_db().await;

    let state_jwt = "concurrent-state-jwt-test-value";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        consume_challenge_state_for_test(&store_a, state_jwt, expires_at),
        consume_challenge_state_for_test(&store_b, state_jwt, expires_at),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one concurrent call should win, got a={a_won}, b={b_won}"
    );
    // The loser must report AlreadyConsumed (not a database error).
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[test]
fn test_scim_filter_parse_korean_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"userName eq "사용자@example.com""#, "userName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "사용자@example.com");
}
