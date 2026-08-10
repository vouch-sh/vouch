// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT-assertion and DPoP JTI replay prevention and expiry cleanup.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// JWT assertion JTI — replay prevention and expiry cleanup
// ========================================================================

#[tokio::test]
async fn test_store_jwt_assertion_jti_replay_prevention() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // First use returns the witness
    let _claim = store_jwt_assertion_jti(&store, "jti-abc", "client-1", expires)
        .await
        .expect("First use of a JTI should be accepted");

    // Replay with same jti + client_id returns AlreadyConsumed
    let replayed = store_jwt_assertion_jti(&store, "jti-abc", "client-1", expires).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of same JTI+client_id should be rejected: got {replayed:?}"
    );

    // Same JTI from a different client_id is allowed
    let _different_client = store_jwt_assertion_jti(&store, "jti-abc", "client-2", expires)
        .await
        .expect("Same JTI from a different client should be accepted");
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_too_long() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // JTI longer than MAX_JTI_LENGTH (256) must be rejected immediately
    let long_jti = "x".repeat(257);
    let result = store_jwt_assertion_jti(
        &store,
        &long_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "JTI exceeding max length must return InvalidInput (client error, \
         not Database — a Database error would tell well-behaved clients to \
         retry the oversized JTI): got {result:?}"
    );
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_rejects_nul() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // A NUL byte would be rejected by Postgres/DSQL at insert time; the
    // pre-check turns that into a client error instead of a Database one.
    let result = store_jwt_assertion_jti(
        &store,
        "jti\0abc",
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "JTI containing NUL must return InvalidInput: got {result:?}"
    );
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_at_max_length() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // Exactly MAX_JTI_LENGTH (256) must be accepted
    let max_jti = "j".repeat(256);
    let _claim = store_jwt_assertion_jti(
        &store,
        &max_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await
    .expect("JTI at max length should be accepted");

    // Replay still detected
    let replayed = store_jwt_assertion_jti(
        &store,
        &max_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of max-length JTI should be rejected: got {replayed:?}"
    );
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_client_isolation() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // Three independent (jti, client_id) pairs must all succeed
    let _a = store_jwt_assertion_jti(&store, "jti-xyz", "client-A", expires)
        .await
        .expect("First pair should be accepted");
    let _b = store_jwt_assertion_jti(&store, "jti-xyz", "client-B", expires)
        .await
        .expect("Same JTI, different client should be accepted");
    let _c = store_jwt_assertion_jti(&store, "jti-pqr", "client-A", expires)
        .await
        .expect("Different JTI, same client should be accepted");

    // Each pair replays to AlreadyConsumed independently
    let a2 = store_jwt_assertion_jti(&store, "jti-xyz", "client-A", expires).await;
    let b2 = store_jwt_assertion_jti(&store, "jti-xyz", "client-B", expires).await;
    let c2 = store_jwt_assertion_jti(&store, "jti-pqr", "client-A", expires).await;
    assert!(matches!(a2, Err(ClaimError::AlreadyConsumed)));
    assert!(matches!(b2, Err(ClaimError::AlreadyConsumed)));
    assert!(matches!(c2, Err(ClaimError::AlreadyConsumed)));
}

#[tokio::test]
async fn test_delete_expired_jwt_assertion_jtis() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let past_expires: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let future_expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // Insert one expired and one valid JTI
    let _expired_claim = store_jwt_assertion_jti(&store, "expired-jti", "c1", past_expires)
        .await
        .expect("insert expired");
    let _valid_claim = store_jwt_assertion_jti(&store, "valid-jti", "c1", future_expires)
        .await
        .expect("insert valid");

    let deleted = delete_expired_jwt_assertion_jtis(&store)
        .await
        .expect("delete_expired should not error");
    assert!(deleted >= 1, "Should delete at least the expired JTI");

    // The valid one is still in place — replay returns AlreadyConsumed
    let still_stored = store_jwt_assertion_jti(&store, "valid-jti", "c1", future_expires).await;
    assert!(
        matches!(still_stored, Err(ClaimError::AlreadyConsumed)),
        "Valid JTI should still block replay: got {still_stored:?}"
    );

    // The expired one was deleted and can be reused
    let _reused = store_jwt_assertion_jti(&store, "expired-jti", "c1", future_expires)
        .await
        .expect("Expired+deleted JTI should be accepted again after cleanup");
}

// ========================================================================
// DPoP JTI replay prevention
// ========================================================================

#[tokio::test]
async fn test_dpop_jti_replay_prevention() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // First use returns the witness
    let _claim = check_and_store_dpop_jti(&store, "dpop-jti-1", 600)
        .await
        .expect("First use of a JTI should be accepted");

    // Replay returns AlreadyConsumed
    let replayed = check_and_store_dpop_jti(&store, "dpop-jti-1", 600).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of same JTI should be AlreadyConsumed, got: {replayed:?}"
    );

    // Different JTI succeeds
    let _different = check_and_store_dpop_jti(&store, "dpop-jti-2", 600)
        .await
        .expect("Different JTI should be accepted");
}

#[tokio::test]
async fn test_dpop_jti_empty() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let result = check_and_store_dpop_jti(&store, "", 600).await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "Empty JTI must return InvalidInput, got: {result:?}"
    );
}

#[tokio::test]
async fn test_dpop_jti_too_long() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let long_jti = "x".repeat(257);
    let result = check_and_store_dpop_jti(&store, &long_jti, 600).await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "JTI exceeding max length must return InvalidInput, got: {result:?}"
    );
}

#[tokio::test]
async fn test_dpop_jti_at_max_length() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let max_jti = "d".repeat(256);
    let _stored = check_and_store_dpop_jti(&store, &max_jti, 600)
        .await
        .expect("JTI at max length should be accepted");

    let replayed = check_and_store_dpop_jti(&store, &max_jti, 600).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of max-length JTI should be AlreadyConsumed, got: {replayed:?}"
    );
}

#[tokio::test]
async fn test_dpop_jti_concurrent_insert_rejects_duplicates() {
    let (store, _audit) = test_db().await;
    let store = Arc::new(store);

    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);

    for _ in 0..num_tasks {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            check_and_store_dpop_jti(&s, "same-jti", 600).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        if result.is_ok() {
            successes += 1;
        }
    }

    assert_eq!(
        successes, 1,
        "Exactly one concurrent insert should succeed, got {successes}"
    );
}

#[tokio::test]
async fn test_delete_expired_dpop_jtis() {
    let (store, _audit) = test_db().await;

    // Insert one with past expiry (validity_seconds=0 won't work since
    // it computes from now; instead insert directly with short validity
    // and rely on the fact that we can test cleanup.)
    let _valid = check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600)
        .await
        .expect("insert valid");

    // Cleanup should not delete the valid one
    let deleted = delete_expired_dpop_jtis(&store, "")
        .await
        .expect("delete_expired should not error");
    assert_eq!(deleted, 0, "No expired JTIs to delete");

    // The valid one should still block replay
    use crate::db::claim::ClaimError;
    let result = check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600).await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "Valid JTI should still block replay, got: {result:?}"
    );
}
