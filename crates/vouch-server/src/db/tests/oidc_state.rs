// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream OIDC login state: lifecycle plus atomic consume / concurrent-replay coverage.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// OIDC State Tests
// ========================================================================

#[tokio::test]
async fn test_oidc_state_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create device auth request first (FK reference)
    let device_auth_id = create_device_auth_request(
        &store,
        "device_hash_for_oidc",
        "OIDC-1234",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("Failed to create device auth");

    // Create OIDC state
    let state = "random_state_12345";
    let nonce = "nonce_67890";
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();

    let id = create_oidc_state(
        &store,
        state,
        Some(&device_auth_id),
        nonce,
        "",
        expires_at,
        "",
    )
    .await
    .expect("Failed to create OIDC state");
    assert!(!id.is_empty());

    // Get OIDC state
    let oidc_state = get_oidc_state(&store, state)
        .await
        .expect("Failed to get OIDC state")
        .expect("Should exist");

    assert_eq!(oidc_state.state, state);
    assert_eq!(
        oidc_state.device_auth_id.as_deref(),
        Some(device_auth_id.as_str())
    );
    assert_eq!(oidc_state.nonce, nonce);
}

// ========================================================================
// OIDC state — atomic consume + concurrent-replay regression coverage
// ========================================================================

/// Seed a fresh OIDC state row tied to a fresh device-auth row.
async fn seed_oidc_state(
    store: &DocumentStore,
    state_value: &str,
    expires_at: jiff::Timestamp,
) -> String {
    let device_auth_id = create_device_auth_request(
        store,
        &format!("device_hash_for_{state_value}"),
        &format!("UC-{state_value}"),
        None,
        expires_at,
        5,
    )
    .await
    .expect("create_device_auth_request");

    create_oidc_state(
        store,
        state_value,
        Some(&device_auth_id),
        "nonce-value",
        "",
        expires_at,
        "",
    )
    .await
    .expect("create_oidc_state");

    device_auth_id
}

#[tokio::test]
async fn test_oidc_state_consume_happy_path() {
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_auth_id = seed_oidc_state(&store, "happy-state", expires_at).await;

    let (data, _claim) = try_consume_oidc_state(&store, "happy-state")
        .await
        .expect("first consume must succeed");

    assert_eq!(data.state, "happy-state");
    assert_eq!(
        data.device_auth_id.as_deref(),
        Some(device_auth_id.as_str())
    );
    assert_eq!(data.nonce, "nonce-value");
}

#[tokio::test]
async fn test_oidc_state_consume_replay_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    seed_oidc_state(&store, "replay-state", expires_at).await;

    let _first = try_consume_oidc_state(&store, "replay-state")
        .await
        .expect("first consume must succeed");

    let replayed = try_consume_oidc_state(&store, "replay-state").await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "second consume must be rejected as AlreadyConsumed, got: {replayed:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_expired_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    // Past expiry.
    let expires_at: jiff::Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
    seed_oidc_state(&store, "expired-state", expires_at).await;

    let result = try_consume_oidc_state(&store, "expired-state").await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "expired state must be reported as AlreadyConsumed (indistinguishable \
         from replay so the caller cannot probe state existence): got {result:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_not_found_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let result = try_consume_oidc_state(&store, "never-existed").await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "missing state must be reported as AlreadyConsumed: got {result:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    seed_oidc_state(&store, "race-state", expires_at).await;

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_oidc_state(&store_a, "race-state"),
        try_consume_oidc_state(&store_b, "race-state"),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one concurrent consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed (not Database), got: {e:?}"
            );
        }
    }
}
