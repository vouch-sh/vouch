// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth client secret cap/floor OCC invariants.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ============================================================================
// OAuth secret cap (≤2) / floor (≥1) OCC invariant tests (#551)
// ============================================================================

/// 4 concurrent adds → exactly 2 `Ok`, rest `409 max_secrets_reached`.
/// Mirrors `test_update_authenticator_counter_high_concurrency_no_lost_update`.
/// Uses multi_thread for defensive OS-level parallelism; busy_timeout waits happen
/// inside sqlx-sqlite's dedicated OS thread and do not block tokio worker threads,
/// so a single-thread runtime would also work correctly here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_secret_add_never_exceeds_two() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    let handles: Vec<_> = (0_u8..4)
        .map(|i| {
            let store = store.clone();
            let app_id = app_id.clone();
            tokio::spawn(async move {
                create_oauth_client_secret(
                    &store,
                    &app_id,
                    &format!("hash_concurrent_{i}"),
                    None,
                    None,
                )
                .await
            })
        })
        .collect();

    let mut ok_count: usize = 0;
    let mut max_reached_count: usize = 0;
    for h in handles {
        match h.await.expect("task must not panic") {
            Ok(_) => ok_count = ok_count.saturating_add(1),
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "max_secrets_reached" =>
            {
                max_reached_count = max_reached_count.saturating_add(1);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(ok_count, 2, "exactly 2 adds must succeed");
    assert_eq!(max_reached_count, 2, "exactly 2 adds must be rejected");

    // Verify at the DB level.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(active, 2, "exactly 2 active secrets must exist");
}

/// Regression for #744: 4 concurrent SCIM token creates → exactly 2 `Ok`, rest
/// `409 token_limit_reached`. Counting in the handler and inserting afterwards
/// let every concurrent request pass the check; the count now happens inside the
/// insert's transaction, with the organization document's version as the
/// serialization point. Mirrors `test_concurrent_secret_add_never_exceeds_two`.
///
/// Scope note: this runs on SQLite, which serializes writers, so moving the
/// count inside the transaction is by itself sufficient here — the test still
/// passes if the `compare_and_update` version guard is removed. That guard
/// exists for PostgreSQL and DSQL, where two transactions can read the same
/// snapshot and neither conflicts on a predicate read. Proving it therefore
/// requires a snapshot-isolated backend, not this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_scim_token_create_never_exceeds_two() {
    use crate::db::create_scim_token;

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "scim-cap.example", Some("Cap Org"), None)
        .await
        .expect("create org");

    let handles: Vec<_> = (0_u8..4)
        .map(|i| {
            let store = store.clone();
            let org_id = org.id.clone();
            tokio::spawn(async move {
                create_scim_token(
                    &store,
                    &CreateScimTokenParams {
                        org_id: &org_id,
                        token_hash: &format!("scim_hash_{i}"),
                        description: None,
                        expires_at: None,
                        scope: ScimScopeSet::default(),
                    },
                )
                .await
            })
        })
        .collect();

    let mut ok_count: usize = 0;
    let mut limit_count: usize = 0;
    for h in handles {
        match h.await.expect("task must not panic") {
            Ok(_) => ok_count = ok_count.saturating_add(1),
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "token_limit_reached" =>
            {
                limit_count = limit_count.saturating_add(1);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(ok_count, 2, "exactly 2 creates must succeed");
    assert_eq!(limit_count, 2, "exactly 2 creates must be rejected");

    // Verify at the DB level — the cap must hold in storage, not just in the
    // return values. None of these carry an expiry, so every stored row counts.
    let stored = list_scim_tokens(&store, Some(&org.id))
        .await
        .expect("list tokens");
    assert_eq!(stored.len(), 2, "exactly 2 SCIM tokens must be stored");
}

/// Seed 2 active secrets, 4 concurrent revokes → at least 1 active always remains.
/// Uses multi_thread for defensive OS-level parallelism (see add test for rationale).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_secret_revoke_never_drops_below_one() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // Seed exactly 2 active secrets.
    let s1 = create_oauth_client_secret(&store, &app_id, "hash_s1", None, None)
        .await
        .expect("seed s1");
    let s2 = create_oauth_client_secret(&store, &app_id, "hash_s2", None, None)
        .await
        .expect("seed s2");

    let secret_ids = [s1.id, s2.id];

    // 4 concurrent revoke attempts on s1 and s2 (two each).
    let handles: Vec<_> = secret_ids
        .iter()
        .flat_map(|sid| [sid.clone(), sid.clone()])
        .map(|sid| {
            let store = store.clone();
            let app_id = app_id.clone();
            tokio::spawn(async move { revoke_oauth_client_secret(&store, &sid, &app_id).await })
        })
        .collect();

    for h in handles {
        let result = h.await.expect("task must not panic");
        // Acceptable outcomes: Ok (revoked), last_secret (floor guard),
        // ServiceError::NotFound (already revoked — idempotent path),
        // or conflict (exhausted OCC budget).  Anything else is a bug.
        // Note: the already-revoked path returns ServiceError::NotFound, not
        // ServiceError::Api { code: "not_found" }, so there is no Api "not_found" arm.
        match result {
            Ok(()) => {}
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "last_secret" || code == "conflict" => {}
            Err(crate::error::ServiceError::NotFound(_)) => {}
            Err(e) => panic!("unexpected error from concurrent revoke: {e}"),
        }
    }

    // Invariant: at least 1 active secret must remain.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert!(
        active >= 1,
        "at least 1 active secret must remain; got {active}"
    );
}

/// Revoke 1 of 2, then add back to 2, confirming the cap counts `is_valid` not total rows.
#[tokio::test]
async fn test_revoke_then_add_back_to_two() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // Seed 2 active secrets.
    let s1 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s1", None, None)
        .await
        .expect("seed s1");
    let _s2 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s2", None, None)
        .await
        .expect("seed s2");

    // Revoke s1 (1 active remains).
    revoke_oauth_client_secret(&store, &s1.id, &app_id)
        .await
        .expect("revoke s1");

    // Now 1 active, 1 soft-deleted row.  A new add should succeed (not
    // triggered by the soft-deleted row's count).
    let _s3 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s3", None, None)
        .await
        .expect("add s3 after revoke");

    // Now 2 active (s2 + s3).  A further add must be rejected.
    let cap_result = create_oauth_client_secret(&store, &app_id, "hash_rtb_s4", None, None).await;
    assert!(
        matches!(
            cap_result,
            Err(crate::error::ServiceError::Api { ref code, .. }) if code == "max_secrets_reached"
        ),
        "third add must fail with max_secrets_reached; got: {cap_result:?}"
    );

    // Verify counts at DB level.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let total = secrets.len();
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(active, 2, "exactly 2 active secrets; got {active}");
    assert_eq!(
        total, 3,
        "3 total rows (1 soft-deleted, 2 active); got {total}"
    );
}

/// Revoking the sole active secret returns `Api(409 "last_secret")`.
/// Complements the handler-layer `test_delete_last_secret_rejected` with a
/// faster, db-level signal that the floor guard fires.
#[tokio::test]
async fn test_revoke_last_secret_rejected() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    let secret = create_oauth_client_secret(&store, &app_id, "hash_only_one", None, None)
        .await
        .expect("create sole secret");

    let result = revoke_oauth_client_secret(&store, &secret.id, &app_id).await;

    assert!(
        matches!(
            result,
            Err(crate::error::ServiceError::Api { ref code, .. }) if code == "last_secret"
        ),
        "revoking the last secret must fail with last_secret; got: {result:?}"
    );
}

/// Revoking an expired-but-unrevoked secret must succeed while another valid
/// secret remains: the floor counts *other* active secrets, not the target.
/// Without excluding the target, the expired row drops `active_count` to 1 and
/// the revoke is wrongly rejected with `last_secret` (#557).
#[tokio::test]
async fn test_revoke_expired_secret_allowed_when_valid_remains() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // One valid secret (no expiry) plus one expired-but-unrevoked secret.
    let _valid = create_oauth_client_secret(&store, &app_id, "hash_valid", None, None)
        .await
        .expect("create valid secret");
    let past: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let expired = create_oauth_client_secret(&store, &app_id, "hash_expired", None, Some(past))
        .await
        .expect("create expired secret");

    // Revoking the expired secret must be allowed — a valid secret still remains.
    revoke_oauth_client_secret(&store, &expired.id, &app_id)
        .await
        .expect("revoking an expired secret must succeed while a valid secret remains");

    // The valid secret is untouched and still active.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(
        active, 1,
        "the valid secret must remain active; got {active}"
    );
}
