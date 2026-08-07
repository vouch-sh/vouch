// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DocumentStore behaviors not covered by `db/store.rs` unit tests.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// DocumentStore — gaps in store.rs tests
// ========================================================================

#[tokio::test]
async fn test_store_get_many_empty_slice() {
    let (store, _audit) = test_db().await;

    // get_many with an empty id slice must return an empty vec, not error
    let result = store
        .list_all::<crate::db::documents::user::UserDoc>()
        .await
        .expect("list_all should succeed");
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_store_count_zero_for_no_matches() {
    let (store, _audit) = test_db().await;

    // Newly-initialised DB has no sessions; count should be 0
    let count = store
        .count::<crate::db::documents::session::SessionDoc>("token_hash", "nonexistent")
        .await
        .expect("count should not error");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_store_delete_cleans_up_indexes() {
    let (store, _audit) = test_db().await;

    // Create a user so we have something with index entries
    let (user_id, _) = upsert_user(&store, "index-cleanup@example.com", None)
        .await
        .expect("upsert failed");

    // The document is findable by its email index
    let found = get_user_by_email(&store, "index-cleanup@example.com")
        .await
        .expect("query failed");
    assert!(found.is_some());

    // Delete the document
    delete_user(&store, &user_id).await.expect("delete failed");

    // Document is gone
    assert!(
        get_user_by_id(&store, &user_id)
            .await
            .expect("query failed")
            .is_none()
    );

    // Index entry is also gone: find_one should return None
    let found_after = get_user_by_email(&store, "index-cleanup@example.com")
        .await
        .expect("query failed");
    assert!(
        found_after.is_none(),
        "index entry should be deleted with the document"
    );
}

#[tokio::test]
async fn test_store_delete_expired_cleans_up_indexes() {
    let (store, _audit) = test_db().await;

    // Create a device-auth request with a past expiry (expired)
    let id = create_device_auth_request(
        &store,
        "expired-code-hash",
        "EXPR-0001",
        None,
        "2020-01-01T00:00:00Z".parse().unwrap(), // past
        5,
    )
    .await
    .expect("create failed");

    // Confirm it is findable by its user-code index
    let found = get_device_auth_by_user_code(&store, "EXPR-0001")
        .await
        .expect("query failed");
    assert!(found.is_some());

    // Run the cleanup
    let now_str = jiff::Timestamp::now().to_string();
    let deleted = delete_expired_device_auth_requests(&store, &now_str)
        .await
        .expect("cleanup failed");
    assert!(deleted >= 1);

    // Now the document should be gone
    assert!(
        get_device_auth_by_id(&store, &id)
            .await
            .expect("query failed")
            .is_none()
    );

    // And the index entry should also be gone
    let found_after = get_device_auth_by_user_code(&store, "EXPR-0001")
        .await
        .expect("query failed");
    assert!(
        found_after.is_none(),
        "index entry should be cleaned up after delete_expired"
    );
}
