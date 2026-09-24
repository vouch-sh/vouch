// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM group lifecycle and membership.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM groups — full lifecycle
// ========================================================================

#[tokio::test]
async fn test_scim_group_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create
    let group = create_scim_group(&store, TEST_ORG_ID, "Engineering", Some("ext-grp-1"), &[])
        .await
        .expect("create_scim_group failed");
    assert!(!group.id.is_empty());
    assert_eq!(group.display_name, "Engineering");
    assert_eq!(group.external_id.as_deref(), Some("ext-grp-1"));

    // Get by ID
    let fetched = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group failed")
        .expect("group should exist");
    assert_eq!(fetched.display_name, "Engineering");

    // Update
    let _ = update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        set_group_attributes("Platform", Some("ext-grp-2")),
    )
    .await
    .expect("update_scim_group failed");
    let updated = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group failed")
        .expect("group should still exist");
    assert_eq!(updated.display_name, "Platform");
    assert_eq!(updated.external_id.as_deref(), Some("ext-grp-2"));

    // List
    let (groups, total) = list_scim_groups(&store, TEST_ORG_ID, None, 1, 100)
        .await
        .expect("list_scim_groups failed");
    assert_eq!(groups.len(), 1);
    assert_eq!(total, 1);

    // Delete
    let deleted = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete_scim_group failed");
    assert!(deleted);

    // Gone
    let missing = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("query should succeed");
    assert!(missing.is_none());

    // Delete again returns false
    let deleted_again = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete should not error");
    assert!(!deleted_again);
}

#[tokio::test]
async fn test_scim_group_members_update_writes_only_the_difference() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let mut users = Vec::new();
    for email in ["u1@example.com", "u2@example.com", "u3@example.com"] {
        let user = create_scim_user(&store, Some(TEST_ORG_ID), email, None, None, true)
            .await
            .expect("create user");
        users.push(user.id);
    }
    let group = create_scim_group(
        &store,
        TEST_ORG_ID,
        "Gamma",
        None,
        &[users[0].clone(), users[1].clone(), users[0].clone()],
    )
    .await
    .expect("create group");
    let docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("member docs");
    assert_eq!(docs.len(), 2, "a repeated member is stored once");
    let kept_id = docs
        .iter()
        .find(|doc| doc.data.user_id == users[1])
        .map(|doc| doc.id.clone())
        .expect("u2 row");

    let applied = update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        set_group_members(&[&users[1], &users[2]]),
    )
    .await
    .expect("replace members");
    assert!(applied);

    let docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("member docs");
    let mut member_ids: Vec<&str> = docs.iter().map(|doc| doc.data.user_id.as_str()).collect();
    member_ids.sort_unstable();
    let mut expected = vec![users[1].as_str(), users[2].as_str()];
    expected.sort_unstable();
    assert_eq!(member_ids, expected);
    assert!(
        docs.iter().any(|doc| doc.id == kept_id),
        "a member present before and after keeps its row"
    );

    let applied = update_scim_group(&store, &group.id, TEST_ORG_ID, set_group_members(&[]))
        .await
        .expect("clear members");
    assert!(applied);
    let empty = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert!(empty.is_empty());
}

// RFC 7644 §3.5.2: "A PATCH request, regardless of the number of operations,
// SHALL be treated as atomic. If a single operation encounters an error
// condition, the original SCIM resource MUST be restored".
#[tokio::test]
async fn test_update_scim_group_rejected_edit_writes_nothing() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "keep@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");
    let group = create_scim_group(
        &store,
        TEST_ORG_ID,
        "Stable",
        Some("ext"),
        std::slice::from_ref(&user.id),
    )
    .await
    .expect("create group");

    let result = update_scim_group(&store, &group.id, TEST_ORG_ID, |state| {
        state.display_name = "Changed".to_string();
        state.members.clear();
        Err("rejected after editing")
    })
    .await;
    assert!(matches!(
        result,
        Err(ScimGroupUpdateError::Rejected("rejected after editing"))
    ));

    let stored = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get group")
        .expect("group exists");
    assert_eq!(stored.display_name, "Stable");
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(members.len(), 1, "membership is untouched");
}

// RFC 7644 §3.5.2.1: adding a value already present "SHALL NOT change the
// modify timestamp of the resource".
#[tokio::test]
async fn test_update_scim_group_without_changes_keeps_last_modified() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "same@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");
    let group = create_scim_group(
        &store,
        TEST_ORG_ID,
        "Same",
        None,
        std::slice::from_ref(&user.id),
    )
    .await
    .expect("create group");

    let applied = update_scim_group(&store, &group.id, TEST_ORG_ID, |state| {
        state.members.insert(user.id.clone());
        Ok::<(), std::convert::Infallible>(())
    })
    .await
    .expect("no-op update");
    assert!(applied);

    let stored = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get group")
        .expect("group exists");
    assert_eq!(stored.updated_at, group.updated_at);
}

#[tokio::test]
async fn test_create_scim_group_failed_member_insert_creates_nothing() {
    // The group and its members commit together: a member id the store
    // rejects must not leave a group behind for a retried POST to duplicate.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let result = create_scim_group(
        &store,
        TEST_ORG_ID,
        "Orphan",
        None,
        &["bad\u{0}member".to_string()],
    )
    .await;
    assert!(result.is_err());

    let (groups, total) = list_scim_groups(&store, TEST_ORG_ID, None, 1, 100)
        .await
        .expect("list groups");
    assert_eq!(total, 0, "no group was created: {groups:?}");
}

#[tokio::test]
async fn test_scim_group_delete_cascades_members() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "cascade-member@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");
    let group = create_scim_group(
        &store,
        TEST_ORG_ID,
        "ToBeCascaded",
        None,
        std::slice::from_ref(&user.id),
    )
    .await
    .expect("create group");

    // Delete the group
    let _ = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete group");

    // User should still exist
    let user_exists = get_scim_user(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("query user");
    assert!(
        user_exists.is_some(),
        "user should not be deleted when group is deleted"
    );
}

#[tokio::test]
async fn test_scim_filter_group_external_id_co_is_case_sensitive() {
    // `externalId` is `caseExact: true` per RFC 7643 Section 3.1, so the
    // "co" operator must be case-sensitive for group externalId filters too
    // (RFC 7644 Section 3.4.2.2). Mirrors the user-side coverage.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Eng", Some("GroupCase-ID-1"), &[])
        .await
        .expect("Failed to create group");

    // Exact-case "co" matches.
    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"externalId co "GroupCase""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(total, 1, "exact-case co should match");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].external_id.as_deref(), Some("GroupCase-ID-1"));

    // Wrong-case "co" must NOT match.
    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"externalId co "groupcase""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(
        total, 0,
        "externalId is caseExact: lowercase co should not match"
    );
    assert!(groups.is_empty());
}

#[tokio::test]
async fn test_scim_filter_group_display_name_co_remains_case_insensitive() {
    // `displayName` is `caseExact: false` per RFC 7643, so "co" must stay
    // case-insensitive even though externalId matching is case-exact.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Engineering", None, &[])
        .await
        .expect("Failed to create group");

    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName co "ENGINEER""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(
        total, 1,
        "displayName is caseExact: false; co must stay case-insensitive"
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].display_name, "Engineering");
}

// ========================================================================
// SCIM group displayName eq — case-insensitive (RFC 7643 caseExact: false)
// ========================================================================

#[tokio::test]
async fn test_scim_filter_group_display_name_eq_is_case_insensitive() {
    // `displayName` is `caseExact: false` per RFC 7643 Section 8.7.2, so
    // `displayName eq` must be case-insensitive: a filter with different
    // casing than the stored value must still match.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Engineering", None, &[])
        .await
        .expect("Failed to create group");

    // Lowercase filter against a title-case group.
    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName eq "engineering""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(
        total, 1,
        "displayName eq must be case-insensitive per RFC 7643 caseExact: false"
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].display_name, "Engineering");
}

#[tokio::test]
async fn test_scim_filter_group_display_name_eq_matches_exact_and_uppercase() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Engineering", None, &[])
        .await
        .expect("Failed to create group");

    // Exact-case match (no regression of the previously-working path).
    let (_groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName eq "Engineering""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(total, 1, "exact-case eq must still match");

    // All-caps filter must also match.
    let (_groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName eq "ENGINEERING""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(total, 1, "uppercase eq must match");
}

#[tokio::test]
async fn test_scim_filter_group_display_name_eq_is_indexed_not_rescanned() {
    // An index row written before displayName normalization still carries its
    // original mixed-case value, so a lowercased indexed lookup misses it.
    // That is accepted rather than papered over: the row is re-stored
    // lowercased the next time the group is written through normal SCIM
    // create/update, matching the decision taken for the user path when the
    // same normalization landed there.
    //
    // The alternative — falling through to the unindexed scan on any miss —
    // is worse than the gap it closes. A miss is the normal case, since Okta
    // and Entra both query `displayName eq` to check whether a group exists
    // before creating it, so above the 10k `FilterTooBroad` threshold the
    // common provisioning path would return 400 instead of an empty list.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Engineering", None, &[])
        .await
        .expect("Failed to create group");

    // Simulate a pre-normalization index row.
    let crate::db::pool::Pool::Sqlite(pool) = store.pool() else {
        panic!("in-memory test DB must be SQLite");
    };
    sqlx::query(
        "UPDATE document_indexes SET index_value = ? \
         WHERE document_id = ? AND index_field = 'display_name'",
    )
    .bind("Engineering")
    .bind(&group.id)
    .execute(pool)
    .await
    .expect("rewrite display_name index to legacy mixed-case");

    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName eq "engineering""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");

    // An empty answer, not a rescan and not an error.
    assert_eq!(
        total, 0,
        "stale index row is not found by the indexed lookup"
    );
    assert!(groups.is_empty());

    // Any change re-writes the group and re-stores the index lowercased, so it
    // is findable again — which is what makes the gap self-healing rather
    // than permanent. An update that changes nothing writes nothing (RFC 7644
    // §3.5.2.1), so the repair waits for a real change.
    update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        set_group_attributes("Engineering", Some("ext-changed")),
    )
    .await
    .expect("Failed to update group");

    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"displayName eq "engineering""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(total, 1, "re-saved group is findable case-insensitively");
    assert_eq!(groups.len(), 1);
}

#[tokio::test]
async fn test_scim_filter_group_external_id_eq_is_case_sensitive() {
    // `externalId` is `caseExact: true` per RFC 7643 Section 3.1, so the
    // indexed `eq` lookup must stay case-sensitive — contrasting with
    // displayName, and matching the case-sensitive `co` coverage above.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Eng", Some("Ext-Case-1"), &[])
        .await
        .expect("Failed to create group");

    // Exact-case match.
    let (_groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"externalId eq "Ext-Case-1""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(total, 1, "exact-case externalId eq must match");

    // Wrong-case match must NOT match (case-sensitive).
    let (_groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(r#"externalId eq "ext-case-1""#)),
        1,
        100,
    )
    .await
    .expect("Failed to filter groups");
    assert_eq!(
        total, 0,
        "externalId is caseExact: true; lowercase eq must not match"
    );
}

// ========================================================================
// Concurrent membership addition — duplicate-prevention regression
// ========================================================================

/// Two concurrent member adds for the same group and user must produce
/// exactly one membership document, not two.
///
/// Concurrent updates collide on the group document's version and the loser
/// retries against the winner's membership, and the membership document ID is
/// derived from `(group_id, user_id)`, so no interleaving stores the pair
/// twice. In-memory SQLite serializes writers, so this is a real-scheduler
/// smoke test rather than a proof of the version bump.
///
/// Mirrors `test_create_scim_user_concurrent_same_email_produces_one_user`
/// (`scim_provisioning.rs`). Uses `multi_thread` for defensive OS-level
/// parallelism.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_member_add_concurrent_same_user() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "RaceGroup", None, &[])
        .await
        .expect("create_scim_group failed");
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "race-concurrent@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create_scim_user failed");

    let (r1, r2) = tokio::join!(
        update_scim_group(&store, &group.id, TEST_ORG_ID, add_group_member(&user.id)),
        update_scim_group(&store, &group.id, TEST_ORG_ID, add_group_member(&user.id)),
    );

    // Both calls must succeed: the second finds the member already present.
    let added1 = r1.expect("first the member add should not error");
    let added2 = r2.expect("second the member add should not error");
    assert!(
        added1,
        "first add should report success for an existing group"
    );
    assert!(
        added2,
        "second add should report success (idempotent) for an existing group"
    );

    // Exactly one membership document must exist for the (group, user) pair.
    let docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("find_all membership docs");
    assert_eq!(
        docs.len(),
        1,
        "exactly one membership document must exist, got {}",
        docs.len()
    );
    assert_eq!(docs[0].data.group_id, group.id);
    assert_eq!(docs[0].data.user_id, user.id);

    // The member must appear exactly once in the group's member list.
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group_members")
        .unwrap_or_default();
    assert_eq!(
        members.len(),
        1,
        "exactly one member must be returned, got {}",
        members.len()
    );
    assert_eq!(members[0].id, user.id);
}

/// High-contention variant: 20 concurrent member adds for the same group and
/// user must still produce exactly one membership document, and every call
/// returns `Ok(true)`.
///
/// Mirrors the 20-task burst in
/// `test_create_scim_user_concurrent_same_email_produces_one_user`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_member_add_concurrent_burst_same_user() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let group = create_scim_group(&store, TEST_ORG_ID, "BurstGroup", None, &[])
        .await
        .expect("create_scim_group failed");
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "burst-concurrent@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create_scim_user failed");

    let num_tasks = 20u32;
    let mut handles = Vec::with_capacity(usize::try_from(num_tasks).expect("num_tasks fits"));
    for _ in 0..num_tasks {
        let s = std::sync::Arc::clone(&store);
        let group_id = group.id.clone();
        let user_id = user.id.clone();
        handles.push(tokio::spawn(async move {
            update_scim_group(&s, &group_id, TEST_ORG_ID, add_group_member(&user_id)).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        let ok = result.expect("the member add should not error for an existing group");
        assert!(
            ok,
            "the member add should return Ok(true) for an existing group"
        );
        successes += 1;
    }

    // Every concurrent call returns Ok(true): the add is idempotent.
    assert_eq!(
        successes, num_tasks,
        "every concurrent add should return Ok(true); got {successes}"
    );

    // But only one membership document may exist.
    let docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("find_all membership docs");
    assert_eq!(
        docs.len(),
        1,
        "exactly one membership document must exist after burst, got {}",
        docs.len()
    );

    // Verify idempotent add after the burst still returns Ok(true) without
    // creating a duplicate.
    let added = update_scim_group(&store, &group.id, TEST_ORG_ID, add_group_member(&user.id))
        .await
        .expect("post-burst idempotent add");
    assert!(added, "idempotent add after burst should return Ok(true)");
    let docs_after = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("find_all after idempotent add");
    assert_eq!(
        docs_after.len(),
        1,
        "idempotent add must not create a duplicate, got {}",
        docs_after.len()
    );
}

/// Concurrent adds for *different* users in the same group must all land:
/// the loser of a version collision retries against the winner's membership
/// rather than overwriting it, and the deterministic ID produces no false
/// collisions between distinct `(group_id, user_id)` pairs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_member_add_concurrent_different_users() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let group = create_scim_group(&store, TEST_ORG_ID, "DistinctGroup", None, &[])
        .await
        .expect("create_scim_group failed");

    // Create 5 distinct users.
    let num_users = 5u32;
    let mut users = Vec::with_capacity(usize::try_from(num_users).expect("num_users fits"));
    for i in 0..num_users {
        let email = format!("distinct-{i}@example.com");
        let user = create_scim_user(&store, Some(TEST_ORG_ID), &email, None, None, true)
            .await
            .expect("create_scim_user");
        users.push(user);
    }

    // Add all 5 concurrently.
    let mut handles = Vec::with_capacity(users.len());
    for user in &users {
        let s = std::sync::Arc::clone(&store);
        let group_id = group.id.clone();
        let user_id = user.id.clone();
        handles.push(tokio::spawn(async move {
            update_scim_group(&s, &group_id, TEST_ORG_ID, add_group_member(&user_id)).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        let ok = result.expect("the member add should not error");
        assert!(ok, "add should succeed for a distinct user");
        successes += 1;
    }
    assert_eq!(
        successes, num_users,
        "all distinct-user adds should succeed; got {successes}"
    );

    // Exactly 5 membership documents, one per user — no false collisions.
    let docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", &group.id)
        .await
        .expect("find_all membership docs");
    assert_eq!(
        docs.len(),
        usize::try_from(num_users).expect("num_users fits"),
        "exactly {num_users} membership documents must exist, got {}",
        docs.len()
    );

    // All 5 members appear in the group's member list.
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group_members")
        .unwrap_or_default();
    assert_eq!(
        members.len(),
        usize::try_from(num_users).expect("num_users fits"),
        "all {num_users} members must appear, got {}",
        members.len()
    );
}

// ========================================================================
// displayName index normalization (case-insensitive storage)
// ========================================================================

/// Read the raw `display_name` index value for a group directly from
/// `document_indexes` (SQLite in-memory, plaintext crypto).
async fn read_display_name_index(store: &DocumentStore, group_id: &str) -> String {
    let crate::db::pool::Pool::Sqlite(p) = store.pool() else {
        panic!("expected SQLite pool");
    };
    let row: (String,) =
        sqlx::query_as("SELECT index_value FROM document_indexes WHERE document_id = $1 AND index_field = 'display_name'")
            .bind(group_id)
            .fetch_one(p)
            .await
            .expect("fetch display_name index row");
    row.0
}

#[tokio::test]
async fn test_scim_group_display_name_index_is_lowercased() {
    // `displayName` is `caseExact: false` per RFC 7643, so the blind-index
    // value is stored ASCII-lowercased — mirroring how `UserDoc` stores the
    // `email` index through the canonicalizing `Email` type. The document
    // body preserves the original casing for display.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Engineering", None, &[])
        .await
        .expect("create group");

    let idx = read_display_name_index(&store, &group.id).await;
    assert_eq!(
        idx, "engineering",
        "display_name index must be ASCII-lowercased"
    );
    let fetched = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get group")
        .expect("group exists");
    assert_eq!(fetched.display_name, "Engineering", "body preserves casing");
}
