// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM group lifecycle and membership.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
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
    let group = create_scim_group(&store, TEST_ORG_ID, "Engineering", Some("ext-grp-1"))
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
        "Platform",
        Some("ext-grp-2"),
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
async fn test_scim_group_member_add_remove() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Beta", None)
        .await
        .expect("create group");
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "member@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");

    // Add member
    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("add_scim_group_member failed");

    // Member appears in group
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group_members failed")
        .unwrap_or_default();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, user.id);

    // Add again is idempotent
    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("idempotent add failed");
    let members_after = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(
        members_after.len(),
        1,
        "idempotent add should not duplicate"
    );

    // Remove member
    let removed = remove_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("remove_scim_group_member failed");
    assert!(removed);

    // Group is now empty
    let members_final = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members after remove")
        .unwrap_or_default();
    assert!(members_final.is_empty());

    // Remove again returns false
    let removed_again = remove_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("remove should not error");
    assert!(!removed_again);
}

#[tokio::test]
async fn test_scim_group_replace_members() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Gamma", None)
        .await
        .expect("create group");
    let user1 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u1@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user1");
    let user2 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u2@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user2");
    let user3 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u3@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user3");

    // Start with user1 and user2
    let _ = replace_scim_group_members(
        &store,
        &group.id,
        TEST_ORG_ID,
        &[user1.id.clone(), user2.id.clone()],
    )
    .await
    .expect("replace members");
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(members.len(), 2);

    // Replace with just user3
    let _ = replace_scim_group_members(
        &store,
        &group.id,
        TEST_ORG_ID,
        std::slice::from_ref(&user3.id),
    )
    .await
    .expect("replace members");
    let members_after = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(members_after.len(), 1);
    assert_eq!(members_after[0].id, user3.id);

    // Replace with empty list
    let _ = replace_scim_group_members(&store, &group.id, TEST_ORG_ID, &[])
        .await
        .expect("replace with empty");
    let empty = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_scim_group_delete_cascades_members() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "ToBeCascaded", None)
        .await
        .expect("create group");
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

    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("add member");

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

    create_scim_group(&store, TEST_ORG_ID, "Eng", Some("GroupCase-ID-1"))
        .await
        .expect("Failed to create group");

    // Exact-case "co" matches.
    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId co "GroupCase""#),
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
        Some(r#"externalId co "groupcase""#),
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
    // case-insensitive. Guards against the fix being over-applied.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_group(&store, TEST_ORG_ID, "Engineering", None)
        .await
        .expect("Failed to create group");

    let (groups, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(r#"displayName co "ENGINEER""#),
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
// Concurrent membership addition — duplicate-prevention regression
// ========================================================================

/// Regression for the SCIM group-member concurrent-add race: two concurrent
/// `add_scim_group_member` calls for the same group and user must produce
/// exactly one membership document, not two.
///
/// Before the deterministic-ID fix, each call generated a fresh random UUID
/// v7 primary key via `store.insert`, so neither insert conflicted with the
/// other and both committed — producing duplicate membership rows. The fix
/// derives the document ID from `(group_id, user_id)` via
/// `deterministic_group_member_id`, so the two inserts collide on the
/// `documents` PRIMARY KEY. The losing insert fails with a unique/primary-key
/// violation, which `is_unique_violation` maps to idempotent success
/// (`Ok(true)`).
///
/// Mirrors `test_create_scim_user_concurrent_same_email_produces_one_user`
/// (`scim_provisioning.rs`). Uses `multi_thread` for defensive OS-level
/// parallelism.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_scim_group_member_concurrent_same_user() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let group = create_scim_group(&store, TEST_ORG_ID, "RaceGroup", None)
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
        add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id),
        add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id),
    );

    // Both calls must succeed — the operation is idempotent, so the unique
    // violation on the losing insert is mapped to Ok(true).
    let added1 = r1.expect("first add_scim_group_member should not error");
    let added2 = r2.expect("second add_scim_group_member should not error");
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

/// High-contention variant: 20 concurrent `add_scim_group_member` calls for
/// the same group and user must still produce exactly one membership
/// document. Every call returns `Ok(true)` — the winner inserts, and every
/// loser's `insert_with_id` fails with a unique violation that is mapped to
/// idempotent success.
///
/// Mirrors the 20-task burst in
/// `test_create_scim_user_concurrent_same_email_produces_one_user`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_scim_group_member_concurrent_burst_same_user() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let group = create_scim_group(&store, TEST_ORG_ID, "BurstGroup", None)
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
            add_scim_group_member(&s, &group_id, TEST_ORG_ID, &user_id).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        let ok = result.expect("add_scim_group_member should not error for an existing group");
        assert!(
            ok,
            "add_scim_group_member should return Ok(true) for an existing group"
        );
        successes += 1;
    }

    // Every concurrent call returns Ok(true) — the operation is idempotent,
    // so both the winning insert and every losing unique-violation are mapped
    // to success.
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
    let added = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
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

/// Concurrent adds for *different* users in the same group must all succeed
/// independently — the deterministic ID must not produce false collisions
/// between distinct `(group_id, user_id)` pairs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_scim_group_member_concurrent_different_users() {
    use crate::db::documents::scim::ScimGroupMemberDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let group = create_scim_group(&store, TEST_ORG_ID, "DistinctGroup", None)
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
            add_scim_group_member(&s, &group_id, TEST_ORG_ID, &user_id).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        let ok = result.expect("add_scim_group_member should not error");
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
