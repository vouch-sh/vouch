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
        Some("Platform"),
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
