// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRUD round-trip tests for the posture-policy DB layer
//! (`crates/vouch-server/src/db/posture_policies.rs`).
//!
//! Covers preconfigured-policy activation, custom policy create/list/get
//! /update/delete, and org-scoped isolation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use vouch_server::db::{self, CreateCustomPolicyParams, FieldUpdate, UpdateCustomPolicyParams};
use vouch_tests::TestHarness;

async fn fresh_org_id(harness: &TestHarness, domain: &str) -> String {
    harness.create_org(domain).await.expect("create org").id
}

// ============================================================================
// Preconfigured policy activation
// ============================================================================

#[tokio::test]
async fn preconfigured_active_starts_empty() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "preconfigured-empty.example").await;

    let slugs = db::get_active_preconfigured_slugs(&harness.state.store, &org_id)
        .await
        .expect("get slugs");
    assert!(slugs.is_empty());
}

#[tokio::test]
async fn preconfigured_active_set_then_get_roundtrip() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "preconfigured-set.example").await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string(), "screen-lock".to_string()],
    )
    .await
    .expect("set active");

    let slugs = db::get_active_preconfigured_slugs(&harness.state.store, &org_id)
        .await
        .expect("get slugs");
    assert_eq!(slugs, vec!["disk-encryption", "screen-lock"]);
}

#[tokio::test]
async fn preconfigured_active_overwrites_previous() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "preconfigured-overwrite.example").await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["first".to_string(), "second".to_string()],
    )
    .await
    .expect("set initial");

    // A second call should replace the slug list outright, not merge it.
    db::set_preconfigured_active(&harness.state.store, &org_id, vec!["third".to_string()])
        .await
        .expect("set replacement");

    let slugs = db::get_active_preconfigured_slugs(&harness.state.store, &org_id)
        .await
        .expect("get slugs");
    assert_eq!(slugs, vec!["third"]);
}

// ============================================================================
// Custom posture policies
// ============================================================================

#[tokio::test]
async fn custom_policy_create_defaults_to_inactive() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "custom-inactive.example").await;

    let policy = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "Require macOS",
            description: Some("Block non-mac platforms"),
            policy_text: "device.platform == 'mac'",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create policy");

    assert_eq!(policy.name, "Require macOS");
    assert_eq!(
        policy.description.as_deref(),
        Some("Block non-mac platforms")
    );
    assert_eq!(policy.policy_text, "device.platform == 'mac'");
    assert!(!policy.active, "new policies must default to inactive");
    assert_eq!(policy.org_id, org_id);
}

#[tokio::test]
async fn custom_policy_list_is_scoped_to_org() {
    let harness = TestHarness::new().await;
    let org_a = fresh_org_id(&harness, "scope-a.example").await;
    let org_b = fresh_org_id(&harness, "scope-b.example").await;

    db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "A1",
            description: None,
            policy_text: "true",
            org_id: &org_a,
            builder_spec: None,
        },
    )
    .await
    .expect("create A1");
    db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "B1",
            description: None,
            policy_text: "true",
            org_id: &org_b,
            builder_spec: None,
        },
    )
    .await
    .expect("create B1");

    let list_a = db::list_custom_policies(&harness.state.store, &org_a)
        .await
        .expect("list a");
    let list_b = db::list_custom_policies(&harness.state.store, &org_b)
        .await
        .expect("list b");

    assert_eq!(list_a.len(), 1);
    assert_eq!(list_a[0].name, "A1");
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_b[0].name, "B1");
}

#[tokio::test]
async fn custom_policy_get_returns_record() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "get-policy.example").await;
    let created = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "Lookup test",
            description: None,
            policy_text: "true",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create");

    let fetched = db::get_custom_policy(&harness.state.store, &created.id)
        .await
        .expect("get")
        .expect("policy exists");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, "Lookup test");
}

#[tokio::test]
async fn custom_policy_get_returns_none_for_unknown_id() {
    let harness = TestHarness::new().await;
    let fetched = db::get_custom_policy(&harness.state.store, "does-not-exist")
        .await
        .expect("get");
    assert!(fetched.is_none());
}

#[tokio::test]
async fn custom_policy_update_can_activate_and_rename() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "update-policy.example").await;
    let created = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "old name",
            description: Some("old desc"),
            policy_text: "true",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create");

    let updated = db::update_custom_policy(
        &harness.state.store,
        &created.id,
        &org_id,
        UpdateCustomPolicyParams {
            name: Some("new name"),
            description: FieldUpdate::Clear,
            policy_text: Some("device.os_version >= '14'"),
            active: Some(true),
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update")
    .expect("policy returned");

    assert_eq!(updated.name, "new name");
    assert!(
        updated.description.is_none(),
        "description should be cleared"
    );
    assert_eq!(updated.policy_text, "device.os_version >= '14'");
    assert!(updated.active);
}

#[tokio::test]
async fn custom_policy_update_refuses_cross_org_writes() {
    let harness = TestHarness::new().await;
    let org_a = fresh_org_id(&harness, "cross-update-a.example").await;
    let org_b = fresh_org_id(&harness, "cross-update-b.example").await;
    let created = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "owned by A",
            description: None,
            policy_text: "true",
            org_id: &org_a,
            builder_spec: None,
        },
    )
    .await
    .expect("create");

    let attempted = db::update_custom_policy(
        &harness.state.store,
        &created.id,
        &org_b, // wrong org
        UpdateCustomPolicyParams {
            name: Some("hijacked"),
            description: FieldUpdate::Keep,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update call");
    assert!(
        attempted.is_none(),
        "wrong-org update must report not-found, got {attempted:?}"
    );

    let unchanged = db::get_custom_policy(&harness.state.store, &created.id)
        .await
        .expect("get")
        .expect("policy exists");
    assert_eq!(unchanged.name, "owned by A");
}

#[tokio::test]
async fn custom_policy_delete_removes_record() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "delete-policy.example").await;
    let created = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "ephemeral",
            description: None,
            policy_text: "true",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create");

    let removed = db::delete_custom_policy(&harness.state.store, &created.id, &org_id)
        .await
        .expect("delete");
    assert!(removed);

    let fetched = db::get_custom_policy(&harness.state.store, &created.id)
        .await
        .expect("get");
    assert!(fetched.is_none(), "deleted policy must not be retrievable");
}

#[tokio::test]
async fn custom_policy_delete_refuses_cross_org() {
    let harness = TestHarness::new().await;
    let org_a = fresh_org_id(&harness, "cross-delete-a.example").await;
    let org_b = fresh_org_id(&harness, "cross-delete-b.example").await;
    let created = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "owned by A",
            description: None,
            policy_text: "true",
            org_id: &org_a,
            builder_spec: None,
        },
    )
    .await
    .expect("create");

    let removed = db::delete_custom_policy(&harness.state.store, &created.id, &org_b)
        .await
        .expect("delete call");
    assert!(!removed, "wrong-org delete must report not-found");

    let still_there = db::get_custom_policy(&harness.state.store, &created.id)
        .await
        .expect("get");
    assert!(
        still_there.is_some(),
        "policy must survive cross-org delete"
    );
}

#[tokio::test]
async fn custom_policy_delete_unknown_id_returns_false() {
    let harness = TestHarness::new().await;
    let removed = db::delete_custom_policy(&harness.state.store, "nope", "any-org")
        .await
        .expect("delete");
    assert!(!removed);
}

#[tokio::test]
async fn get_active_custom_policies_filters_by_flag() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "active-filter.example").await;

    let inactive = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "off",
            description: None,
            policy_text: "true",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create inactive");
    let active = db::create_custom_policy(
        &harness.state.store,
        CreateCustomPolicyParams {
            name: "on",
            description: None,
            policy_text: "true",
            org_id: &org_id,
            builder_spec: None,
        },
    )
    .await
    .expect("create soon-to-be active");
    db::update_custom_policy(
        &harness.state.store,
        &active.id,
        &org_id,
        UpdateCustomPolicyParams {
            name: None,
            description: FieldUpdate::Keep,
            policy_text: None,
            active: Some(true),
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("activate")
    .expect("returned");

    let actives = db::get_active_custom_policies(&harness.state.store, &org_id)
        .await
        .expect("get actives");
    assert_eq!(actives.len(), 1);
    assert_eq!(actives[0].id, active.id);
    assert_ne!(actives[0].id, inactive.id);
}
