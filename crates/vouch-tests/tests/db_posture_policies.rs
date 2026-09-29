// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRUD round-trip tests for the posture-policy DB layer
//! (`crates/vouch-server/src/db/posture_policies.rs`).
//!
//! Covers preconfigured-policy activation, custom policy create/list/get
//! /update/delete, and org-scoped isolation.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
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
// Preconfigured policy activation — optimistic-concurrency (OCC) update
// ============================================================================
//
// The admin toggle handler reads the slugs, mutates one, and writes the list
// back. To close the lost-update race where two concurrent toggles each derive
// from a stale read and the second write silently clobbers the first, the
// write is a single-shot `compare_and_update` guarded by the version captured
// at the read. These tests pin the OCC primitive directly: a matching version
// applies (and bumps the version), a stale version is rejected WITHOUT
// overwriting the concurrent winner, and the full-replace semantics the blind
// helper relies on are preserved.

#[tokio::test]
async fn get_preconfigured_active_with_version_returns_none_for_new_org() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "cfg-version-none.example").await;

    let cfg = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read config");
    assert!(cfg.is_none(), "no config exists for a brand-new org");
}

#[tokio::test]
async fn get_preconfigured_active_with_version_returns_id_version_and_slugs() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "cfg-version-roundtrip.example").await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string(), "firewall".to_string()],
    )
    .await
    .expect("seed");

    let cfg = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("config exists");
    assert!(!cfg.doc_id.is_empty(), "must expose the document id");
    assert_eq!(cfg.version, 1, "freshly inserted doc is at version 1");
    assert_eq!(cfg.active_slugs, vec!["disk-encryption", "firewall"]);
}

#[tokio::test]
async fn create_preconfigured_active_inserts_first_config() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "create-cfg.example").await;

    db::create_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["screen-lock".to_string()],
    )
    .await
    .expect("create");

    let cfg = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("config exists");
    assert_eq!(cfg.version, 1);
    assert_eq!(cfg.active_slugs, vec!["screen-lock"]);
}

#[tokio::test]
async fn concurrent_first_activation_creates_one_config_not_two() {
    // There is at most one PostureConfigDoc per org, but `org_id` is an
    // ordinary index, so nothing at the storage layer rejects a second one.
    // Two first activations racing each other both read no config and both
    // insert; the deterministic document ID is what makes the loser collide
    // on the primary key instead of creating a duplicate that
    // `get_posture_config`'s `find_one` would then resolve arbitrarily.
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "concurrent-first.example").await;

    let first = db::create_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string()],
    )
    .await
    .expect("first create");
    let second = db::create_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["firewall".to_string()],
    )
    .await
    .expect("second create must report the collision, not fail");

    assert!(first, "the first activation creates the config");
    assert!(
        !second,
        "the second must report that it lost, so the handler re-reads instead of \
         silently writing a duplicate"
    );

    // The loser's slugs were not applied, and exactly one config exists: a
    // duplicate would leave the winner's value reachable only by chance.
    let cfg = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("config exists");
    assert_eq!(cfg.active_slugs, vec!["disk-encryption"]);
    assert_eq!(cfg.version, 1, "the losing insert must not have bumped it");
}

#[tokio::test]
async fn compare_and_set_applies_when_version_matches_and_bumps_version() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "cas-match.example").await;

    // Seed at version 1 via the blind helper (authoritative full-replace).
    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string()],
    )
    .await
    .expect("seed");
    let cfg = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");

    let applied = db::compare_and_set_preconfigured_active(
        &harness.state.store,
        &cfg.doc_id,
        cfg.version,
        &org_id,
        vec!["disk-encryption".to_string(), "firewall".to_string()],
    )
    .await
    .expect("cas");
    assert!(applied, "a matching version must apply");

    let after = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(after.version, 2, "version must bump on apply");
    assert_eq!(after.active_slugs, vec!["disk-encryption", "firewall"]);
}

#[tokio::test]
async fn compare_and_set_rejects_stale_version_without_overwriting_winner() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "cas-stale.example").await;

    // Seed at version 1.
    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string()],
    )
    .await
    .expect("seed");
    let stale = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");

    // A concurrent admin's toggle commits first (version 1 → 2), e.g.
    // activating `screen-lock`. The blind helper re-reads and writes the
    // current version, simulating a writer that won the race.
    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["disk-encryption".to_string(), "screen-lock".to_string()],
    )
    .await
    .expect("concurrent winner");
    let after_winner = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(after_winner.version, 2);
    assert_eq!(
        after_winner.active_slugs,
        vec!["disk-encryption", "screen-lock"]
    );

    // The first reader now attempts its CAS with the stale version 1. Before
    // the fix this was a blind `store.update` that would have silently
    // overwritten the winner's `screen-lock` with `["disk-encryption",
    // "firewall"]`. It must instead be rejected and leave the winner intact.
    let applied = db::compare_and_set_preconfigured_active(
        &harness.state.store,
        &stale.doc_id,
        stale.version,
        &org_id,
        vec!["disk-encryption".to_string(), "firewall".to_string()],
    )
    .await
    .expect("cas");
    assert!(!applied, "a stale version must not apply");

    let final_state = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        final_state.version, 2,
        "a rejected CAS must not bump the version"
    );
    assert_eq!(
        final_state.active_slugs,
        vec!["disk-encryption", "screen-lock"],
        "a rejected CAS must not overwrite the concurrent winner"
    );
}

#[tokio::test]
async fn compare_and_set_preserves_full_replace_semantics_on_sequential_calls() {
    // Mirrors `preconfigured_active_overwrites_previous` but through the OCC
    // path: sequential (non-concurrent) calls never conflict, so the second
    // call's list replaces the first outright — confirming the OCC guard did
    // not turn full-replace into a merge.
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "cas-sequential.example").await;

    db::set_preconfigured_active(
        &harness.state.store,
        &org_id,
        vec!["first".to_string(), "second".to_string()],
    )
    .await
    .expect("seed first");
    let first = db::get_preconfigured_active_with_version(&harness.state.store, &org_id)
        .await
        .expect("read")
        .expect("exists");

    let applied = db::compare_and_set_preconfigured_active(
        &harness.state.store,
        &first.doc_id,
        first.version,
        &org_id,
        vec!["third".to_string()],
    )
    .await
    .expect("cas");
    assert!(applied, "sequential call must not conflict");

    let slugs = db::get_active_preconfigured_slugs(&harness.state.store, &org_id)
        .await
        .expect("get slugs");
    assert_eq!(slugs, vec!["third"], "second call must replace, not merge");
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
