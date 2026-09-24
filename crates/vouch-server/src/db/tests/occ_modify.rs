// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OCC read-modify-write conversions: every mutation path uses `store.modify`, not blind get+update.
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// OCC read-modify-write conversions: blind get+update → store.modify()
// ========================================================================

// ---- update_authenticator_name ----

/// After `update_authenticator_name`, only the `name` field changes; the
/// `credential_id`, `counter`, and other fields are untouched, and the
/// document version is incremented.
#[tokio::test]
async fn test_update_authenticator_name_only_name_changes() {
    use crate::db::documents::authenticator::AuthenticatorDoc;

    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "rename@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            name: "OldName",
            credential_id: b"cred-rename",
            public_key: &[1u8; 32],
            aaguid: Some("aaguid-rename"),
            user_handle: None,
            attestation_verified: true,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");

    let before = store
        .get::<AuthenticatorDoc>(&auth_id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_authenticator_name(&store, &auth_id, "NewName")
        .await
        .expect("update name");
    assert!(found, "update must report found=true");

    let after = store
        .get::<AuthenticatorDoc>(&auth_id)
        .await
        .expect("get after")
        .expect("must exist");

    assert_eq!(after.data.name, "NewName", "name must be updated");
    assert_eq!(
        after.data.credential_id, before.data.credential_id,
        "credential_id must be unchanged"
    );
    assert_eq!(
        after.data.counter, before.data.counter,
        "counter must be unchanged"
    );
    assert_eq!(
        after.data.aaguid, before.data.aaguid,
        "aaguid must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after update"
    );
}

/// `update_authenticator_name` on a non-existent authenticator returns `Ok(false)`.
#[tokio::test]
async fn test_update_authenticator_name_not_found() {
    let (store, _audit) = test_db().await;
    let found = update_authenticator_name(&store, "does-not-exist", "AnyName")
        .await
        .expect("query must not error");
    assert!(!found, "missing authenticator must return false");
}

// ---- suspend/unsuspend/update_github_installation_repos ----

/// Helper: create a minimal GitHub installation for tests.
pub(super) async fn create_test_github_installation(
    store: &DocumentStore,
    installation_id: i64,
    org_id: &str,
) -> String {
    create_github_installation(
        store,
        &CreateGitHubInstallationParams {
            org_id,
            installation_id,
            github_account_login: "test-account",
            github_account_type: "Organization",
            permissions: &std::collections::HashMap::new(),
            repository_selection: "all",
            installed_by_user_id: None,
        },
    )
    .await
    .expect("create_github_installation")
}

/// After `suspend_github_installation`, only `suspended_at` is set; other fields
/// are unchanged and the document version increments.
#[tokio::test]
async fn test_suspend_github_installation_only_suspended_at_changes() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_001, "org-suspend").await;

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before")
        .expect("must exist");
    assert!(
        before.data.suspended_at.is_none(),
        "fresh installation must not be suspended"
    );
    let version_before = before.version;

    let found = suspend_github_installation(&store, 10_001)
        .await
        .expect("suspend");
    assert!(found, "suspend must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert!(
        after.data.suspended_at.is_some(),
        "suspended_at must be set after suspend"
    );
    assert_eq!(
        after.data.installation_id, before.data.installation_id,
        "installation_id must be unchanged"
    );
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after suspend"
    );
}

/// After `unsuspend_github_installation`, `suspended_at` is cleared; version increments.
#[tokio::test]
async fn test_unsuspend_github_installation_only_suspended_at_changes() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_002, "org-unsuspend").await;

    // First suspend, then unsuspend.
    suspend_github_installation(&store, 10_002)
        .await
        .expect("suspend");

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before unsuspend")
        .expect("must exist");
    let version_before = before.version;

    let found = unsuspend_github_installation(&store, 10_002)
        .await
        .expect("unsuspend");
    assert!(found, "unsuspend must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after unsuspend")
        .expect("must exist");
    assert!(
        after.data.suspended_at.is_none(),
        "suspended_at must be cleared after unsuspend"
    );
    assert_eq!(
        after.data.installation_id, before.data.installation_id,
        "installation_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after unsuspend"
    );
}

/// After `update_github_installation_repos`, only `repositories` changes; version increments.
#[tokio::test]
async fn test_update_github_installation_repos_only_repos_change() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_003, "org-repos").await;

    let repos = vec!["owner/repo-a".to_string(), "owner/repo-b".to_string()];

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_github_installation_repos(&store, 10_003, &repos)
        .await
        .expect("update repos");
    assert!(found, "update must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.repositories.as_deref(),
        Some(repos.as_slice()),
        "repositories must be updated"
    );
    assert_eq!(
        after.data.suspended_at, before.data.suspended_at,
        "suspended_at must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after repo update"
    );
}

/// Concurrent suspend+unsuspend on the same installation converge without lost updates.
/// At least one write must win and be reflected in the final state.
#[tokio::test]
async fn test_github_installation_concurrent_suspend_unsuspend_no_lost_update() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_001, "org-concurrent-suspend").await;

    let store_a = store.clone();
    let store_b = store.clone();
    let handles: Vec<_> = [
        tokio::spawn(async move { suspend_github_installation(&store_a, 20_001).await }),
        tokio::spawn(async move { unsuspend_github_installation(&store_b, 20_001).await }),
    ]
    .into_iter()
    .collect();

    for h in handles {
        h.await
            .expect("task must not panic")
            .expect("operation must succeed");
    }

    // Smoke check: both concurrent writes complete without error, and the
    // record still exists with both increments applied (version ≥ 2). This does
    // not by itself distinguish OCC from a blind `store.update` — the blind path
    // also bumps the version unconditionally — so it only proves concurrent
    // access doesn't error or corrupt. The lost-update regression (a sibling
    // field being clobbered) is caught by the `*_only_*_changes` tests above.
    use crate::db::documents::github::GitHubInstallationDoc;
    let doc_after = store
        .get::<GitHubInstallationDoc>(&{
            let d = store
                .find_one::<GitHubInstallationDoc>("installation_id", "20001")
                .await
                .expect("find_one")
                .expect("must exist after concurrent writes");
            d.id
        })
        .await
        .expect("get after concurrent writes")
        .expect("installation must still exist after concurrent suspend/unsuspend");
    assert!(
        doc_after.version >= 2,
        "both concurrent writes must land (version ≥2); got version {}",
        doc_after.version
    );
}

/// Two concurrent delta updates with disjoint adds must both land: the merge
/// runs inside the `modify` closure, so an OCC retry re-reads fresh state and
/// re-applies the delta instead of losing the other webhook's update.
#[tokio::test]
async fn test_update_github_installation_repos_delta_concurrent_deltas_both_land() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_002, "org-concurrent-delta").await;
    let seeded = update_github_installation_repos(&store, 20_002, &["seed".to_string()])
        .await
        .expect("seed repos");
    assert!(seeded, "seeding must find the installation");

    let store_a = store.clone();
    let store_b = store.clone();
    let add_a = vec!["alpha".to_string()];
    let add_b = vec!["bravo".to_string()];
    let (a, b) = tokio::join!(
        update_github_installation_repos_delta(&store_a, 20_002, &add_a, &[]),
        update_github_installation_repos_delta(&store_b, 20_002, &add_b, &[]),
    );
    assert!(
        a.expect("delta a must not error"),
        "delta a must find the installation"
    );
    assert!(
        b.expect("delta b must not error"),
        "delta b must find the installation"
    );

    let after = get_github_installation_by_installation_id(&store, 20_002)
        .await
        .expect("lookup after concurrent deltas")
        .expect("installation must still exist");
    assert_eq!(
        after.repositories.as_deref(),
        Some(&["alpha".to_string(), "bravo".to_string(), "seed".to_string()][..]),
        "both concurrent deltas must land (no lost update)"
    );
}

/// Deterministic companion to the concurrent-delta test above (whose
/// `tokio::join!` contention depends on scheduling): the modify test seam
/// applies a second delta inside the OCC window, guaranteeing the retry path
/// runs and asserting the retried merge re-reads the fresh repo list.
#[tokio::test]
async fn test_update_github_installation_repos_delta_occ_retry_merges_fresh_state() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_004, "org-delta-seam").await;
    let seeded = update_github_installation_repos(&store, 20_004, &["seed".to_string()])
        .await
        .expect("seed repos");
    assert!(seeded, "seeding must find the installation");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let bravo = vec!["bravo".to_string()];
            let found = update_github_installation_repos_delta(&writer, 20_004, &bravo, &[])
                .await
                .expect("hook delta must not error");
            assert!(found, "hook delta must find the installation");
        })
    }));

    let alpha = vec!["alpha".to_string()];
    let found = update_github_installation_repos_delta(&hooked, 20_004, &alpha, &[])
        .await
        .expect("delta must not error");
    assert!(found, "delta must find the installation");

    let after = get_github_installation_by_installation_id(&store, 20_004)
        .await
        .expect("lookup after deltas")
        .expect("installation must still exist");
    assert_eq!(
        after.repositories.as_deref(),
        Some(&["alpha".to_string(), "bravo".to_string(), "seed".to_string()][..]),
        "the delta applied inside the OCC window must survive the retried merge"
    );
}

/// If an installation is deleted between the index-resolve and the `modify` call
/// (race with an uninstall webhook), `modify` returns `Ok(false)` rather than
/// updating a stale document.
#[tokio::test]
async fn test_github_installation_deleted_between_resolve_and_modify() {
    // This test exercises the edge case described in the plan: the resolve step
    // maps installation_id → doc.id, then the doc is deleted before `modify`
    // runs. `modify` re-reads by id, finds nothing, and returns Ok(false).
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 30_001, "org-delete-race").await;

    // Step 1: resolve the doc_id (simulates what suspend_github_installation does).
    let doc = store
        .find_one::<crate::db::documents::github::GitHubInstallationDoc>("installation_id", "30001")
        .await
        .expect("find_one")
        .expect("must exist after create");
    let doc_id = doc.id.clone();

    // Step 2: delete the installation (simulates a concurrent uninstall webhook).
    delete_github_installation_by_installation_id(&store, 30_001)
        .await
        .expect("delete");

    // Step 3: call modify directly on the now-deleted id — must return Ok(false).
    let found = store
        .modify::<crate::db::documents::github::GitHubInstallationDoc, _>(&doc_id, |data| {
            data.suspended_at = Some(jiff::Timestamp::now());
        })
        .await
        .expect("modify must not error");
    assert!(!found, "modify on deleted doc must return Ok(false)");
}

/// Insert an installation row under a random document ID, the shape rows had
/// before `create_github_installation` derived the ID from `installation_id`,
/// so two can exist for one installation.
async fn insert_random_id_github_installation(
    store: &DocumentStore,
    installation_id: i64,
    org_id: &str,
) -> String {
    let doc = crate::db::documents::github::GitHubInstallationDoc {
        org_id: org_id.to_owned(),
        installation_id,
        github_account_login: "acme".to_owned(),
        github_account_type: "Organization".to_owned(),
        permissions: std::collections::HashMap::new(),
        repository_selection: "all".to_owned(),
        installed_at: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
        installed_by_user_id: None,
        suspended_at: None,
        repositories: None,
    };
    store.insert(&doc).await.expect("insert").id
}

/// Every installation webhook reaches every row for the installation, not
/// only the newest: a row left behind would stay connected, unsuspended, or
/// on stale repositories for its organization.
#[tokio::test]
async fn test_github_installation_webhooks_reach_every_row() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let rows = [
        insert_random_id_github_installation(&store, 40_001, "org-a").await,
        insert_random_id_github_installation(&store, 40_001, "org-b").await,
    ];
    let control = create_test_github_installation(&store, 40_002, "org-c").await;
    let docs = || async {
        let mut docs = Vec::new();
        for id in &rows {
            docs.push(
                store
                    .get::<GitHubInstallationDoc>(id)
                    .await
                    .expect("get")
                    .map(|d| d.data),
            );
        }
        docs
    };

    assert!(
        suspend_github_installation(&store, 40_001)
            .await
            .expect("webhook helper")
    );
    for doc in docs().await {
        assert!(
            doc.expect("webhook helper").suspended_at.is_some(),
            "every row is suspended"
        );
    }

    assert!(
        update_github_installation_repos(&store, 40_001, &["r1".to_owned()])
            .await
            .expect("webhook helper")
    );
    assert!(
        update_github_installation_repos_delta(
            &store,
            40_001,
            &["r2".to_owned()],
            &["r1".to_owned()]
        )
        .await
        .expect("webhook helper")
    );
    for doc in docs().await {
        assert_eq!(
            doc.expect("webhook helper").repositories,
            Some(vec!["r2".to_owned()])
        );
    }

    assert!(
        unsuspend_github_installation(&store, 40_001)
            .await
            .expect("webhook helper")
    );
    for doc in docs().await {
        assert!(
            doc.expect("webhook helper").suspended_at.is_none(),
            "every row is unsuspended"
        );
    }

    assert!(
        delete_github_installation_by_installation_id(&store, 40_001)
            .await
            .expect("webhook helper")
    );
    for doc in docs().await {
        assert!(doc.is_none(), "every row is deleted by one webhook");
    }
    assert!(
        !delete_github_installation_by_installation_id(&store, 40_001)
            .await
            .expect("webhook helper"),
        "a redelivered delete finds nothing left"
    );

    let other = store
        .get::<GitHubInstallationDoc>(&control)
        .await
        .expect("get")
        .expect("another installation is untouched");
    assert!(other.data.suspended_at.is_none());
}

// ---- update_scim_group ----

/// After `update_scim_group`, only the updated fields change and version increments.
#[tokio::test]
async fn test_update_scim_group_only_intended_fields_change() {
    use crate::db::documents::scim::ScimGroupDoc;

    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "OriginalName", Some("ext-123"), &[])
        .await
        .expect("create_scim_group");

    let before = store
        .get::<ScimGroupDoc>(&group.id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        set_group_attributes("UpdatedName", Some("ext-456")),
    )
    .await
    .expect("update_scim_group");
    assert!(found, "update must return true");

    let after = store
        .get::<ScimGroupDoc>(&group.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(after.data.display_name, "UpdatedName", "name must update");
    assert_eq!(
        after.data.external_id.as_deref(),
        Some("ext-456"),
        "external_id must update"
    );
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment"
    );
}

/// `update_scim_group` with a wrong `org_id` returns `Ok(false)` without modifying the doc.
#[tokio::test]
async fn test_update_scim_group_wrong_org_returns_false() {
    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "GroupToProtect", None, &[])
        .await
        .expect("create_scim_group");

    let found = update_scim_group(
        &store,
        &group.id,
        "wrong-org",
        set_group_attributes("HackedName", None),
    )
    .await
    .expect("update_scim_group query must not error");
    assert!(!found, "cross-org update must return false");

    // Original name must be unchanged.
    let unchanged = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group")
        .expect("must exist");
    assert_eq!(
        unchanged.display_name, "GroupToProtect",
        "name must be unchanged after cross-org rejection"
    );
}

// ---- update_custom_policy ----

/// After `update_custom_policy`, only the updated fields change and version increments.
#[tokio::test]
async fn test_update_custom_policy_only_intended_fields_change() {
    use crate::db::documents::posture_policy::CustomPosturePolicyDoc;

    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "OriginalPolicy",
            description: Some("orig desc"),
            policy_text: "true",
            org_id: "org-policy-test",
            builder_spec: None,
        },
    )
    .await
    .expect("create_custom_policy");

    let before = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-policy-test",
        UpdateCustomPolicyParams {
            name: Some("UpdatedPolicy"),
            description: FieldUpdate::Set("new desc"),
            policy_text: Some("false"),
            active: Some(true),
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return updated record");

    assert_eq!(updated.name, "UpdatedPolicy", "name must update");
    assert_eq!(
        updated.description.as_deref(),
        Some("new desc"),
        "description must update"
    );
    assert_eq!(updated.policy_text, "false", "policy_text must update");
    assert!(updated.active, "active must be set to true");

    let after = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment"
    );
}

/// `FieldUpdate::Keep` leaves the description unchanged.
#[tokio::test]
async fn test_update_custom_policy_field_update_keep() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "KeepDescPolicy",
            description: Some("original desc"),
            policy_text: "true",
            org_id: "org-keep-test",
            builder_spec: None,
        },
    )
    .await
    .expect("create_custom_policy");

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-keep-test",
        UpdateCustomPolicyParams {
            name: None,
            description: FieldUpdate::Keep,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return record");

    assert_eq!(
        updated.description.as_deref(),
        Some("original desc"),
        "Keep must leave description unchanged"
    );
}

/// `FieldUpdate::Clear` sets the description to None.
#[tokio::test]
async fn test_update_custom_policy_field_update_clear() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "ClearDescPolicy",
            description: Some("will be cleared"),
            policy_text: "true",
            org_id: "org-clear-test",
            builder_spec: None,
        },
    )
    .await
    .expect("create_custom_policy");

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-clear-test",
        UpdateCustomPolicyParams {
            name: None,
            description: FieldUpdate::Clear,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return record");

    assert!(
        updated.description.is_none(),
        "Clear must set description to None"
    );
}

/// `update_custom_policy` with wrong `org_id` returns `Ok(None)`.
#[tokio::test]
async fn test_update_custom_policy_wrong_org_returns_none() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "ProtectedPolicy",
            description: None,
            policy_text: "true",
            org_id: "real-org",
            builder_spec: None,
        },
    )
    .await
    .expect("create_custom_policy");

    let result = update_custom_policy(
        &store,
        &policy.id,
        "wrong-org",
        UpdateCustomPolicyParams {
            name: Some("HackedName"),
            description: FieldUpdate::Keep,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("query must not error");
    assert!(result.is_none(), "cross-org update must return None");

    let unchanged = get_custom_policy(&store, &policy.id)
        .await
        .expect("get_custom_policy")
        .expect("must exist");
    assert_eq!(
        unchanged.name, "ProtectedPolicy",
        "name must be unchanged after cross-org rejection"
    );
}

/// `update_custom_policy` with an id that does not exist returns `None`.
///
/// The pre-check at the top of `update_custom_policy` fast-paths to `Ok(None)`
/// when `store.get` finds no document. This path is distinct from the wrong-org
/// rejection and needs its own coverage.
#[tokio::test]
async fn test_update_custom_policy_not_found_returns_none() {
    let (store, _audit) = test_db().await;

    let result = update_custom_policy(
        &store,
        "does-not-exist",
        TEST_ORG_ID,
        UpdateCustomPolicyParams {
            name: Some("Anything"),
            description: FieldUpdate::Keep,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("query must not error");
    assert!(result.is_none(), "absent policy id must return None");
}

// ---- OCC applied-flag reset (uses the `modify` test seam) ----

/// A SCIM update must never apply a cross-org write: if the target user does
/// not belong to the caller's organization, nothing is mutated and the call
/// reports not-applied.
///
/// The mechanism moved when the admin-count floor was added. `update_scim_user`
/// now enforces "at least one active admin per organization" — a cross-row
/// invariant — so it runs as one transaction that version-bumps the org row
/// rather than as a `store.modify` loop, and the org check lives inside that
/// transaction.
///
/// The mid-flight variant reduces to this one rather than needing its own
/// case: moving the user to another org bumps their row's version, so the
/// guarded `compare_and_update` loses, `with_dsql_retry!` re-runs the closure,
/// and the re-read hits exactly the org mismatch asserted below. It is not
/// driven here with a hook because a concurrent writer firing mid-transaction
/// deadlocks against the open transaction on SQLite.
#[tokio::test]
async fn test_update_scim_user_cross_org_write_is_never_applied() {
    use crate::db::documents::user::UserDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "occ-race@example.com",
        Some("Before"),
        None,
        true,
    )
    .await
    .expect("create_scim_user");

    // The state a lost CAS leaves behind for the retry to observe: the user
    // has moved to another org since the caller's request was authorized.
    let doc = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("get")
        .expect("must exist");
    let mut moved = doc.data;
    moved.org_id = Some("other-org".to_string());
    store.update(&user.id, &moved).await.expect("move org");

    let applied = update_scim_user(&store, &user.id, TEST_ORG_ID, Some("Hacked"), None, false)
        .await
        .expect("update_scim_user must not error");
    assert!(
        !applied,
        "user belongs to another org: update must report not-applied"
    );

    let after = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id.as_deref(),
        Some("other-org"),
        "the org change must not be clobbered"
    );
    assert_eq!(
        after.data.name.as_deref(),
        Some("Before"),
        "the cross-org name mutation must not land"
    );
    assert!(after.data.active, "active must be unchanged");
}

/// Regression: same race as
/// [`test_update_scim_user_concurrent_org_change_reports_not_applied`],
/// for `update_custom_policy` (which reports not-applied as `None`).
#[tokio::test]
async fn test_update_custom_policy_concurrent_org_change_returns_none() {
    use crate::db::documents::posture_policy::CustomPosturePolicyDoc;

    let (store, _audit) = test_db().await;
    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "PolicyBefore",
            description: None,
            policy_text: "true",
            org_id: "org-occ-race",
            builder_spec: None,
        },
    )
    .await
    .expect("create_custom_policy");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let doc = writer
                .get::<CustomPosturePolicyDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.org_id = "other-org".to_string();
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    let result = update_custom_policy(
        &hooked,
        &policy.id,
        "org-occ-race",
        UpdateCustomPolicyParams {
            name: Some("Hacked"),
            description: FieldUpdate::Keep,
            policy_text: None,
            active: None,
            builder_spec: FieldUpdate::Keep,
        },
    )
    .await
    .expect("update_custom_policy must not error");
    assert!(
        result.is_none(),
        "org changed mid-flight: update must return None"
    );

    let after = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id, "other-org",
        "the concurrent org change must not be clobbered"
    );
    assert_eq!(
        after.data.name, "PolicyBefore",
        "the cross-org name mutation must not land"
    );
}

/// `suspend_github_installation` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_suspend_github_installation_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = suspend_github_installation(&store, 99_001)
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from suspend"
    );
}

/// `unsuspend_github_installation` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_unsuspend_github_installation_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = unsuspend_github_installation(&store, 99_002)
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from unsuspend"
    );
}

/// `update_github_installation_repos` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_update_github_installation_repos_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = update_github_installation_repos(&store, 99_003, &["owner/repo".to_string()])
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from update_repos"
    );
}

// ---- revoke_registration_access_token (RFC 7592 §2.1/2.2/2.3) ----

/// Create a minimal dynamically-registered web client holding the given
/// registration access token hash. Returns `(OAuthClient, client_id)`. The
/// helper centralizes the `CreateOAuthClientParams` literal so the three
/// revoke tests below share one fixture with no secrets, keys, or org.
pub(super) async fn seed_dynamic_client_with_reg_token(
    store: &DocumentStore,
    reg_token_hash: &str,
) -> (OAuthClient, String) {
    use crate::crypto::alg::JwsAlgorithm;

    let redirect_uris = vec!["https://example.com/callback".to_string()];
    create_oauth_client(
        store,
        &CreateOAuthClientParams {
            user_id: None,
            name: "Dynamic Reg Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &redirect_uris,
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Dynamic,
            registration_access_token_hash: Some(reg_token_hash),
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("create dynamic client")
}

/// `revoke_registration_access_token` sequentially clears the stored hash of
/// the client whose registration access token hashes to `token_hash` — the
/// core RFC 7592 §2.1 "misdirected token SHOULD be revoked" behavior. This
/// anchors the helper's intended effect so the concurrent regression below
/// is contrasted against a known-good baseline (the fix does not weaken the
/// revocation the `SHOULD` requires).
#[tokio::test]
async fn test_revoke_registration_access_token_revokes_presented_hash() {
    use crate::crypto::hash_token;
    use crate::db::documents::oauth::OAuthClientDoc;

    let (store, _audit) = test_db().await;

    let t_old = "vouch_reg_OLD_TOKEN".to_string();
    let old_hash = hash_token(&t_old);
    let (client, client_id) = seed_dynamic_client_with_reg_token(&store, &old_hash).await;
    let victim_id = client.id.clone();

    let revoked_owner = revoke_registration_access_token(&store, &old_hash)
        .await
        .expect("revoke must not error");
    assert_eq!(
        revoked_owner.as_deref(),
        Some(victim_id.as_str()),
        "the owning client's doc id must be returned"
    );

    let after = store
        .get::<OAuthClientDoc>(&victim_id)
        .await
        .expect("get after")
        .expect("victim must still exist");
    assert_eq!(
        after.data.registration_access_token_hash, None,
        "the presented token's hash must be cleared"
    );

    let looked_up = get_oauth_client_by_client_id(&store, &client_id)
        .await
        .expect("lookup")
        .expect("client must exist");
    assert_eq!(
        looked_up.registration_access_token_hash, None,
        "the client_id lookup must observe the revoked token"
    );
}

/// `revoke_registration_access_token` with a hash no client holds returns
/// `Ok(None)` and disturbs nothing — the overwhelmingly common path, since
/// the caller only reaches it after a `client_id` miss.
#[tokio::test]
async fn test_revoke_registration_access_token_unknown_hash_returns_none() {
    use crate::crypto::hash_token;
    use crate::db::documents::oauth::OAuthClientDoc;

    let (store, _audit) = test_db().await;

    let keeper_hash = hash_token("vouch_reg_KEEPER");
    let (keeper, _) = seed_dynamic_client_with_reg_token(&store, &keeper_hash).await;

    let unknown = hash_token("vouch_reg_NO_SUCH_TOKEN");
    let revoked_owner = revoke_registration_access_token(&store, &unknown)
        .await
        .expect("revoke must not error");
    assert!(revoked_owner.is_none(), "unknown hash must return None");

    let keeper_after = store
        .get::<OAuthClientDoc>(&keeper.id)
        .await
        .expect("get keeper")
        .expect("keeper must exist");
    assert_eq!(
        keeper_after.data.registration_access_token_hash.as_deref(),
        Some(keeper_hash.as_str()),
        "an unrelated client's token must be untouched"
    );
}

/// Regression: a racing RFC 7592 PUT that rotates a client's registration
/// access token while an attacker's misdirected-token revoke is in flight must
/// NOT clear the freshly rotated token. The revoke's `find_one` only resolves
/// the presented (pre-rotation) hash to an owner id; the actual clear happens
/// inside `store.modify`, which re-reads the latest document on every OCC
/// attempt — either because the PUT committed between `find_one` and
/// `modify`'s internal read, or because it committed between that read and
/// `modify`'s compare-and-update (forcing an OCC retry). Clearing
/// unconditionally on retry wipes the rotated hash the owner just received and
/// locks them out of all RFC 7592 operations until an administrator reissues a
/// token. The fix conditions the clear on the stored hash still equaling the
/// presented hash, making a rotate-then-racing-revoke a no-op.
///
/// This test forces the OCC-retry interleaving deterministically using the
/// `set_modify_test_hook` seam: the victim's `update_oauth_client_registration`
/// PUT runs inside the attacker's `modify`'s first attempt, bumping the
/// document version so the attacker's first compare-and-update loses the
/// version race and the loop retries against the freshly rotated document.
#[tokio::test]
async fn test_revoke_registration_access_token_does_not_clobber_concurrently_rotated_token() {
    use crate::crypto::hash_token;
    use crate::db::documents::oauth::OAuthClientDoc;

    let (store, _audit) = test_db().await;

    // The victim holds the about-to-be-leaked T_old. The attacker has captured
    // T_old and replays it against a non-existent client_id while the victim
    // rotates to T_new via a legitimate PUT.
    let t_old = "vouch_reg_OLD_TOKEN_leaked".to_string();
    let t_new = "vouch_reg_NEW_TOKEN_rotated".to_string();
    let old_hash = hash_token(&t_old);
    let new_hash = hash_token(&t_new);

    let redirect_uris = vec!["https://example.com/callback".to_string()];
    let (client, client_id) = seed_dynamic_client_with_reg_token(&store, &old_hash).await;
    let victim_id = client.id.clone();

    // Hookless writer clone for the victim's PUT — must not re-enter the hook
    // when it writes through the store.
    let writer = store.clone();
    let mut hooked = store.clone();
    let new_hash_for_hook = new_hash.clone();
    let redirect_uris_for_hook = redirect_uris.clone();
    let victim_id_for_hook = victim_id.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let new_hash = new_hash_for_hook.clone();
        let redirect_uris = redirect_uris_for_hook.clone();
        let victim_id = victim_id_for_hook.clone();
        Box::pin(async move {
            // Run the victim's RFC 7592 PUT (rotating to T_new) exactly once,
            // inside the attacker's first modify attempt — after it read the
            // pre-rotation doc but before its compare-and-update. The PUT
            // commits version V+1 (hash T_new), so the attacker's first CAS
            // loses the version race and the modify loop retries against the
            // freshly rotated document.
            if attempt != 0 {
                return;
            }
            update_oauth_client_registration(
                &writer,
                &victim_id,
                &UpdateClientRegistrationParams {
                    redirect_uris: &redirect_uris,
                    grant_types: None,
                    response_types: None,
                    keys: None,
                    registration_access_token_hash: &new_hash,
                    registration_metadata: None,
                    userinfo_signed_response_alg: None,
                    request_uris: None,
                    post_logout_redirect_uris: None,
                    client_name: None,
                    software_id: None,
                    software_version: None,
                    id_token_signed_response_alg: crate::crypto::alg::JwsAlgorithm::Es256,
                    authorization_signed_response_alg: None,
                    introspection_signed_response_alg: None,
                    request_object_signing_alg: None,
                    require_signed_request_object: None,
                    tls_client_auth_subject_dn: None,
                    tls_client_auth_san_dns: None,
                    tls_client_auth_san_uri: None,
                    tls_client_auth_san_ip: None,
                    tls_client_auth_san_email: None,
                },
            )
            .await
            .expect("victim PUT must rotate the token");
        })
    }));

    // The attacker replays the leaked T_old against a non-existent client_id;
    // the misdirected-token path revokes whichever client holds hash(T_old).
    let revoked_owner = revoke_registration_access_token(&hooked, &old_hash)
        .await
        .expect("revoke must not error");
    assert_eq!(
        revoked_owner.as_deref(),
        Some(victim_id.as_str()),
        "the revocation still names the owner it found by hash, even if the \
         clear turns out to be a no-op against a rotated token"
    );

    // The rotated token T_new — which only the legitimate owner holds — must
    // survive, so the owner can still authenticate against their real client.
    let after = store
        .get::<OAuthClientDoc>(&victim_id)
        .await
        .expect("get after")
        .expect("victim must still exist");
    assert_eq!(
        after.data.registration_access_token_hash.as_deref(),
        Some(new_hash.as_str()),
        "the concurrently rotated token must not be wiped by the racing revoke; \
         otherwise the legitimate owner is locked out of all RFC 7592 operations"
    );

    // Cross-check via the client_id lookup that the live state reflects T_new.
    let looked_up = get_oauth_client_by_client_id(&store, &client_id)
        .await
        .expect("lookup")
        .expect("client must exist");
    assert_eq!(
        looked_up.registration_access_token_hash.as_deref(),
        Some(new_hash.as_str()),
        "client_id lookup must observe the rotated token"
    );
}
