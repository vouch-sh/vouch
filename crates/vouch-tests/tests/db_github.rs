// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRUD round-trip tests for the GitHub App installation DB layer
//! (`crates/vouch-server/src/db/github.rs`).
//!
//! Covers create / lookup-by-org / lookup-by-installation-id / suspend /
//! unsuspend / repository updates / delta updates / delete / global
//! installation-id listing, plus the credential audit log helpers.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::collections::HashMap;

use vouch_server::db;
use vouch_tests::TestHarness;

fn perm(map: &[(&str, &str)]) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

async fn fresh_org_id(harness: &TestHarness, domain: &str) -> String {
    harness.create_org(domain).await.expect("create org").id
}

async fn install(
    harness: &TestHarness,
    org_id: &str,
    installation_id: i64,
    login: &str,
    account_type: &str,
) -> String {
    db::create_github_installation(
        &harness.state.store,
        &db::CreateGitHubInstallationParams {
            org_id,
            installation_id,
            github_account_login: login,
            github_account_type: account_type,
            permissions: &perm(&[("contents", "read")]),
            repository_selection: "all",
            installed_by_user_id: Some("admin-user"),
        },
    )
    .await
    .expect("create installation")
}

// ============================================================================
// create + lookup
// ============================================================================

#[tokio::test]
async fn create_and_get_by_org_returns_installation() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-create.example").await;

    let id = install(&harness, &org_id, 100, "acme", "Organization").await;

    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    assert_eq!(listed.len(), 1);
    let installation = &listed[0];
    assert_eq!(installation.id, id);
    assert_eq!(installation.installation_id, 100);
    assert_eq!(installation.github_account_login, "acme");
    assert_eq!(installation.github_account_type, "Organization");
    assert_eq!(installation.repository_selection, "all");
    assert_eq!(
        installation.installed_by_user_id.as_deref(),
        Some("admin-user")
    );
    assert!(installation.suspended_at.is_none());
    assert!(installation.repositories.is_none());
    assert_eq!(
        installation.permissions.get("contents").map(String::as_str),
        Some("read")
    );
}

#[tokio::test]
async fn get_by_org_returns_empty_when_no_installs() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-empty.example").await;

    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    assert!(listed.is_empty());
}

#[tokio::test]
async fn get_by_org_sorts_by_account_login() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-sort.example").await;

    let _ = install(&harness, &org_id, 1, "charlie", "Organization").await;
    let _ = install(&harness, &org_id, 2, "alpha", "Organization").await;
    let _ = install(&harness, &org_id, 3, "bravo", "Organization").await;

    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    let names: Vec<_> = listed
        .iter()
        .map(|i| i.github_account_login.as_str())
        .collect();
    assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
}

#[tokio::test]
async fn get_by_org_and_account_is_case_insensitive() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-case.example").await;

    let _ = install(&harness, &org_id, 42, "MixedCase", "Organization").await;

    let lower =
        db::get_github_installation_by_org_and_account(&harness.state.store, &org_id, "mixedcase")
            .await
            .expect("get by login");
    assert!(lower.is_some());
    let upper =
        db::get_github_installation_by_org_and_account(&harness.state.store, &org_id, "MIXEDCASE")
            .await
            .expect("get by login");
    assert!(upper.is_some());

    let other =
        db::get_github_installation_by_org_and_account(&harness.state.store, &org_id, "different")
            .await
            .expect("get by login");
    assert!(other.is_none());
}

#[tokio::test]
async fn get_by_installation_id_finds_record() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-by-id.example").await;
    let _ = install(&harness, &org_id, 999, "lookup", "Organization").await;

    let found = db::get_github_installation_by_installation_id(&harness.state.store, 999)
        .await
        .expect("lookup");
    let found = found.expect("installation exists");
    assert_eq!(found.installation_id, 999);

    let missing = db::get_github_installation_by_installation_id(&harness.state.store, 12_345)
        .await
        .expect("lookup");
    assert!(missing.is_none());
}

// ============================================================================
// suspend / unsuspend
// ============================================================================

#[tokio::test]
async fn suspend_and_unsuspend_toggle_suspended_at() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-suspend.example").await;
    let _ = install(&harness, &org_id, 7, "suspendable", "Organization").await;

    let toggled = db::suspend_github_installation(&harness.state.store, 7)
        .await
        .expect("suspend");
    assert!(toggled);

    let after_suspend = db::get_github_installation_by_installation_id(&harness.state.store, 7)
        .await
        .expect("lookup")
        .expect("present");
    assert!(after_suspend.suspended_at.is_some());

    let toggled = db::unsuspend_github_installation(&harness.state.store, 7)
        .await
        .expect("unsuspend");
    assert!(toggled);

    let after_unsuspend = db::get_github_installation_by_installation_id(&harness.state.store, 7)
        .await
        .expect("lookup")
        .expect("present");
    assert!(after_unsuspend.suspended_at.is_none());
}

#[tokio::test]
async fn suspend_unknown_installation_returns_false() {
    let harness = TestHarness::new().await;
    let toggled = db::suspend_github_installation(&harness.state.store, 999_999)
        .await
        .expect("suspend");
    assert!(!toggled);

    let toggled = db::unsuspend_github_installation(&harness.state.store, 999_999)
        .await
        .expect("unsuspend");
    assert!(!toggled);
}

// ============================================================================
// repositories update
// ============================================================================

#[tokio::test]
async fn update_repos_replaces_list() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-repos.example").await;
    let _ = install(&harness, &org_id, 11, "repos", "Organization").await;

    let updated = db::update_github_installation_repos(
        &harness.state.store,
        11,
        &["repo-a".to_string(), "repo-b".to_string()],
    )
    .await
    .expect("update");
    assert!(updated);

    let fetched = db::get_github_installation_by_installation_id(&harness.state.store, 11)
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(
        fetched.repositories.as_deref(),
        Some(&["repo-a".to_string(), "repo-b".to_string()][..])
    );

    // A subsequent call replaces, not merges.
    let updated =
        db::update_github_installation_repos(&harness.state.store, 11, &["repo-c".to_string()])
            .await
            .expect("update");
    assert!(updated);
    let fetched = db::get_github_installation_by_installation_id(&harness.state.store, 11)
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(
        fetched.repositories.as_deref(),
        Some(&["repo-c".to_string()][..])
    );
}

#[tokio::test]
async fn update_repos_delta_adds_and_removes_with_sort() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-delta.example").await;
    let _ = install(&harness, &org_id, 21, "delta", "Organization").await;
    db::update_github_installation_repos(
        &harness.state.store,
        21,
        &["beta".to_string(), "delta".to_string()],
    )
    .await
    .expect("seed");

    let touched = db::update_github_installation_repos_delta(
        &harness.state.store,
        21,
        &["alpha".to_string(), "gamma".to_string()],
        &["beta".to_string()],
    )
    .await
    .expect("delta");
    assert!(touched);

    let fetched = db::get_github_installation_by_installation_id(&harness.state.store, 21)
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(
        fetched.repositories.as_deref(),
        Some(
            &[
                "alpha".to_string(),
                "delta".to_string(),
                "gamma".to_string()
            ][..]
        ),
        "delta should add+remove and sort the result"
    );
}

#[tokio::test]
async fn update_repos_delta_ignores_duplicate_adds() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-delta-dup.example").await;
    let _ = install(&harness, &org_id, 31, "dup", "Organization").await;
    db::update_github_installation_repos(&harness.state.store, 31, &["existing".to_string()])
        .await
        .expect("seed");

    let touched = db::update_github_installation_repos_delta(
        &harness.state.store,
        31,
        &["existing".to_string(), "new".to_string()],
        &[],
    )
    .await
    .expect("delta");
    assert!(touched);

    let fetched = db::get_github_installation_by_installation_id(&harness.state.store, 31)
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(
        fetched.repositories.as_deref(),
        Some(&["existing".to_string(), "new".to_string()][..]),
        "duplicate adds must not produce repeated entries"
    );
}

#[tokio::test]
async fn update_repos_unknown_installation_returns_false() {
    let harness = TestHarness::new().await;
    let touched =
        db::update_github_installation_repos(&harness.state.store, 424_242, &["nope".to_string()])
            .await
            .expect("update");
    assert!(!touched);

    let touched = db::update_github_installation_repos_delta(
        &harness.state.store,
        424_242,
        &["nope".to_string()],
        &[],
    )
    .await
    .expect("delta");
    assert!(!touched);
}

// ============================================================================
// replay / duplicate prevention (deterministic document ID)
//
// `create_github_installation` derives a deterministic document ID from
// `(org_id, installation_id)` and uses `insert_with_id`, so a replayed install
// callback (or two concurrent connects) for the same installation in the same
// org collide on the primary key and return `Duplicate` instead of creating a
// duplicate row. These tests pin that behavior against the real in-memory
// SQLite backend so the `is_unique_violation` detection is exercised for real.
// ============================================================================

#[tokio::test]
async fn create_github_installation_replay_returns_duplicate_and_single_row() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-replay.example").await;

    let first = install(&harness, &org_id, 100, "acme", "Organization").await;

    // Replay: same (org_id, installation_id). Before the fix this would insert
    // a second, byte-equivalent row (random document_id). Now it must collide
    // on the deterministic primary key and return `Duplicate`.
    let replay = db::create_github_installation(
        &harness.state.store,
        &db::CreateGitHubInstallationParams {
            org_id: &org_id,
            installation_id: 100,
            github_account_login: "acme",
            github_account_type: "Organization",
            permissions: &perm(&[("contents", "read")]),
            repository_selection: "all",
            installed_by_user_id: Some("admin-user"),
        },
    )
    .await;

    assert!(
        matches!(replay, Err(db::CreateGitHubInstallationError::Duplicate)),
        "expected Duplicate on replay, got {replay:?}"
    );

    // Exactly one row exists — the deterministic ID prevented the duplicate.
    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    assert_eq!(listed.len(), 1, "replay must not create a duplicate row");
    assert_eq!(listed[0].id, first, "the original row must remain");
    assert_eq!(listed[0].installation_id, 100);
    assert_eq!(listed[0].github_account_login, "acme");
}

#[tokio::test]
async fn create_github_installation_replay_prevents_orphan_after_delete() {
    // Regression for scenario B: replay → duplicate → uninstall webhook
    // (find_one delete) leaves an orphan → credential path hits a deleted
    // installation. With the deterministic ID there is only ever one row, so a
    // single `delete_by_installation_id` clears the installation entirely.
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-orphan.example").await;
    let _ = install(&harness, &org_id, 777, "orphanable", "Organization").await;

    // A replay attempt is rejected; no second row is created.
    let replay = db::create_github_installation(
        &harness.state.store,
        &db::CreateGitHubInstallationParams {
            org_id: &org_id,
            installation_id: 777,
            github_account_login: "orphanable",
            github_account_type: "Organization",
            permissions: &perm(&[("contents", "read")]),
            repository_selection: "all",
            installed_by_user_id: Some("admin-user"),
        },
    )
    .await;
    assert!(matches!(
        replay,
        Err(db::CreateGitHubInstallationError::Duplicate)
    ));

    // The `installation.deleted` webhook removes the single row.
    let deleted = db::delete_github_installation_by_installation_id(&harness.state.store, 777)
        .await
        .expect("delete");
    assert!(deleted);

    // No orphan survives: the org has zero installations, so credential
    // issuance would take the clean `github_not_connected` path.
    let after = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    assert!(
        after.is_empty(),
        "no orphan duplicate should survive webhook cleanup"
    );
    let by_id = db::get_github_installation_by_installation_id(&harness.state.store, 777)
        .await
        .expect("lookup");
    assert!(by_id.is_none(), "global lookup must find no installation");
}

#[tokio::test]
async fn create_github_installation_distinct_installation_ids_same_org_succeed() {
    // Different installation_ids in the same org must not collide: the
    // deterministic ID is derived from `(org_id, installation_id)`, so a
    // multi-account org can still link more than one GitHub installation.
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-multi.example").await;

    let _ = install(&harness, &org_id, 1, "alpha", "Organization").await;
    let _ = install(&harness, &org_id, 2, "bravo", "Organization").await;

    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    let logins: Vec<_> = listed
        .iter()
        .map(|i| i.github_account_login.as_str())
        .collect();
    assert_eq!(logins, vec!["alpha", "bravo"], "both installs must persist");
}

#[tokio::test]
async fn create_github_installation_same_installation_id_different_org_succeed() {
    // The deterministic ID is scoped to `(org_id, installation_id)`, so the
    // same GitHub installation_id linked to two different Vouch orgs produces
    // two distinct documents (no collision). This pins the scoping the
    // primary fix intentionally uses.
    let harness = TestHarness::new().await;
    let org_a = fresh_org_id(&harness, "gh-cross-a.example").await;
    let org_b = fresh_org_id(&harness, "gh-cross-b.example").await;

    let id_a = install(&harness, &org_a, 42, "shared", "Organization").await;
    let id_b = install(&harness, &org_b, 42, "shared", "Organization").await;
    assert_ne!(id_a, id_b, "distinct orgs must get distinct document IDs");

    let listed_a = db::get_github_installations_by_org(&harness.state.store, &org_a)
        .await
        .expect("get by org a");
    assert_eq!(listed_a.len(), 1);
    let listed_b = db::get_github_installations_by_org(&harness.state.store, &org_b)
        .await
        .expect("get by org b");
    assert_eq!(listed_b.len(), 1);
}

#[tokio::test]
async fn create_github_installation_concurrent_same_installation_produces_one_row() {
    // Race-safety (G9): N concurrent `create_github_installation` calls for the
    // same `(org_id, installation_id)` must produce exactly one `Ok(id)` and
    // N-1 `Err(Duplicate)`, leaving exactly one row — the deterministic primary
    // key collides atomically. Mirrors the challenge-state and SCIM concurrent
    // tests (`test_challenge_state_concurrent_calls_produce_one_row`,
    // `test_create_scim_user_concurrent_same_email_produces_one_user`).
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-race.example").await;

    const N: usize = 8;
    let perms = perm(&[("contents", "read")]);
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let store = harness.state.store.clone();
        let org_id = org_id.clone();
        let perms = perms.clone();
        handles.push(tokio::spawn(async move {
            db::create_github_installation(
                &store,
                &db::CreateGitHubInstallationParams {
                    org_id: &org_id,
                    installation_id: 9001,
                    github_account_login: "racer",
                    github_account_type: "Organization",
                    permissions: &perms,
                    repository_selection: "all",
                    installed_by_user_id: Some("admin-user"),
                },
            )
            .await
        }));
    }

    let mut ok_count = 0usize;
    let mut dup_count = 0usize;
    let mut other_err = None;
    for handle in handles {
        match handle.await.expect("task join") {
            Ok(_) => ok_count += 1,
            Err(db::CreateGitHubInstallationError::Duplicate) => dup_count += 1,
            Err(e) => other_err = Some(e),
        }
    }
    assert!(
        other_err.is_none(),
        "unexpected non-Duplicate error: {other_err:?}"
    );
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent call must win, got {ok_count}"
    );
    assert_eq!(
        dup_count,
        N - 1,
        "exactly N-1 must be Duplicate, got {dup_count}"
    );

    // Exactly one row exists, with the expected fields.
    let listed = db::get_github_installations_by_org(&harness.state.store, &org_id)
        .await
        .expect("get by org");
    assert_eq!(listed.len(), 1, "exactly one row must exist after the race");
    assert_eq!(listed[0].installation_id, 9001);
    assert_eq!(listed[0].github_account_login, "racer");
}

// ============================================================================
// delete + global listing
// ============================================================================

#[tokio::test]
async fn delete_removes_installation() {
    let harness = TestHarness::new().await;
    let org_id = fresh_org_id(&harness, "gh-delete.example").await;
    let _ = install(&harness, &org_id, 55, "doomed", "Organization").await;

    let deleted = db::delete_github_installation_by_installation_id(&harness.state.store, 55)
        .await
        .expect("delete");
    assert!(deleted);

    let after = db::get_github_installation_by_installation_id(&harness.state.store, 55)
        .await
        .expect("lookup");
    assert!(after.is_none());

    // Second delete is a no-op.
    let deleted_again = db::delete_github_installation_by_installation_id(&harness.state.store, 55)
        .await
        .expect("delete again");
    assert!(!deleted_again);
}

#[tokio::test]
async fn linked_installation_ids_spans_orgs() {
    let harness = TestHarness::new().await;
    let org_a = fresh_org_id(&harness, "gh-multi-a.example").await;
    let org_b = fresh_org_id(&harness, "gh-multi-b.example").await;

    let _ = install(&harness, &org_a, 1, "a", "Organization").await;
    let _ = install(&harness, &org_b, 2, "b", "Organization").await;
    let _ = install(&harness, &org_b, 3, "b2", "Organization").await;

    let mut ids = db::get_all_linked_installation_ids(&harness.state.store)
        .await
        .expect("list linked");
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3]);
}

// ============================================================================
// credential audit log
// ============================================================================

#[tokio::test]
async fn github_credential_event_persists_audit_row() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            db::CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                org_id: Some("test-org".to_string()),
                success: true,
                ..Default::default()
            },
            &db::GitHubCredentialDetails {
                installation_id: Some(7),
                ..Default::default()
            },
        )
        .await;

    let events = harness
        .state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["github_credential".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1);
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("parse data");
    assert_eq!(data["installation_id"], 7);
    assert_eq!(data["org_id"], "test-org");
}
