// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRUD round-trip tests for the GitHub App installation DB layer
//! (`crates/vouch-server/src/db/github.rs`).
//!
//! Covers create / lookup-by-org / lookup-by-installation-id / suspend /
//! unsuspend / repository updates / delta updates / delete / global
//! installation-id listing, plus the credential audit log helpers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::collections::HashMap;

use vouch_server::db::{self, GitHubCredentialAuditData};
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
        org_id,
        installation_id,
        login,
        account_type,
        &perm(&[("contents", "read")]),
        "all",
        Some("admin-user"),
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
async fn log_github_credential_event_persists_audit_row() {
    let harness = TestHarness::new().await;
    let data = GitHubCredentialAuditData {
        event_type: "ssh_credential_issued".to_string(),
        org_id: Some("test-org".to_string()),
        installation_id: Some(7),
        success: true,
        ..Default::default()
    };

    let event_id = db::log_github_credential_event(
        &harness.state.audit,
        "user-123",
        "user@example.com",
        data,
        None,
    )
    .await
    .expect("log event");

    assert!(!event_id.is_empty(), "audit insert should return an id");
}
