// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App installation database operations.

use std::collections::HashMap;

use super::document_type::Document;
use super::documents::github::GitHubInstallationDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// GitHub App Installations
// ============================================================================

/// GitHub App installation record.
#[derive(Debug)]
pub struct GitHubInstallation {
    pub id: String,
    pub org_id: String,
    pub installation_id: i64,
    pub github_account_login: String,
    pub github_account_type: String,
    pub permissions: HashMap<String, String>,
    pub repository_selection: String,
    pub installed_at: Timestamp,
    pub installed_by_user_id: Option<String>,
    pub suspended_at: Option<Timestamp>,
    pub repositories: Option<Vec<String>>,
}

impl From<Document<GitHubInstallationDoc>> for GitHubInstallation {
    fn from(doc: Document<GitHubInstallationDoc>) -> Self {
        Self {
            id: doc.id,
            org_id: doc.data.org_id,
            installation_id: doc.data.installation_id,
            github_account_login: doc.data.github_account_login,
            github_account_type: doc.data.github_account_type,
            permissions: doc.data.permissions,
            repository_selection: doc.data.repository_selection,
            installed_at: doc.data.installed_at,
            installed_by_user_id: doc.data.installed_by_user_id,
            suspended_at: doc.data.suspended_at,
            repositories: doc.data.repositories,
        }
    }
}

/// Parameters for creating a new GitHub App installation.
pub struct CreateGitHubInstallationParams<'a> {
    pub org_id: &'a str,
    pub installation_id: i64,
    pub github_account_login: &'a str,
    pub github_account_type: &'a str,
    pub permissions: &'a HashMap<String, String>,
    pub repository_selection: &'a str,
    pub installed_by_user_id: Option<&'a str>,
}

/// Create a new GitHub App installation for an organization.
pub async fn create_github_installation(
    store: &DocumentStore,
    params: &CreateGitHubInstallationParams<'_>,
) -> Result<String> {
    let doc = GitHubInstallationDoc {
        org_id: params.org_id.to_string(),
        installation_id: params.installation_id,
        github_account_login: params.github_account_login.to_string(),
        github_account_type: params.github_account_type.to_string(),
        permissions: params.permissions.clone(),
        repository_selection: params.repository_selection.to_string(),
        installed_at: Timestamp::now(),
        installed_by_user_id: params.installed_by_user_id.map(String::from),
        suspended_at: None,
        repositories: None,
    };

    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get all GitHub installations for an organization.
pub async fn get_github_installations_by_org(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<GitHubInstallation>> {
    let docs = store
        .find_all::<GitHubInstallationDoc>("org_id", org_id)
        .await?;

    let mut installations: Vec<GitHubInstallation> =
        docs.into_iter().map(GitHubInstallation::from).collect();

    installations.sort_by(|a, b| a.github_account_login.cmp(&b.github_account_login));

    Ok(installations)
}

/// Get GitHub installation by organization ID and
/// GitHub account login (case-insensitive).
pub async fn get_github_installation_by_org_and_account(
    store: &DocumentStore,
    org_id: &str,
    github_account: &str,
) -> Result<Option<GitHubInstallation>> {
    let docs = store
        .find_all::<GitHubInstallationDoc>("org_id", org_id)
        .await?;

    let account_lower = github_account.to_lowercase();
    let found = docs
        .into_iter()
        .find(|d| d.data.github_account_login.to_lowercase() == account_lower);

    Ok(found.map(GitHubInstallation::from))
}

/// Get GitHub installation by installation ID.
pub async fn get_github_installation_by_installation_id(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<Option<GitHubInstallation>> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    Ok(doc.map(GitHubInstallation::from))
}

/// Delete GitHub installation by installation ID.
pub async fn delete_github_installation_by_installation_id(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    if let Some(doc) = doc {
        store.delete(&doc.id).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Resolve a GitHub installation's document ID from its `installation_id` index.
///
/// Returns `Some(doc_id)` on a hit or `None` if no matching installation exists.
/// The resolved `doc_id` is the stable primary key used by `store.modify()`.
async fn resolve_installation_doc_id(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<Option<String>> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;
    Ok(doc.map(|d| d.id))
}

/// Suspend GitHub installation (used by webhook handler).
///
/// Uses optimistic concurrency (`store.modify`) so concurrent webhook events
/// targeting the same installation never produce a lost update. If the
/// installation is deleted between index-resolve and modify, returns `Ok(false)`.
pub async fn suspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
        return Ok(false);
    };
    store
        .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
            data.suspended_at = Some(Timestamp::now());
        })
        .await
}

/// Unsuspend GitHub installation (used by webhook handler).
///
/// Uses optimistic concurrency (`store.modify`) so concurrent webhook events
/// targeting the same installation never produce a lost update. If the
/// installation is deleted between index-resolve and modify, returns `Ok(false)`.
pub async fn unsuspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
        return Ok(false);
    };
    store
        .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
            data.suspended_at = None;
        })
        .await
}

/// Update repositories for a GitHub installation.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent webhook events
/// targeting the same installation never produce a lost update. If the
/// installation is deleted between index-resolve and modify, returns `Ok(false)`.
pub async fn update_github_installation_repos(
    store: &DocumentStore,
    installation_id: i64,
    repos: &[String],
) -> Result<bool> {
    let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
        return Ok(false);
    };
    let repos_owned = repos.to_vec();
    store
        .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
            data.repositories = Some(repos_owned.clone());
        })
        .await
}

/// Update repositories for a GitHub installation by
/// adding/removing repos (used by webhook handler).
///
/// The delta merge runs inside the `store.modify` closure, so every
/// optimistic-concurrency retry re-reads the current repo list and re-applies
/// the delta to fresh state: two concurrent delta webhooks for the same
/// installation both land. The merge is idempotent (adds are deduplicated,
/// removals filter by name, the result is sorted). If the installation is
/// deleted between index-resolve and modify, returns `Ok(false)`.
pub async fn update_github_installation_repos_delta(
    store: &DocumentStore,
    installation_id: i64,
    added: &[String],
    removed: &[String],
) -> Result<bool> {
    let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
        return Ok(false);
    };
    // Owned copies for the `Fn` closure (may run once per OCC retry).
    let added_owned = added.to_vec();
    let removed_owned = removed.to_vec();
    store
        .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
            let repos = data.repositories.get_or_insert_default();
            for repo in &added_owned {
                if !repos.contains(repo) {
                    repos.push(repo.clone());
                }
            }
            repos.retain(|r| !removed_owned.contains(r));
            repos.sort();
        })
        .await
}

/// Get all linked GitHub installation IDs (across all orgs).
///
/// Useful for finding "orphaned" installations on GitHub
/// that aren't in the database.
pub async fn get_all_linked_installation_ids(store: &DocumentStore) -> Result<Vec<i64>> {
    let docs = store.list_all::<GitHubInstallationDoc>().await?;
    Ok(docs.into_iter().map(|d| d.data.installation_id).collect())
}
