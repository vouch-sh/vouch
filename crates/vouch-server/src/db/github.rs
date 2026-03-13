// SPDX-License-Identifier: BUSL-1.1
//! GitHub App installation database operations.

use std::collections::HashMap;

use super::audit::AuditStore;
use super::document_type::Document;
use super::documents::audit::GitHubCredentialAuditData;
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

/// Create a new GitHub App installation for an organization.
#[allow(clippy::too_many_arguments)]
pub async fn create_github_installation(
    store: &DocumentStore,
    org_id: &str,
    installation_id: i64,
    github_account_login: &str,
    github_account_type: &str,
    permissions: &HashMap<String, String>,
    repository_selection: &str,
    installed_by_user_id: Option<&str>,
) -> Result<String> {
    let doc = GitHubInstallationDoc {
        org_id: org_id.to_string(),
        installation_id,
        github_account_login: github_account_login.to_string(),
        github_account_type: github_account_type.to_string(),
        permissions: permissions.clone(),
        repository_selection: repository_selection.to_string(),
        installed_at: Timestamp::now(),
        installed_by_user_id: installed_by_user_id.map(String::from),
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

/// Suspend GitHub installation (used by webhook handler).
pub async fn suspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    if let Some(doc) = doc {
        let mut data = doc.data;
        data.suspended_at = Some(Timestamp::now());
        store.update(&doc.id, &data).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Unsuspend GitHub installation (used by webhook handler).
pub async fn unsuspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    if let Some(doc) = doc {
        let mut data = doc.data;
        data.suspended_at = None;
        store.update(&doc.id, &data).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Update repositories for a GitHub installation.
pub async fn update_github_installation_repos(
    store: &DocumentStore,
    installation_id: i64,
    repos: &[String],
) -> Result<bool> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    if let Some(doc) = doc {
        let mut data = doc.data;
        data.repositories = Some(repos.to_vec());
        store.update(&doc.id, &data).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Update repositories for a GitHub installation by
/// adding/removing repos (used by webhook handler).
pub async fn update_github_installation_repos_delta(
    store: &DocumentStore,
    installation_id: i64,
    added: &[String],
    removed: &[String],
) -> Result<bool> {
    let installation = get_github_installation_by_installation_id(store, installation_id).await?;

    let Some(installation) = installation else {
        return Ok(false);
    };

    let mut repos: Vec<String> = installation.repositories.unwrap_or_default();

    // Apply delta
    for repo in added {
        if !repos.contains(repo) {
            repos.push(repo.clone());
        }
    }
    repos.retain(|r| !removed.contains(r));

    // Sort for consistency
    repos.sort();

    update_github_installation_repos(store, installation_id, &repos).await
}

// ============================================================================
// GitHub Credential Events (Audit Log)
// ============================================================================

/// Log a GitHub credential event (audit log).
pub async fn log_github_credential_event(
    audit: &AuditStore,
    user_id: &str,
    user_email: &str,
    mut data: GitHubCredentialAuditData,
    ip: Option<std::net::IpAddr>,
) -> Result<String> {
    data.client_ip = ip.map(|a| a.to_string());
    let geo = ip.and_then(crate::geo::lookup);
    data.country_code = geo.as_ref().map(|g| g.country_code.clone());
    data.asn = geo.as_ref().and_then(|g| g.asn);
    data.org_name = geo.as_ref().and_then(|g| g.org_name.clone());
    let data_json = serde_json::to_string(&data)?;

    audit
        .insert_event(
            "github_credential",
            Some(user_id),
            Some(user_email),
            &data_json,
        )
        .await
}

/// Delete old GitHub credential events (retention).
pub async fn delete_old_github_credential_events(
    audit: &AuditStore,
    before: Timestamp,
) -> Result<u64> {
    let before_str = before.to_string();
    audit
        .delete_old_events("github_credential", &before_str)
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
