// SPDX-License-Identifier: BUSL-1.1
//! GitHub App installation database operations.

use super::Pool;
use super::compat::now_expr;
use crate::{db_execute, db_fetch_all, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use uuid::Uuid;

// ============================================================================
// GitHub App Installations
// ============================================================================

/// GitHub App installation record.
#[derive(Debug, sqlx::FromRow)]
pub struct GitHubInstallation {
    pub id: String,
    pub org_id: String,
    pub installation_id: i64,
    pub github_account_login: String,
    pub github_account_type: String,
    pub permissions: String,
    pub repository_selection: String,
    pub installed_at: String,
    pub installed_by_user_id: Option<String>,
    pub suspended_at: Option<String>,
    /// JSON array of repository names when repository_selection is "selected".
    pub repositories: Option<String>,
}

/// Create a new GitHub App installation for an organization.
#[allow(clippy::too_many_arguments)]
pub async fn create_github_installation(
    pool: &Pool,
    org_id: &str,
    installation_id: i64,
    github_account_login: &str,
    github_account_type: &str,
    permissions: &str,
    repository_selection: &str,
    installed_by_user_id: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO github_installations (id, org_id, installation_id, github_account_login, github_account_type, permissions, repository_selection, installed_by_user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(org_id)
        .bind(installation_id)
        .bind(github_account_login)
        .bind(github_account_type)
        .bind(permissions)
        .bind(repository_selection)
        .bind(installed_by_user_id)
    )?;

    Ok(id)
}

/// Get all GitHub installations for an organization.
pub async fn get_github_installations_by_org(
    pool: &Pool,
    org_id: &str,
) -> Result<Vec<GitHubInstallation>> {
    let installations = db_fetch_all!(
        pool,
        sqlx::query_as::<_, GitHubInstallation>(
            "SELECT id, org_id, installation_id, github_account_login, github_account_type, permissions, repository_selection, installed_at, installed_by_user_id, suspended_at, repositories
         FROM github_installations WHERE org_id = ? ORDER BY github_account_login"
        )
        .bind(org_id)
    )?;

    Ok(installations)
}

/// Get GitHub installation by organization ID and GitHub account login.
pub async fn get_github_installation_by_org_and_account(
    pool: &Pool,
    org_id: &str,
    github_account: &str,
) -> Result<Option<GitHubInstallation>> {
    let installation = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, GitHubInstallation>(
            "SELECT id, org_id, installation_id, github_account_login, github_account_type, permissions, repository_selection, installed_at, installed_by_user_id, suspended_at, repositories
         FROM github_installations WHERE org_id = ? AND LOWER(github_account_login) = LOWER(?)"
        )
        .bind(org_id)
        .bind(github_account)
    )?;

    Ok(installation)
}

/// Get GitHub installation by installation ID.
pub async fn get_github_installation_by_installation_id(
    pool: &Pool,
    installation_id: i64,
) -> Result<Option<GitHubInstallation>> {
    let installation = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, GitHubInstallation>(
            "SELECT id, org_id, installation_id, github_account_login, github_account_type, permissions, repository_selection, installed_at, installed_by_user_id, suspended_at, repositories
         FROM github_installations WHERE installation_id = ?"
        )
        .bind(installation_id)
    )?;

    Ok(installation)
}

/// Delete GitHub installation by installation ID (used by webhook handler).
pub async fn delete_github_installation_by_installation_id(
    pool: &Pool,
    installation_id: i64,
) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM github_installations WHERE installation_id = ?")
            .bind(installation_id)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Suspend GitHub installation (used by webhook handler).
pub async fn suspend_github_installation(pool: &Pool, installation_id: i64) -> Result<bool> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql =
        format!("UPDATE github_installations SET suspended_at = {now} WHERE installation_id = ?");

    let result = db_execute!(pool, sqlx::query(&sql).bind(installation_id))?;

    Ok(result.rows_affected() > 0)
}

/// Unsuspend GitHub installation (used by webhook handler).
pub async fn unsuspend_github_installation(pool: &Pool, installation_id: i64) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query(
            "UPDATE github_installations SET suspended_at = NULL WHERE installation_id = ?"
        )
        .bind(installation_id)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Update repositories for a GitHub installation (used by webhook handler).
pub async fn update_github_installation_repos(
    pool: &Pool,
    installation_id: i64,
    repos: &[String],
) -> Result<bool> {
    let repos_json = serde_json::to_string(repos)?;
    let result = db_execute!(
        pool,
        sqlx::query("UPDATE github_installations SET repositories = ? WHERE installation_id = ?")
            .bind(&repos_json)
            .bind(installation_id)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Update repositories for a GitHub installation by adding/removing repos (used by webhook handler).
pub async fn update_github_installation_repos_delta(
    pool: &Pool,
    installation_id: i64,
    added: &[String],
    removed: &[String],
) -> Result<bool> {
    // Fetch current repos
    let installation = get_github_installation_by_installation_id(pool, installation_id).await?;
    let Some(installation) = installation else {
        return Ok(false);
    };

    // Parse existing repos
    let mut repos: Vec<String> = installation
        .repositories
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();

    // Apply delta
    for repo in added {
        if !repos.contains(repo) {
            repos.push(repo.clone());
        }
    }
    repos.retain(|r| !removed.contains(r));

    // Sort for consistency
    repos.sort();

    // Save
    update_github_installation_repos(pool, installation_id, &repos).await
}

// ============================================================================
// GitHub Credential Events (Audit Log)
// ============================================================================

/// Parameters for logging a GitHub credential event.
pub struct GitHubCredentialEventParams<'a> {
    pub event_type: &'a str,
    pub user_id: &'a str,
    pub user_email: &'a str,
    pub org_id: Option<&'a str>,
    pub installation_id: Option<i64>,
    pub session_id: Option<&'a str>,
    pub authenticator_id: Option<&'a str>,
    pub repositories: Option<&'a str>,
    pub permissions: Option<&'a str>,
    pub token_expires_at: Option<&'a str>,
    pub success: bool,
    pub error_code: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Log a GitHub credential event (audit log).
pub async fn log_github_credential_event(
    pool: &Pool,
    params: GitHubCredentialEventParams<'_>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO github_credential_events (id, event_type, user_id, user_email, org_id, installation_id, session_id, authenticator_id, repositories, permissions, token_expires_at, success, error_code, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(params.event_type)
        .bind(params.user_id)
        .bind(params.user_email)
        .bind(params.org_id)
        .bind(params.installation_id)
        .bind(params.session_id)
        .bind(params.authenticator_id)
        .bind(params.repositories)
        .bind(params.permissions)
        .bind(params.token_expires_at)
        .bind(params.success)
        .bind(params.error_code)
        .bind(params.ip_address)
        .bind(params.user_agent)
    )?;

    Ok(id)
}

/// Delete old GitHub credential events (retention).
pub async fn delete_old_github_credential_events(pool: &Pool, before: &Timestamp) -> Result<u64> {
    let before_str = before.strftime("%Y-%m-%d %H:%M:%S").to_string();
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM github_credential_events WHERE created_at < ?").bind(before_str)
    )?;

    Ok(result.rows_affected())
}
