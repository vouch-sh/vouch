// SPDX-License-Identifier: BUSL-1.1
//! GitHub App installation database operations.

use super::Pool;
use super::schema::{GitHubCredentialEvents, GitHubInstallations};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, Func, Order, Query, SimpleExpr};
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
    pub installed_at: DbTimestamp,
    pub installed_by_user_id: Option<String>,
    pub suspended_at: Option<DbTimestamp>,
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
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(GitHubInstallations::Table)
            .columns([
                GitHubInstallations::Id,
                GitHubInstallations::OrgId,
                GitHubInstallations::InstallationId,
                GitHubInstallations::GitHubAccountLogin,
                GitHubInstallations::GitHubAccountType,
                GitHubInstallations::Permissions,
                GitHubInstallations::RepositorySelection,
                GitHubInstallations::InstalledAt,
                GitHubInstallations::InstalledByUserId,
            ])
            .values_panic([
                id.clone().into(),
                org_id.into(),
                installation_id.into(),
                github_account_login.into(),
                github_account_type.into(),
                permissions.into(),
                repository_selection.into(),
                now.as_str().into(),
                installed_by_user_id.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get all GitHub installations for an organization.
pub async fn get_github_installations_by_org(
    pool: &Pool,
    org_id: &str,
) -> Result<Vec<GitHubInstallation>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                GitHubInstallations::Id,
                GitHubInstallations::OrgId,
                GitHubInstallations::InstallationId,
                GitHubInstallations::GitHubAccountLogin,
                GitHubInstallations::GitHubAccountType,
                GitHubInstallations::Permissions,
                GitHubInstallations::RepositorySelection,
                GitHubInstallations::InstalledAt,
                GitHubInstallations::InstalledByUserId,
                GitHubInstallations::SuspendedAt,
                GitHubInstallations::Repositories,
            ])
            .from(GitHubInstallations::Table)
            .and_where(Expr::col(GitHubInstallations::OrgId).eq(org_id))
            .order_by(GitHubInstallations::GitHubAccountLogin, Order::Asc)
            .to_owned();
        query.build_sql(db_type)
    };

    let installations = db_fetch_all!(pool, sqlx::query_as::<_, GitHubInstallation>(&sql))?;

    Ok(installations)
}

/// Get GitHub installation by organization ID and GitHub account login.
pub async fn get_github_installation_by_org_and_account(
    pool: &Pool,
    org_id: &str,
    github_account: &str,
) -> Result<Option<GitHubInstallation>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                GitHubInstallations::Id,
                GitHubInstallations::OrgId,
                GitHubInstallations::InstallationId,
                GitHubInstallations::GitHubAccountLogin,
                GitHubInstallations::GitHubAccountType,
                GitHubInstallations::Permissions,
                GitHubInstallations::RepositorySelection,
                GitHubInstallations::InstalledAt,
                GitHubInstallations::InstalledByUserId,
                GitHubInstallations::SuspendedAt,
                GitHubInstallations::Repositories,
            ])
            .from(GitHubInstallations::Table)
            .and_where(Expr::col(GitHubInstallations::OrgId).eq(org_id))
            .and_where(
                SimpleExpr::FunctionCall(Func::lower(Expr::col(
                    GitHubInstallations::GitHubAccountLogin,
                )))
                .eq(github_account.to_lowercase()),
            )
            .to_owned();
        query.build_sql(db_type)
    };

    let installation = db_fetch_optional!(pool, sqlx::query_as::<_, GitHubInstallation>(&sql))?;

    Ok(installation)
}

/// Get GitHub installation by installation ID.
pub async fn get_github_installation_by_installation_id(
    pool: &Pool,
    installation_id: i64,
) -> Result<Option<GitHubInstallation>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                GitHubInstallations::Id,
                GitHubInstallations::OrgId,
                GitHubInstallations::InstallationId,
                GitHubInstallations::GitHubAccountLogin,
                GitHubInstallations::GitHubAccountType,
                GitHubInstallations::Permissions,
                GitHubInstallations::RepositorySelection,
                GitHubInstallations::InstalledAt,
                GitHubInstallations::InstalledByUserId,
                GitHubInstallations::SuspendedAt,
                GitHubInstallations::Repositories,
            ])
            .from(GitHubInstallations::Table)
            .and_where(Expr::col(GitHubInstallations::InstallationId).eq(installation_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let installation = db_fetch_optional!(pool, sqlx::query_as::<_, GitHubInstallation>(&sql))?;

    Ok(installation)
}

/// Delete GitHub installation by installation ID (used by webhook handler).
pub async fn delete_github_installation_by_installation_id(
    pool: &Pool,
    installation_id: i64,
) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(GitHubInstallations::Table)
            .and_where(Expr::col(GitHubInstallations::InstallationId).eq(installation_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Suspend GitHub installation (used by webhook handler).
pub async fn suspend_github_installation(pool: &Pool, installation_id: i64) -> Result<bool> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(GitHubInstallations::Table)
            .value(GitHubInstallations::SuspendedAt, now.as_str())
            .and_where(Expr::col(GitHubInstallations::InstallationId).eq(installation_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Unsuspend GitHub installation (used by webhook handler).
pub async fn unsuspend_github_installation(pool: &Pool, installation_id: i64) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(GitHubInstallations::Table)
            .value(GitHubInstallations::SuspendedAt, Option::<String>::None)
            .and_where(Expr::col(GitHubInstallations::InstallationId).eq(installation_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Update repositories for a GitHub installation (used by webhook handler).
pub async fn update_github_installation_repos(
    pool: &Pool,
    installation_id: i64,
    repos: &[String],
) -> Result<bool> {
    let db_type = pool.db_type();
    let repos_json = serde_json::to_string(repos)?;

    let sql = {
        let query = Query::update()
            .table(GitHubInstallations::Table)
            .value(GitHubInstallations::Repositories, repos_json.as_str())
            .and_where(Expr::col(GitHubInstallations::InstallationId).eq(installation_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

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
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(GitHubCredentialEvents::Table)
            .columns([
                GitHubCredentialEvents::Id,
                GitHubCredentialEvents::EventType,
                GitHubCredentialEvents::UserId,
                GitHubCredentialEvents::UserEmail,
                GitHubCredentialEvents::OrgId,
                GitHubCredentialEvents::InstallationId,
                GitHubCredentialEvents::SessionId,
                GitHubCredentialEvents::AuthenticatorId,
                GitHubCredentialEvents::Repositories,
                GitHubCredentialEvents::Permissions,
                GitHubCredentialEvents::TokenExpiresAt,
                GitHubCredentialEvents::Success,
                GitHubCredentialEvents::ErrorCode,
                GitHubCredentialEvents::IpAddress,
                GitHubCredentialEvents::UserAgent,
                GitHubCredentialEvents::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                params.event_type.into(),
                params.user_id.into(),
                params.user_email.into(),
                params.org_id.into(),
                params.installation_id.into(),
                params.session_id.into(),
                params.authenticator_id.into(),
                params.repositories.into(),
                params.permissions.into(),
                params.token_expires_at.into(),
                params.success.into(),
                params.error_code.into(),
                params.ip_address.into(),
                params.user_agent.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Delete old GitHub credential events (retention).
pub async fn delete_old_github_credential_events(pool: &Pool, before: &Timestamp) -> Result<u64> {
    let db_type = pool.db_type();
    let before_str = before.strftime("%Y-%m-%d %H:%M:%S").to_string();

    let sql = {
        let query = Query::delete()
            .from_table(GitHubCredentialEvents::Table)
            .and_where(Expr::col(GitHubCredentialEvents::CreatedAt).lt(before_str.as_str()))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Get all linked GitHub installation IDs (across all orgs).
///
/// Returns a list of all installation IDs that are currently linked to any organization.
/// Useful for finding "orphaned" installations on GitHub that aren't in the database.
pub async fn get_all_linked_installation_ids(pool: &Pool) -> Result<Vec<i64>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .column(GitHubInstallations::InstallationId)
            .from(GitHubInstallations::Table)
            .to_owned();
        query.build_sql(db_type)
    };

    let ids = db_fetch_all!(pool, sqlx::query_scalar::<_, i64>(&sql))?;

    Ok(ids)
}
