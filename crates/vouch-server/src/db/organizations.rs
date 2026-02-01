// SPDX-License-Identifier: BUSL-1.1
//! Organization database operations.

use super::Pool;
use super::compat::BuildSql;
use super::schema::{
    CloudIntegrations, GitHubCredentialEvents, GitHubInstallations, Organizations, ScimAuditLog,
    ScimTokens, Users,
};
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute, tx_fetch_all};
use anyhow::Result;
use sea_query::{Expr, Order, Query};
use uuid::Uuid;

/// Organization record for domain-based multi-tenancy.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: String,
    pub created_by_user_id: Option<String>,
}

/// Get an organization by domain.
pub async fn get_org_by_domain(pool: &Pool, domain: &str) -> Result<Option<Organization>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedAt,
                Organizations::CreatedByUserId,
            ])
            .from(Organizations::Table)
            .and_where(Expr::col(Organizations::Domain).eq(domain))
            .to_owned();
        query.build_sql(db_type)
    };

    let org = db_fetch_optional!(pool, sqlx::query_as::<_, Organization>(&sql))?;

    Ok(org)
}

/// Get an organization by ID.
#[allow(dead_code)]
pub async fn get_org_by_id(pool: &Pool, org_id: &str) -> Result<Option<Organization>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedAt,
                Organizations::CreatedByUserId,
            ])
            .from(Organizations::Table)
            .and_where(Expr::col(Organizations::Id).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let org = db_fetch_optional!(pool, sqlx::query_as::<_, Organization>(&sql))?;

    Ok(org)
}

/// Create a new organization.
pub async fn create_organization(
    pool: &Pool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    let insert_sql = {
        let query = Query::insert()
            .into_table(Organizations::Table)
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedByUserId,
            ])
            .values_panic([
                id.clone().into(),
                domain.into(),
                name.into(),
                created_by_user_id.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&insert_sql))?;

    let select_sql = {
        let query = Query::select()
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedAt,
                Organizations::CreatedByUserId,
            ])
            .from(Organizations::Table)
            .and_where(Expr::col(Organizations::Id).eq(&id))
            .to_owned();
        query.build_sql(db_type)
    };

    let org = db_fetch_one!(pool, sqlx::query_as::<_, Organization>(&select_sql))?;

    Ok(org)
}

/// Get or create an organization by domain.
/// Returns (org, is_new) tuple where is_new indicates if the org was just created.
pub async fn get_or_create_org_by_domain(
    pool: &Pool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<(Organization, bool)> {
    // Check if org exists
    if let Some(org) = get_org_by_domain(pool, domain).await? {
        return Ok((org, false));
    }

    // Create new org
    let org = create_organization(pool, domain, name, created_by_user_id).await?;
    Ok((org, true))
}

/// Update a user's organization membership.
#[allow(dead_code)]
pub async fn set_user_org(
    pool: &Pool,
    user_id: &str,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(Users::Table)
            .value(Users::OrgId, org_id)
            .value(Users::IsOrgAdmin, is_org_admin)
            .and_where(Expr::col(Users::Id).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Count users in an organization.
#[allow(dead_code)]
pub async fn count_users_in_org(pool: &Pool, org_id: &str) -> Result<i64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .expr(Expr::col(Users::Id).count())
            .from(Users::Table)
            .and_where(Expr::col(Users::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let row: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(row.0)
}

/// List all organizations.
#[allow(dead_code)]
pub async fn list_organizations(pool: &Pool) -> Result<Vec<Organization>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedAt,
                Organizations::CreatedByUserId,
            ])
            .from(Organizations::Table)
            .order_by(Organizations::Domain, Order::Asc)
            .to_owned();
        query.build_sql(db_type)
    };

    let orgs = db_fetch_all!(pool, sqlx::query_as::<_, Organization>(&sql))?;

    Ok(orgs)
}

/// Delete an organization and all associated data.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete cloud integrations
/// 2. Delete GitHub installations
/// 3. Delete SCIM tokens (with audit log SET NULL)
/// 4. SET NULL for github_credential_events.org_id (preserve audit trail)
/// 5. SET NULL for users.org_id (users are not deleted, just unlinked)
/// 6. Delete the organization
#[allow(dead_code)]
pub async fn delete_organization(pool: &Pool, org_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Delete cloud integrations
    let sql1 = {
        let query = Query::delete()
            .from_table(CloudIntegrations::Table)
            .and_where(Expr::col(CloudIntegrations::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete GitHub installations
    let sql2 = {
        let query = Query::delete()
            .from_table(GitHubInstallations::Table)
            .and_where(Expr::col(GitHubInstallations::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql2))?;

    // 3. Delete SCIM tokens (handle audit log SET NULL first)
    let sql_select_tokens = {
        let query = Query::select()
            .column(ScimTokens::Id)
            .from(ScimTokens::Table)
            .and_where(Expr::col(ScimTokens::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    let token_ids: Vec<(String,)> = tx_fetch_all!(tx, sqlx::query_as(&sql_select_tokens))?;

    for (token_id,) in token_ids {
        let sql_update_audit = {
            let query = Query::update()
                .table(ScimAuditLog::Table)
                .value(ScimAuditLog::ActorTokenId, Option::<String>::None)
                .and_where(Expr::col(ScimAuditLog::ActorTokenId).eq(&token_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&sql_update_audit))?;
    }

    let sql_delete_tokens = {
        let query = Query::delete()
            .from_table(ScimTokens::Table)
            .and_where(Expr::col(ScimTokens::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql_delete_tokens))?;

    // 4. SET NULL for github_credential_events.org_id (preserve audit trail)
    let sql4 = {
        let query = Query::update()
            .table(GitHubCredentialEvents::Table)
            .value(GitHubCredentialEvents::OrgId, Option::<String>::None)
            .and_where(Expr::col(GitHubCredentialEvents::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql4))?;

    // 5. SET NULL for users.org_id (unlink users from org, don't delete them)
    let sql5 = {
        let query = Query::update()
            .table(Users::Table)
            .value(Users::OrgId, Option::<String>::None)
            .value(Users::IsOrgAdmin, false)
            .and_where(Expr::col(Users::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql5))?;

    // 6. Delete the organization
    let sql6 = {
        let query = Query::delete()
            .from_table(Organizations::Table)
            .and_where(Expr::col(Organizations::Id).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql6))?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}
