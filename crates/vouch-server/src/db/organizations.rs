// SPDX-License-Identifier: BUSL-1.1
//! Organization database operations.

use super::Pool;
use super::schema::{
    CloudIntegrations, GitHubCredentialEvents, GitHubInstallations, Organizations, ScimAuditLog,
    ScimTokens, Users,
};
use super::types::BuildSql;
use super::types::DbTimestamp;
#[cfg(any(test, feature = "test-utils"))]
use crate::{db_execute, db_fetch_one};
use crate::{tx_execute, tx_fetch_all};
use anyhow::Result;
#[cfg(any(test, feature = "test-utils"))]
use jiff::Timestamp;
use sea_query::{Expr, Query};
#[cfg(any(test, feature = "test-utils"))]
use uuid::Uuid;

/// Organization record for domain-based multi-tenancy.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Organization {
    pub id: String,
    pub domain: String,
    pub name: Option<String>,
    pub created_at: DbTimestamp,
    pub created_by_user_id: Option<String>,
}

/// Create a new organization.
///
/// Note: This function is only used in tests. Production code uses the
/// transactional `enroll_user_with_org` function which handles organization
/// creation atomically with user creation.
#[cfg(any(test, feature = "test-utils"))]
pub async fn create_organization(
    pool: &Pool,
    domain: &str,
    name: Option<&str>,
    created_by_user_id: Option<&str>,
) -> Result<Organization> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    let insert_sql = {
        let query = Query::insert()
            .into_table(Organizations::Table)
            .columns([
                Organizations::Id,
                Organizations::Domain,
                Organizations::Name,
                Organizations::CreatedAt,
                Organizations::CreatedByUserId,
            ])
            .values_panic([
                id.clone().into(),
                domain.into(),
                name.into(),
                now.as_str().into(),
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

/// Get an organization's domain by ID.
///
/// Returns the domain (hd claim) for the organization, or None if not found.
pub async fn get_organization_domain(pool: &Pool, org_id: &str) -> Result<Option<String>> {
    use crate::db_fetch_optional;

    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .column(Organizations::Domain)
            .from(Organizations::Table)
            .and_where(Expr::col(Organizations::Id).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let domain = db_fetch_optional!(pool, sqlx::query_scalar::<_, String>(&sql))?;

    Ok(domain)
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
