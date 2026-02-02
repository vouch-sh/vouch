// SPDX-License-Identifier: BUSL-1.1
//! User database operations.

use super::Pool;
use super::schema::{
    AuthEvents, Authenticators, DeviceAuthRequests, EnrollmentSessions, OAuthClientSecrets,
    OAuthClients, OAuthUsageEvents, ScimGroupMembers, Sessions, SshRevokedCertificates,
    TokenExchanges, Users,
};
use super::types::BuildSql;
#[cfg(any(test, feature = "test-utils"))]
use crate::{db_execute, db_fetch_one};
use crate::{db_fetch_optional, tx_execute, tx_fetch_all};
use anyhow::Result;
#[cfg(any(test, feature = "test-utils"))]
use jiff::Timestamp;
#[cfg(any(test, feature = "test-utils"))]
use sea_query::OnConflict;
use sea_query::{Expr, Query};
#[cfg(any(test, feature = "test-utils"))]
use uuid::Uuid;

/// User record.
#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    #[allow(dead_code)]
    pub name: Option<String>,
    /// Organization ID (NULL for personal accounts like gmail.com).
    pub org_id: Option<String>,
    /// Whether this user is an admin of their organization.
    pub is_org_admin: bool,
}

/// Create or get a user by email.
///
/// Note: This function is only used in tests. Production code uses the
/// transactional `enroll_user_with_org` function.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user(pool: &Pool, email: &str, name: Option<&str>) -> Result<User> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    // Try to insert, ignore if exists using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([Users::Id, Users::Email, Users::Name, Users::CreatedAt])
            .values_panic([
                id.clone().into(),
                email.into(),
                name.into(),
                now.as_str().into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Fetch the user
    let fetch_sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Email).eq(email))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_one!(pool, sqlx::query_as::<_, User>(&fetch_sql))?;

    Ok(user)
}

/// Create or get a user by email, associating them with an organization.
///
/// Note: This function is only used in tests. Production code uses the
/// transactional `enroll_user_with_org` function which handles organization
/// and user creation atomically.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user_with_org(
    pool: &Pool,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<User> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    // Try to insert with org info, ignore if exists using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
                Users::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                email.into(),
                name.into(),
                org_id.into(),
                is_org_admin.into(),
                now.as_str().into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Fetch the user
    let fetch_sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Email).eq(email))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_one!(pool, sqlx::query_as::<_, User>(&fetch_sql))?;

    Ok(user)
}

/// Get a user by email.
#[allow(dead_code)]
pub async fn get_user_by_email(pool: &Pool, email: &str) -> Result<Option<User>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Email).eq(email))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_optional!(pool, sqlx::query_as::<_, User>(&sql))?;

    Ok(user)
}

/// Get a user by ID.
pub async fn get_user_by_id(pool: &Pool, user_id: &str) -> Result<Option<User>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::OrgId,
                Users::IsOrgAdmin,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_optional!(pool, sqlx::query_as::<_, User>(&sql))?;

    Ok(user)
}

/// Delete a user and all associated data.
///
/// Performs application-level cascade deletes for DSQL compatibility.
/// Order matters - child records must be deleted before parent records.
pub async fn delete_user(pool: &Pool, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Delete sessions (references user_id and authenticator_id)
    let sql1 = {
        let query = Query::delete()
            .from_table(Sessions::Table)
            .and_where(Expr::col(Sessions::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete enrollment sessions
    let sql2 = {
        let query = Query::delete()
            .from_table(EnrollmentSessions::Table)
            .and_where(Expr::col(EnrollmentSessions::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql2))?;

    // 3. Delete auth events
    let sql3 = {
        let query = Query::delete()
            .from_table(AuthEvents::Table)
            .and_where(Expr::col(AuthEvents::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql3))?;

    // 4. Delete SCIM group memberships
    let sql4 = {
        let query = Query::delete()
            .from_table(ScimGroupMembers::Table)
            .and_where(Expr::col(ScimGroupMembers::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql4))?;

    // 5. Handle token exchanges - SET NULL for actor, DELETE for subject
    let sql5a = {
        let query = Query::update()
            .table(TokenExchanges::Table)
            .value(TokenExchanges::ActorUserId, Option::<String>::None)
            .and_where(Expr::col(TokenExchanges::ActorUserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql5a))?;

    let sql5b = {
        let query = Query::delete()
            .from_table(TokenExchanges::Table)
            .and_where(Expr::col(TokenExchanges::SubjectUserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql5b))?;

    // 6. Delete SSH revoked certificates
    let sql6 = {
        let query = Query::delete()
            .from_table(SshRevokedCertificates::Table)
            .and_where(Expr::col(SshRevokedCertificates::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql6))?;

    // 7. Delete OAuth clients and their children
    // First get all client IDs owned by this user
    let sql7_select = {
        let query = Query::select()
            .column(OAuthClients::Id)
            .from(OAuthClients::Table)
            .and_where(Expr::col(OAuthClients::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    let client_ids: Vec<(String,)> = tx_fetch_all!(tx, sqlx::query_as(&sql7_select))?;

    for (client_id,) in client_ids {
        // Delete usage events first
        let sql_usage = {
            let query = Query::delete()
                .from_table(OAuthUsageEvents::Table)
                .and_where(Expr::col(OAuthUsageEvents::OAuthClientId).eq(&client_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&sql_usage))?;

        // Delete secrets
        let sql_secrets = {
            let query = Query::delete()
                .from_table(OAuthClientSecrets::Table)
                .and_where(Expr::col(OAuthClientSecrets::OAuthClientId).eq(&client_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&sql_secrets))?;

        // Delete client
        let sql_client = {
            let query = Query::delete()
                .from_table(OAuthClients::Table)
                .and_where(Expr::col(OAuthClients::Id).eq(&client_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&sql_client))?;
    }

    // 8. Clear authenticator references in device_auth_requests, then delete authenticators
    // For the subquery, we need to use raw SQL as sea-query subqueries are complex
    let sql8a = {
        let subquery = Query::select()
            .column(Authenticators::Id)
            .from(Authenticators::Table)
            .and_where(Expr::col(Authenticators::UserId).eq(user_id))
            .to_owned();
        let query = Query::update()
            .table(DeviceAuthRequests::Table)
            .value(DeviceAuthRequests::AuthenticatorId, Option::<String>::None)
            .and_where(Expr::col(DeviceAuthRequests::AuthenticatorId).in_subquery(subquery))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql8a))?;

    let sql8b = {
        let query = Query::delete()
            .from_table(Authenticators::Table)
            .and_where(Expr::col(Authenticators::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql8b))?;

    // 9. Finally delete the user
    let sql9 = {
        let query = Query::delete()
            .from_table(Users::Table)
            .and_where(Expr::col(Users::Id).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql9))?;

    tx.commit().await?;
    Ok(())
}
