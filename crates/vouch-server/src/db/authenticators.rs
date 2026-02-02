// SPDX-License-Identifier: BUSL-1.1
//! Authenticator (WebAuthn credential) database operations.

use super::Pool;
use super::compat::BuildSql;
use super::schema::{Authenticators, DeviceAuthRequests, Sessions};
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, Query};
use uuid::Uuid;

/// Authenticator (credential) record.
#[derive(Debug, sqlx::FromRow)]
pub struct Authenticator {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    #[allow(dead_code)]
    pub public_key: Vec<u8>,
    /// WebAuthn signature counter (32-bit per spec).
    pub counter: i32,
    pub created_at: DbTimestamp,
    /// AAGUID (Authenticator Attestation GUID) identifies the authenticator model.
    pub aaguid: Option<String>,
    /// User handle stored in discoverable credentials (resident keys).
    #[allow(dead_code)]
    pub user_handle: Option<Vec<u8>>,
}

/// Create a new authenticator.
pub async fn create_authenticator(
    pool: &Pool,
    user_id: &str,
    name: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: Option<&str>,
    user_handle: Option<&[u8]>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::insert()
            .into_table(Authenticators::Table)
            .columns([
                Authenticators::Id,
                Authenticators::UserId,
                Authenticators::Name,
                Authenticators::CredentialId,
                Authenticators::PublicKey,
                Authenticators::Counter,
                Authenticators::CreatedAt,
                Authenticators::Aaguid,
                Authenticators::UserHandle,
            ])
            .values_panic([
                id.clone().into(),
                user_id.into(),
                name.into(),
                credential_id.into(),
                public_key.into(),
                0i32.into(),
                now.as_str().into(),
                aaguid.into(),
                user_handle.map(|h| h.to_vec()).into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get authenticators for a user.
pub async fn get_authenticators_for_user(pool: &Pool, user_id: &str) -> Result<Vec<Authenticator>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Authenticators::Id,
                Authenticators::UserId,
                Authenticators::Name,
                Authenticators::CredentialId,
                Authenticators::PublicKey,
                Authenticators::Counter,
                Authenticators::CreatedAt,
                Authenticators::Aaguid,
                Authenticators::UserHandle,
            ])
            .from(Authenticators::Table)
            .and_where(Expr::col(Authenticators::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let authenticators = db_fetch_all!(pool, sqlx::query_as::<_, Authenticator>(&sql))?;

    Ok(authenticators)
}

/// Get an authenticator by credential ID.
pub async fn get_authenticator_by_credential_id(
    pool: &Pool,
    credential_id: &[u8],
) -> Result<Option<Authenticator>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Authenticators::Id,
                Authenticators::UserId,
                Authenticators::Name,
                Authenticators::CredentialId,
                Authenticators::PublicKey,
                Authenticators::Counter,
                Authenticators::CreatedAt,
                Authenticators::Aaguid,
                Authenticators::UserHandle,
            ])
            .from(Authenticators::Table)
            .and_where(Expr::col(Authenticators::CredentialId).eq(credential_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let authenticator = db_fetch_optional!(pool, sqlx::query_as::<_, Authenticator>(&sql))?;

    Ok(authenticator)
}

/// Get an authenticator by ID.
pub async fn get_authenticator_by_id(
    pool: &Pool,
    authenticator_id: &str,
) -> Result<Option<Authenticator>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Authenticators::Id,
                Authenticators::UserId,
                Authenticators::Name,
                Authenticators::CredentialId,
                Authenticators::PublicKey,
                Authenticators::Counter,
                Authenticators::CreatedAt,
                Authenticators::Aaguid,
                Authenticators::UserHandle,
            ])
            .from(Authenticators::Table)
            .and_where(Expr::col(Authenticators::Id).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let authenticator = db_fetch_optional!(pool, sqlx::query_as::<_, Authenticator>(&sql))?;

    Ok(authenticator)
}

/// Update authenticator counter.
pub async fn update_authenticator_counter(
    pool: &Pool,
    authenticator_id: &str,
    counter: i32,
) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(Authenticators::Table)
            .value(Authenticators::Counter, counter)
            .and_where(Expr::col(Authenticators::Id).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Count the number of authenticators for a user.
pub async fn count_authenticators_for_user(pool: &Pool, user_id: &str) -> Result<i64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .expr(Expr::col(Authenticators::Id).count())
            .from(Authenticators::Table)
            .and_where(Expr::col(Authenticators::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let row: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(row.0)
}

/// Count the number of sessions for an authenticator.
pub async fn count_sessions_for_authenticator(pool: &Pool, authenticator_id: &str) -> Result<i64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .expr(Expr::col(Sessions::Id).count())
            .from(Sessions::Table)
            .and_where(Expr::col(Sessions::AuthenticatorId).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let row: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(row.0)
}

/// Delete an authenticator by ID.
/// Returns the number of rows affected.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Clear authenticator_id references in device_auth_requests
/// 2. Delete sessions using this authenticator
/// 3. Delete the authenticator
pub async fn delete_authenticator(pool: &Pool, authenticator_id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Clear authenticator_id references in device_auth_requests
    let sql1 = {
        let query = Query::update()
            .table(DeviceAuthRequests::Table)
            .value(DeviceAuthRequests::AuthenticatorId, Option::<String>::None)
            .and_where(Expr::col(DeviceAuthRequests::AuthenticatorId).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete sessions using this authenticator
    let sql2 = {
        let query = Query::delete()
            .from_table(Sessions::Table)
            .and_where(Expr::col(Sessions::AuthenticatorId).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql2))?;

    // 3. Delete the authenticator
    let sql3 = {
        let query = Query::delete()
            .from_table(Authenticators::Table)
            .and_where(Expr::col(Authenticators::Id).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql3))?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

/// Update an authenticator's name.
pub async fn update_authenticator_name(
    pool: &Pool,
    authenticator_id: &str,
    name: &str,
) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(Authenticators::Table)
            .value(Authenticators::Name, name)
            .and_where(Expr::col(Authenticators::Id).eq(authenticator_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}
