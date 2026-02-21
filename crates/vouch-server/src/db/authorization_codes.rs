// SPDX-License-Identifier: BUSL-1.1
//! Authorization code single-use enforcement (RFC 6749 Section 10.5).
//!
//! Stores hashes of issued authorization codes to detect and prevent replay.
//! When a code is exchanged it is marked as consumed; a second attempt to
//! exchange the same code will fail and should trigger revocation of any
//! tokens issued from it (per RFC 6749 Section 10.5).

use super::Pool;
use super::schema::AuthorizationCodes;
use super::types::BuildSql;
use crate::{db_execute, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, Query};

/// Record an issued authorization code.
///
/// `code_hash` is the SHA-256 hash of the raw code value (base64url-encoded).
/// The raw code is never stored.
///
/// # Errors
///
/// Returns an error if the database operation fails.
pub async fn store_authorization_code(
    pool: &Pool,
    code_hash: &str,
    client_id: &str,
    user_id: &str,
    expires_at: &str,
) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(AuthorizationCodes::Table)
            .columns([
                AuthorizationCodes::CodeHash,
                AuthorizationCodes::ClientId,
                AuthorizationCodes::UserId,
                AuthorizationCodes::CreatedAt,
                AuthorizationCodes::ExpiresAt,
            ])
            .values_panic([
                code_hash.into(),
                client_id.into(),
                user_id.into(),
                now.as_str().into(),
                expires_at.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;
    Ok(())
}

/// Try to consume an authorization code.
///
/// Returns `true` if the code was successfully consumed (first use).
/// Returns `false` if the code was already consumed or does not exist.
///
/// # Errors
///
/// Returns an error if the database operation fails.
pub async fn try_consume_authorization_code(pool: &Pool, code_hash: &str) -> Result<bool> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Only consume if not already consumed and not expired
    let sql = {
        let query = Query::update()
            .table(AuthorizationCodes::Table)
            .value(AuthorizationCodes::ConsumedAt, now.as_str())
            .and_where(Expr::col(AuthorizationCodes::CodeHash).eq(code_hash))
            .and_where(Expr::col(AuthorizationCodes::ConsumedAt).is_null())
            .and_where(Expr::col(AuthorizationCodes::ExpiresAt).gt(&now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;
    Ok(result.rows_affected() > 0)
}

/// Check if an authorization code has already been consumed (replay detection).
///
/// Returns `true` if the code exists and has been consumed.
///
/// # Errors
///
/// Returns an error if the database operation fails.
pub async fn is_authorization_code_consumed(pool: &Pool, code_hash: &str) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .column(AuthorizationCodes::CodeHash)
            .from(AuthorizationCodes::Table)
            .and_where(Expr::col(AuthorizationCodes::CodeHash).eq(code_hash))
            .and_where(Expr::col(AuthorizationCodes::ConsumedAt).is_not_null())
            .to_owned();
        query.build_sql(db_type)
    };

    let result: Option<(String,)> = db_fetch_optional!(pool, sqlx::query_as(&sql))?;
    Ok(result.is_some())
}

/// Get user_id and client_id for a consumed authorization code.
///
/// Used during replay detection to identify which tokens to revoke
/// per RFC 6749 Section 10.5.
///
/// # Errors
///
/// Returns an error if the database operation fails.
pub async fn get_authorization_code_owner(
    pool: &Pool,
    code_hash: &str,
) -> Result<Option<(String, String)>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([AuthorizationCodes::UserId, AuthorizationCodes::ClientId])
            .from(AuthorizationCodes::Table)
            .and_where(Expr::col(AuthorizationCodes::CodeHash).eq(code_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let result: Option<(String, String)> = db_fetch_optional!(pool, sqlx::query_as(&sql))?;
    Ok(result)
}

/// Delete expired authorization codes.
///
/// # Errors
///
/// Returns an error if the database operation fails.
pub async fn delete_expired_authorization_codes(pool: &Pool) -> Result<u64> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::delete()
            .from_table(AuthorizationCodes::Table)
            .and_where(Expr::col(AuthorizationCodes::ExpiresAt).lt(&now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;
    Ok(result.rows_affected())
}
