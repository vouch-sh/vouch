// SPDX-License-Identifier: BUSL-1.1
//! DPoP nonce and JTI database operations (RFC 9449).

use super::Pool;
use super::schema::{DpopJtiCache, DpopNonces};
use super::types::BuildSql;
use crate::db_execute;
use anyhow::Result;
use aws_lc_rs::rand as aws_rand;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Timestamp, ToSpan};
use sea_query::{Expr, Query};
use uuid::Uuid;

/// Generate a random URL-safe string.
///
/// Returns an error if the system RNG fails.
fn generate_random_string(len: usize) -> Result<String> {
    let mut bytes = vec![0u8; len];
    aws_rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Generate and store a DPoP nonce. Returns the nonce string.
pub async fn generate_dpop_nonce(pool: &Pool, validity_seconds: i64) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let nonce = generate_random_string(32)?;
    let db_type = pool.db_type();
    let now = Timestamp::now();
    let now_str = now.to_string();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .unwrap_or(now)
        .to_string();

    let sql = {
        let query = Query::insert()
            .into_table(DpopNonces::Table)
            .columns([
                DpopNonces::Id,
                DpopNonces::Nonce,
                DpopNonces::CreatedAt,
                DpopNonces::ExpiresAt,
            ])
            .values_panic([
                id.into(),
                nonce.clone().into(),
                now_str.as_str().into(),
                expires_at.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(nonce)
}

/// Validate and consume a nonce (atomic DELETE WHERE nonce=? AND expires_at > now).
///
/// Returns `true` if valid and consumed, `false` if not found or expired.
pub async fn validate_and_consume_dpop_nonce(pool: &Pool, nonce: &str) -> Result<bool> {
    let db_type = pool.db_type();
    let now_str = Timestamp::now().to_string();

    let sql = {
        let query = Query::delete()
            .from_table(DpopNonces::Table)
            .and_where(Expr::col(DpopNonces::Nonce).eq(nonce))
            .and_where(Expr::col(DpopNonces::ExpiresAt).gt(now_str.as_str()))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Check if JTI exists (replay) and store it. Returns `true` if new, `false` if replay.
///
/// Uses INSERT with conflict detection on PRIMARY KEY (jti).
pub async fn check_and_store_dpop_jti(
    pool: &Pool,
    jti: &str,
    validity_seconds: i64,
) -> Result<bool> {
    let db_type = pool.db_type();
    let now = Timestamp::now();
    let now_str = now.to_string();
    let expires_at = now
        .checked_add(validity_seconds.seconds())
        .unwrap_or(now)
        .to_string();

    let sql = {
        let query = Query::insert()
            .into_table(DpopJtiCache::Table)
            .columns([
                DpopJtiCache::Jti,
                DpopJtiCache::CreatedAt,
                DpopJtiCache::ExpiresAt,
            ])
            .values_panic([
                jti.into(),
                now_str.as_str().into(),
                expires_at.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    match db_execute!(pool, sqlx::query(&sql)) {
        Ok(_) => Ok(true),
        Err(e) => {
            // Check for unique/primary key constraint violation (replay)
            let err_str = e.to_string();
            if err_str.contains("UNIQUE")
                || err_str.contains("duplicate key")
                || err_str.contains("PRIMARY KEY")
            {
                Ok(false)
            } else {
                Err(e.into())
            }
        }
    }
}

/// Delete expired nonces. Returns count deleted.
pub async fn delete_expired_dpop_nonces(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(DpopNonces::Table)
            .and_where(Expr::col(DpopNonces::ExpiresAt).lte(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Delete expired JTIs. Returns count deleted.
pub async fn delete_expired_dpop_jtis(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(DpopJtiCache::Table)
            .and_where(Expr::col(DpopJtiCache::ExpiresAt).lte(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}
