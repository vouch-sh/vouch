// SPDX-License-Identifier: BUSL-1.1
//! Trusted JWT issuer database operations (RFC 7523).

use super::Pool;
use super::schema::TrustedJwtIssuers;
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use jiff_sqlx::ToSqlx;
use sea_query::{Expr, Order, Query};
use uuid::Uuid;

/// Default subject claim mapping for new trusted issuers.
pub const DEFAULT_SUBJECT_CLAIM_MAPPING: &str = "email";

/// Default maximum token lifetime in seconds for new trusted issuers.
pub const DEFAULT_MAX_TOKEN_LIFETIME_SECONDS: i32 = 3600;

/// Trusted JWT issuer record (RFC 7523).
#[derive(Debug, sqlx::FromRow)]
pub struct TrustedJwtIssuer {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub description: Option<String>,
    pub jwks_uri: String,
    pub jwks_cache: Option<String>,
    pub jwks_cached_at: Option<DbTimestamp>,
    pub subject_claim_mapping: String,
    pub allowed_scopes: Option<String>,
    pub max_token_lifetime_seconds: i32,
    pub enabled: bool,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

/// Columns to select for TrustedJwtIssuer queries.
const ISSUER_COLUMNS: [TrustedJwtIssuers; 13] = [
    TrustedJwtIssuers::Id,
    TrustedJwtIssuers::Issuer,
    TrustedJwtIssuers::Name,
    TrustedJwtIssuers::Description,
    TrustedJwtIssuers::JwksUri,
    TrustedJwtIssuers::JwksCache,
    TrustedJwtIssuers::JwksCachedAt,
    TrustedJwtIssuers::SubjectClaimMapping,
    TrustedJwtIssuers::AllowedScopes,
    TrustedJwtIssuers::MaxTokenLifetimeSeconds,
    TrustedJwtIssuers::Enabled,
    TrustedJwtIssuers::CreatedAt,
    TrustedJwtIssuers::UpdatedAt,
];

/// Create a new trusted JWT issuer.
#[allow(clippy::too_many_arguments)]
pub async fn create_trusted_jwt_issuer(
    pool: &Pool,
    issuer: &str,
    name: &str,
    description: Option<&str>,
    jwks_uri: &str,
    subject_claim_mapping: Option<&str>,
    allowed_scopes: Option<&str>,
    max_token_lifetime_seconds: Option<i32>,
) -> Result<TrustedJwtIssuer> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now_ts = Timestamp::now();
    let now = now_ts.to_string();
    let mapping = subject_claim_mapping.unwrap_or(DEFAULT_SUBJECT_CLAIM_MAPPING);
    let max_lifetime = max_token_lifetime_seconds.unwrap_or(DEFAULT_MAX_TOKEN_LIFETIME_SECONDS);

    let sql = {
        let query = Query::insert()
            .into_table(TrustedJwtIssuers::Table)
            .columns([
                TrustedJwtIssuers::Id,
                TrustedJwtIssuers::Issuer,
                TrustedJwtIssuers::Name,
                TrustedJwtIssuers::Description,
                TrustedJwtIssuers::JwksUri,
                TrustedJwtIssuers::SubjectClaimMapping,
                TrustedJwtIssuers::AllowedScopes,
                TrustedJwtIssuers::MaxTokenLifetimeSeconds,
                TrustedJwtIssuers::Enabled,
                TrustedJwtIssuers::CreatedAt,
                TrustedJwtIssuers::UpdatedAt,
            ])
            .values_panic([
                id.clone().into(),
                issuer.into(),
                name.into(),
                description.into(),
                jwks_uri.into(),
                mapping.into(),
                allowed_scopes.into(),
                max_lifetime.into(),
                true.into(),
                now.as_str().into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(TrustedJwtIssuer {
        id,
        issuer: issuer.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        jwks_uri: jwks_uri.to_string(),
        jwks_cache: None,
        jwks_cached_at: None,
        subject_claim_mapping: mapping.to_string(),
        allowed_scopes: allowed_scopes.map(String::from),
        max_token_lifetime_seconds: max_lifetime,
        enabled: true,
        created_at: now_ts.to_sqlx(),
        updated_at: now_ts.to_sqlx(),
    })
}

/// Get a trusted JWT issuer by its issuer URL.
pub async fn get_trusted_jwt_issuer_by_issuer(
    pool: &Pool,
    issuer: &str,
) -> Result<Option<TrustedJwtIssuer>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns(ISSUER_COLUMNS)
            .from(TrustedJwtIssuers::Table)
            .and_where(Expr::col(TrustedJwtIssuers::Issuer).eq(issuer))
            .to_owned();
        query.build_sql(db_type)
    };

    let issuer = db_fetch_optional!(pool, sqlx::query_as::<_, TrustedJwtIssuer>(&sql))?;

    Ok(issuer)
}

/// List all trusted JWT issuers.
pub async fn list_trusted_jwt_issuers(pool: &Pool) -> Result<Vec<TrustedJwtIssuer>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns(ISSUER_COLUMNS)
            .from(TrustedJwtIssuers::Table)
            .order_by(TrustedJwtIssuers::CreatedAt, Order::Desc)
            .to_owned();
        query.build_sql(db_type)
    };

    let issuers = db_fetch_all!(pool, sqlx::query_as::<_, TrustedJwtIssuer>(&sql))?;

    Ok(issuers)
}

/// Update a trusted JWT issuer.
#[allow(clippy::too_many_arguments)]
pub async fn update_trusted_jwt_issuer(
    pool: &Pool,
    id: &str,
    name: &str,
    description: Option<&str>,
    jwks_uri: &str,
    subject_claim_mapping: &str,
    allowed_scopes: Option<&str>,
    max_token_lifetime_seconds: i32,
    enabled: bool,
) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(TrustedJwtIssuers::Table)
            .value(TrustedJwtIssuers::Name, name)
            .value(TrustedJwtIssuers::Description, description)
            .value(TrustedJwtIssuers::JwksUri, jwks_uri)
            .value(
                TrustedJwtIssuers::SubjectClaimMapping,
                subject_claim_mapping,
            )
            .value(TrustedJwtIssuers::AllowedScopes, allowed_scopes)
            .value(
                TrustedJwtIssuers::MaxTokenLifetimeSeconds,
                max_token_lifetime_seconds,
            )
            .value(TrustedJwtIssuers::Enabled, enabled)
            .value(TrustedJwtIssuers::UpdatedAt, now.as_str())
            .and_where(Expr::col(TrustedJwtIssuers::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Delete a trusted JWT issuer.
pub async fn delete_trusted_jwt_issuer(pool: &Pool, id: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(TrustedJwtIssuers::Table)
            .and_where(Expr::col(TrustedJwtIssuers::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Update the cached JWKS for a trusted issuer.
pub async fn update_issuer_jwks_cache(pool: &Pool, id: &str, jwks_json: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(TrustedJwtIssuers::Table)
            .value(TrustedJwtIssuers::JwksCache, jwks_json)
            .value(TrustedJwtIssuers::JwksCachedAt, now.as_str())
            .and_where(Expr::col(TrustedJwtIssuers::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}
