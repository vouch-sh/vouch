// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 (RFC 7643/7644) database operations.

use super::Pool;
use super::schema::{ScimAuditLog, ScimGroupMembers, ScimGroups, ScimTokens, Users};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Alias, Asterisk, Expr, Func, JoinType, OnConflict, Order, Query};
use uuid::Uuid;

// ============================================================================
// SCIM Tokens
// ============================================================================

/// Default scope for new SCIM tokens: full access.
pub const SCIM_DEFAULT_SCOPE: &str = "users:read,users:write,groups:read,groups:write";

/// SCIM token record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimToken {
    pub id: String,
    pub token_hash: String,
    pub org_id: Option<String>,
    pub description: Option<String>,
    pub created_at: DbTimestamp,
    pub last_used_at: Option<DbTimestamp>,
    pub expires_at: Option<DbTimestamp>,
    pub scope: String,
}

/// Get a SCIM token by its hash.
pub async fn get_scim_token_by_hash(pool: &Pool, token_hash: &str) -> Result<Option<ScimToken>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                ScimTokens::Id,
                ScimTokens::TokenHash,
                ScimTokens::OrgId,
                ScimTokens::Description,
                ScimTokens::CreatedAt,
                ScimTokens::LastUsedAt,
                ScimTokens::ExpiresAt,
                ScimTokens::Scope,
            ])
            .from(ScimTokens::Table)
            .and_where(Expr::col(ScimTokens::TokenHash).eq(token_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let token = db_fetch_optional!(pool, sqlx::query_as::<_, ScimToken>(&sql))?;

    Ok(token)
}

/// Update SCIM token last used timestamp.
pub async fn update_scim_token_last_used(pool: &Pool, token_id: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(ScimTokens::Table)
            .value(ScimTokens::LastUsedAt, now.as_str())
            .and_where(Expr::col(ScimTokens::Id).eq(token_id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Create a new SCIM token.
#[allow(dead_code)]
pub async fn create_scim_token(
    pool: &Pool,
    token_hash: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
    org_id: Option<&str>,
    scope: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();
    let scope_val = scope.unwrap_or(SCIM_DEFAULT_SCOPE);

    let sql = {
        let query = Query::insert()
            .into_table(ScimTokens::Table)
            .columns([
                ScimTokens::Id,
                ScimTokens::TokenHash,
                ScimTokens::OrgId,
                ScimTokens::Description,
                ScimTokens::ExpiresAt,
                ScimTokens::CreatedAt,
                ScimTokens::Scope,
            ])
            .values_panic([
                id.clone().into(),
                token_hash.into(),
                org_id.into(),
                description.into(),
                expires_at.into(),
                now.as_str().into(),
                scope_val.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Delete a SCIM token, scoped to the given organization.
///
/// Performs application-level SET NULL for DSQL compatibility:
/// 1. Set scim_audit_log.actor_token_id to NULL for this token
/// 2. Delete the token (only if it belongs to the specified org)
///
/// Returns `Ok(true)` if a token was deleted, `Ok(false)` if no matching
/// token was found for the given org (prevents cross-org deletion).
#[allow(dead_code)]
pub async fn delete_scim_token(pool: &Pool, token_id: &str, org_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. SET NULL for audit log references (preserves audit trail)
    let sql1 = {
        let query = Query::update()
            .table(ScimAuditLog::Table)
            .value(ScimAuditLog::ActorTokenId, Option::<String>::None)
            .and_where(Expr::col(ScimAuditLog::ActorTokenId).eq(token_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete the token (scoped to org to prevent cross-org deletion)
    let sql2 = {
        let query = Query::delete()
            .from_table(ScimTokens::Table)
            .and_where(Expr::col(ScimTokens::Id).eq(token_id))
            .and_where(Expr::col(ScimTokens::OrgId).eq(org_id))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql2))?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// List SCIM tokens, optionally filtered by organization.
#[allow(dead_code)]
pub async fn list_scim_tokens(pool: &Pool, org_id: Option<&str>) -> Result<Vec<ScimToken>> {
    let db_type = pool.db_type();

    let tokens = if let Some(org_id) = org_id {
        let sql = {
            let query = Query::select()
                .columns([
                    ScimTokens::Id,
                    ScimTokens::TokenHash,
                    ScimTokens::OrgId,
                    ScimTokens::Description,
                    ScimTokens::CreatedAt,
                    ScimTokens::LastUsedAt,
                    ScimTokens::ExpiresAt,
                    ScimTokens::Scope,
                ])
                .from(ScimTokens::Table)
                .and_where(Expr::col(ScimTokens::OrgId).eq(org_id))
                .order_by(ScimTokens::CreatedAt, Order::Desc)
                .to_owned();
            query.build_sql(db_type)
        };
        db_fetch_all!(pool, sqlx::query_as::<_, ScimToken>(&sql))?
    } else {
        let sql = {
            let query = Query::select()
                .columns([
                    ScimTokens::Id,
                    ScimTokens::TokenHash,
                    ScimTokens::OrgId,
                    ScimTokens::Description,
                    ScimTokens::CreatedAt,
                    ScimTokens::LastUsedAt,
                    ScimTokens::ExpiresAt,
                    ScimTokens::Scope,
                ])
                .from(ScimTokens::Table)
                .order_by(ScimTokens::CreatedAt, Order::Desc)
                .to_owned();
            query.build_sql(db_type)
        };
        db_fetch_all!(pool, sqlx::query_as::<_, ScimToken>(&sql))?
    };

    Ok(tokens)
}

/// Insert SCIM audit log entry.
pub async fn insert_scim_audit(
    pool: &Pool,
    operation: &str,
    resource_type: &str,
    resource_id: &str,
    actor_token_id: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(ScimAuditLog::Table)
            .columns([
                ScimAuditLog::Id,
                ScimAuditLog::Operation,
                ScimAuditLog::ResourceType,
                ScimAuditLog::ResourceId,
                ScimAuditLog::ActorTokenId,
                ScimAuditLog::Details,
                ScimAuditLog::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                operation.into(),
                resource_type.into(),
                resource_id.into(),
                actor_token_id.into(),
                details.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Delete SCIM audit log entries older than the specified timestamp.
pub async fn delete_old_scim_audit_logs(pool: &Pool, before: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(ScimAuditLog::Table)
            .and_where(Expr::col(ScimAuditLog::CreatedAt).lt(before))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// SCIM Users
// ============================================================================

/// SCIM user record (includes active and external_id fields).
#[derive(Debug, sqlx::FromRow)]
pub struct ScimUserRecord {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub created_at: DbTimestamp,
    pub active: bool,
    pub external_id: Option<String>,
}

/// List users for SCIM with optional filter.
pub async fn list_scim_users(
    pool: &Pool,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<Vec<ScimUserRecord>> {
    let db_type = pool.db_type();
    let offset = start_index.saturating_sub(1); // SCIM is 1-indexed

    let sql = {
        let mut query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::CreatedAt,
                Users::Active,
                Users::ExternalId,
            ])
            .from(Users::Table)
            .to_owned();

        // Parse simple SCIM filter (userName eq "value" or email eq "value")
        if let Some(f) = filter {
            if let Some(value) = parse_scim_filter(f, "userName") {
                query = query
                    .and_where(Expr::col(Users::Email).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(f, "email") {
                query = query
                    .and_where(Expr::col(Users::Email).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(f, "externalId") {
                query = query
                    .and_where(Expr::col(Users::ExternalId).eq(value))
                    .to_owned();
            }
        }

        query = query
            .order_by(Users::Email, Order::Asc)
            .limit(count as u64)
            .offset(offset as u64)
            .to_owned();

        query.build_sql(db_type)
    };

    let users = db_fetch_all!(pool, sqlx::query_as::<_, ScimUserRecord>(&sql))?;

    Ok(users)
}

/// Count users for SCIM pagination.
pub async fn count_scim_users(pool: &Pool, filter: Option<&str>) -> Result<usize> {
    let db_type = pool.db_type();

    let sql = {
        let mut query = Query::select()
            .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("count"))
            .from(Users::Table)
            .to_owned();

        if let Some(f) = filter {
            if let Some(value) = parse_scim_filter(f, "userName") {
                query = query
                    .and_where(Expr::col(Users::Email).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(f, "email") {
                query = query
                    .and_where(Expr::col(Users::Email).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(f, "externalId") {
                query = query
                    .and_where(Expr::col(Users::ExternalId).eq(value))
                    .to_owned();
            }
        }

        query.build_sql(db_type)
    };

    let count: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(count.0 as usize)
}

/// Parse simple SCIM filter (e.g., `userName eq "john@example.com"`).
pub(crate) fn parse_scim_filter(filter: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr} eq ");
    let filter_lower = filter.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    if let Some(pos) = filter_lower.find(&pattern_lower) {
        // Get the rest of the string after the pattern
        let rest = filter.get(pos + pattern.len()..)?;
        // Extract quoted value
        if let Some(unquoted) = rest.strip_prefix('"')
            && let Some(end) = unquoted.find('"')
        {
            return unquoted.get(..end).map(|s| s.to_string());
        }
    }
    None
}

/// Get a user by ID for SCIM.
pub async fn get_scim_user(pool: &Pool, user_id: &str) -> Result<Option<ScimUserRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::CreatedAt,
                Users::Active,
                Users::ExternalId,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_optional!(pool, sqlx::query_as::<_, ScimUserRecord>(&sql))?;

    Ok(user)
}

/// Create a user via SCIM.
pub async fn create_scim_user(
    pool: &Pool,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<ScimUserRecord> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let insert_sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::ExternalId,
                Users::Active,
                Users::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                email.into(),
                name.into(),
                external_id.into(),
                active.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&insert_sql))?;

    // Fetch and return the created user
    let select_sql = {
        let query = Query::select()
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::CreatedAt,
                Users::Active,
                Users::ExternalId,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).eq(&id))
            .to_owned();
        query.build_sql(db_type)
    };

    let user = db_fetch_one!(pool, sqlx::query_as::<_, ScimUserRecord>(&select_sql))?;

    Ok(user)
}

/// Update a user via SCIM.
pub async fn update_scim_user(
    pool: &Pool,
    user_id: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<()> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::update()
            .table(Users::Table)
            .value(Users::Name, name)
            .value(Users::ExternalId, external_id)
            .value(Users::Active, active)
            .and_where(Expr::col(Users::Id).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

// ============================================================================
// SCIM Groups
// ============================================================================

/// SCIM Group record.
#[derive(Debug, sqlx::FromRow)]
pub struct ScimGroupRecord {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

/// SCIM Group member record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimGroupMemberRecord {
    pub group_id: String,
    pub user_id: String,
    pub created_at: DbTimestamp,
}

/// Create a new SCIM group.
pub async fn create_scim_group(
    pool: &Pool,
    display_name: &str,
    external_id: Option<&str>,
) -> Result<ScimGroupRecord> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(ScimGroups::Table)
            .columns([
                ScimGroups::Id,
                ScimGroups::DisplayName,
                ScimGroups::ExternalId,
                ScimGroups::CreatedAt,
                ScimGroups::UpdatedAt,
            ])
            .values_panic([
                id.clone().into(),
                display_name.into(),
                external_id.into(),
                now.as_str().into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Return the created group
    get_scim_group(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created group"))
}

/// Get a SCIM group by ID.
pub async fn get_scim_group(pool: &Pool, id: &str) -> Result<Option<ScimGroupRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                ScimGroups::Id,
                ScimGroups::DisplayName,
                ScimGroups::ExternalId,
                ScimGroups::CreatedAt,
                ScimGroups::UpdatedAt,
            ])
            .from(ScimGroups::Table)
            .and_where(Expr::col(ScimGroups::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let group = db_fetch_optional!(pool, sqlx::query_as::<_, ScimGroupRecord>(&sql))?;

    Ok(group)
}

/// Get a SCIM group by display name.
#[allow(dead_code)]
pub async fn get_scim_group_by_name(
    pool: &Pool,
    display_name: &str,
) -> Result<Option<ScimGroupRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                ScimGroups::Id,
                ScimGroups::DisplayName,
                ScimGroups::ExternalId,
                ScimGroups::CreatedAt,
                ScimGroups::UpdatedAt,
            ])
            .from(ScimGroups::Table)
            .and_where(Expr::col(ScimGroups::DisplayName).eq(display_name))
            .to_owned();
        query.build_sql(db_type)
    };

    let group = db_fetch_optional!(pool, sqlx::query_as::<_, ScimGroupRecord>(&sql))?;

    Ok(group)
}

/// List SCIM groups with pagination.
pub async fn list_scim_groups(
    pool: &Pool,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<Vec<ScimGroupRecord>> {
    let db_type = pool.db_type();
    let offset = if start_index > 0 { start_index - 1 } else { 0 };

    let sql = {
        let mut query = Query::select()
            .columns([
                ScimGroups::Id,
                ScimGroups::DisplayName,
                ScimGroups::ExternalId,
                ScimGroups::CreatedAt,
                ScimGroups::UpdatedAt,
            ])
            .from(ScimGroups::Table)
            .to_owned();

        if let Some(filter_str) = filter {
            if let Some(value) = parse_scim_filter(filter_str, "displayName") {
                query = query
                    .and_where(Expr::col(ScimGroups::DisplayName).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
                query = query
                    .and_where(Expr::col(ScimGroups::ExternalId).eq(value))
                    .to_owned();
            }
        }

        query = query
            .order_by(ScimGroups::CreatedAt, Order::Desc)
            .limit(count as u64)
            .offset(offset as u64)
            .to_owned();

        query.build_sql(db_type)
    };

    let groups = db_fetch_all!(pool, sqlx::query_as::<_, ScimGroupRecord>(&sql))?;

    Ok(groups)
}

/// Count SCIM groups (for pagination).
pub async fn count_scim_groups(pool: &Pool, filter: Option<&str>) -> Result<usize> {
    let db_type = pool.db_type();

    let sql = {
        let mut query = Query::select()
            .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("count"))
            .from(ScimGroups::Table)
            .to_owned();

        if let Some(filter_str) = filter {
            if let Some(value) = parse_scim_filter(filter_str, "displayName") {
                query = query
                    .and_where(Expr::col(ScimGroups::DisplayName).eq(value))
                    .to_owned();
            } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
                query = query
                    .and_where(Expr::col(ScimGroups::ExternalId).eq(value))
                    .to_owned();
            }
        }

        query.build_sql(db_type)
    };

    let count: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(count.0 as usize)
}

/// Update a SCIM group.
/// Only updates fields that are provided (Some), leaving others unchanged.
pub async fn update_scim_group(
    pool: &Pool,
    id: &str,
    display_name: Option<&str>,
    external_id: Option<&str>,
) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Build update query conditionally - only include fields that are Some
    let sql = {
        let mut query = Query::update()
            .table(ScimGroups::Table)
            .value(ScimGroups::UpdatedAt, now.as_str())
            .and_where(Expr::col(ScimGroups::Id).eq(id))
            .to_owned();

        if let Some(name) = display_name {
            query = query.value(ScimGroups::DisplayName, name).to_owned();
        }
        if let Some(ext_id) = external_id {
            query = query.value(ScimGroups::ExternalId, ext_id).to_owned();
        }

        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Delete a SCIM group.
///
/// Performs application-level cascade deletes for DSQL compatibility:
/// 1. Delete group memberships
/// 2. Delete the group
pub async fn delete_scim_group(pool: &Pool, id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // 1. Delete group memberships
    let sql1 = {
        let query = Query::delete()
            .from_table(ScimGroupMembers::Table)
            .and_where(Expr::col(ScimGroupMembers::GroupId).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql1))?;

    // 2. Delete the group
    let sql2 = {
        let query = Query::delete()
            .from_table(ScimGroups::Table)
            .and_where(Expr::col(ScimGroups::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };
    let result = tx_execute!(tx, sqlx::query(&sql2))?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// Add a member to a SCIM group.
/// This operation is atomic - both the insert and timestamp update happen together.
pub async fn add_scim_group_member(pool: &Pool, group_id: &str, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();
    let now = Timestamp::now().to_string();

    // Insert member using sea-query
    // Build SQL in a block to ensure query is dropped before await
    let insert_sql = {
        let insert_query = Query::insert()
            .into_table(ScimGroupMembers::Table)
            .columns([ScimGroupMembers::GroupId, ScimGroupMembers::UserId])
            .values_panic([group_id.into(), user_id.into()])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        insert_query.build_sql(db_type)
    };

    tx_execute!(tx, sqlx::query(&insert_sql))?;

    // Update group's updated_at using sea-query
    let update_sql = {
        let query = Query::update()
            .table(ScimGroups::Table)
            .value(ScimGroups::UpdatedAt, now.as_str())
            .and_where(Expr::col(ScimGroups::Id).eq(group_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&update_sql))?;

    tx.commit().await?;
    Ok(())
}

/// Remove a member from a SCIM group.
/// This operation is atomic - both the delete and timestamp update happen together.
pub async fn remove_scim_group_member(pool: &Pool, group_id: &str, user_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();
    let now = Timestamp::now().to_string();

    let delete_sql = {
        let query = Query::delete()
            .from_table(ScimGroupMembers::Table)
            .and_where(Expr::col(ScimGroupMembers::GroupId).eq(group_id))
            .and_where(Expr::col(ScimGroupMembers::UserId).eq(user_id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = tx_execute!(tx, sqlx::query(&delete_sql))?;

    if result.rows_affected() > 0 {
        // Update group's updated_at
        let update_sql = {
            let query = Query::update()
                .table(ScimGroups::Table)
                .value(ScimGroups::UpdatedAt, now.as_str())
                .and_where(Expr::col(ScimGroups::Id).eq(group_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&update_sql))?;
        tx.commit().await?;
        Ok(true)
    } else {
        tx.commit().await?;
        Ok(false)
    }
}

/// Get all members of a SCIM group.
pub async fn get_scim_group_members(pool: &Pool, group_id: &str) -> Result<Vec<ScimUserRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .column((Users::Table, Users::Id))
            .column((Users::Table, Users::Email))
            .column((Users::Table, Users::Name))
            .column((Users::Table, Users::ExternalId))
            .column((Users::Table, Users::Active))
            .column((Users::Table, Users::CreatedAt))
            .from(Users::Table)
            .join(
                JoinType::InnerJoin,
                ScimGroupMembers::Table,
                Expr::col((ScimGroupMembers::Table, ScimGroupMembers::UserId))
                    .equals((Users::Table, Users::Id)),
            )
            .and_where(Expr::col((ScimGroupMembers::Table, ScimGroupMembers::GroupId)).eq(group_id))
            .order_by((Users::Table, Users::Email), Order::Asc)
            .to_owned();
        query.build_sql(db_type)
    };

    let users = db_fetch_all!(pool, sqlx::query_as::<_, ScimUserRecord>(&sql))?;

    Ok(users)
}

/// Get all groups a user belongs to.
#[allow(dead_code)]
pub async fn get_user_scim_groups(pool: &Pool, user_id: &str) -> Result<Vec<ScimGroupRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .column((ScimGroups::Table, ScimGroups::Id))
            .column((ScimGroups::Table, ScimGroups::DisplayName))
            .column((ScimGroups::Table, ScimGroups::ExternalId))
            .column((ScimGroups::Table, ScimGroups::CreatedAt))
            .column((ScimGroups::Table, ScimGroups::UpdatedAt))
            .from(ScimGroups::Table)
            .join(
                JoinType::InnerJoin,
                ScimGroupMembers::Table,
                Expr::col((ScimGroupMembers::Table, ScimGroupMembers::GroupId))
                    .equals((ScimGroups::Table, ScimGroups::Id)),
            )
            .and_where(Expr::col((ScimGroupMembers::Table, ScimGroupMembers::UserId)).eq(user_id))
            .order_by((ScimGroups::Table, ScimGroups::DisplayName), Order::Asc)
            .to_owned();
        query.build_sql(db_type)
    };

    let groups = db_fetch_all!(pool, sqlx::query_as::<_, ScimGroupRecord>(&sql))?;

    Ok(groups)
}

/// Maximum number of rows that can be modified in a single DSQL transaction.
/// DSQL limits transactions to 3,000 rows; we use 2,000 to leave margin for
/// the delete operation and updated_at update.
const DSQL_BATCH_SIZE: usize = 2000;

/// Replace all members of a SCIM group.
///
/// For small groups (≤ `DSQL_BATCH_SIZE` members), this operation is atomic.
/// For larger groups, members are added in batches. The delete and first batch
/// are atomic, but subsequent batches are separate transactions.
///
/// # Note on atomicity for large groups
///
/// If a failure occurs mid-way through processing a large group, the group
/// will be left in a partially-updated state. The SCIM client should retry
/// the PUT request to complete the update.
pub async fn replace_scim_group_members(
    pool: &Pool,
    group_id: &str,
    user_ids: &[String],
) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // For small groups, do everything in one transaction (atomic)
    if user_ids.len() <= DSQL_BATCH_SIZE {
        let mut tx = pool.begin().await?;

        // Delete all existing members
        let delete_sql = {
            let query = Query::delete()
                .from_table(ScimGroupMembers::Table)
                .and_where(Expr::col(ScimGroupMembers::GroupId).eq(group_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&delete_sql))?;

        // Add new members
        for user_id in user_ids {
            let insert_sql = {
                let insert_query = Query::insert()
                    .into_table(ScimGroupMembers::Table)
                    .columns([ScimGroupMembers::GroupId, ScimGroupMembers::UserId])
                    .values_panic([group_id.into(), user_id.clone().into()])
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .to_owned();
                insert_query.build_sql(db_type)
            };
            tx_execute!(tx, sqlx::query(&insert_sql))?;
        }

        // Update group's updated_at
        let update_sql = {
            let query = Query::update()
                .table(ScimGroups::Table)
                .value(ScimGroups::UpdatedAt, now.as_str())
                .and_where(Expr::col(ScimGroups::Id).eq(group_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&update_sql))?;

        tx.commit().await?;
        return Ok(());
    }

    // For large groups, process in batches
    // First batch: delete existing + add first batch (atomic)
    {
        let mut tx = pool.begin().await?;

        let delete_sql = {
            let query = Query::delete()
                .from_table(ScimGroupMembers::Table)
                .and_where(Expr::col(ScimGroupMembers::GroupId).eq(group_id))
                .to_owned();
            query.build_sql(db_type)
        };
        tx_execute!(tx, sqlx::query(&delete_sql))?;

        for user_id in user_ids.iter().take(DSQL_BATCH_SIZE) {
            let insert_sql = {
                let insert_query = Query::insert()
                    .into_table(ScimGroupMembers::Table)
                    .columns([ScimGroupMembers::GroupId, ScimGroupMembers::UserId])
                    .values_panic([group_id.into(), user_id.clone().into()])
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .to_owned();
                insert_query.build_sql(db_type)
            };
            tx_execute!(tx, sqlx::query(&insert_sql))?;
        }

        tx.commit().await?;
    }

    // Subsequent batches: each in its own transaction
    for chunk in user_ids
        .get(DSQL_BATCH_SIZE..)
        .unwrap_or(&[])
        .chunks(DSQL_BATCH_SIZE)
    {
        let mut tx = pool.begin().await?;

        for user_id in chunk {
            let insert_sql = {
                let insert_query = Query::insert()
                    .into_table(ScimGroupMembers::Table)
                    .columns([ScimGroupMembers::GroupId, ScimGroupMembers::UserId])
                    .values_panic([group_id.into(), user_id.clone().into()])
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .to_owned();
                insert_query.build_sql(db_type)
            };
            tx_execute!(tx, sqlx::query(&insert_sql))?;
        }

        tx.commit().await?;
    }

    // Update group's updated_at after all batches complete
    let update_sql = {
        let query = Query::update()
            .table(ScimGroups::Table)
            .value(ScimGroups::UpdatedAt, now.as_str())
            .and_where(Expr::col(ScimGroups::Id).eq(group_id))
            .to_owned();
        query.build_sql(db_type)
    };
    db_execute!(pool, sqlx::query(&update_sql))?;

    Ok(())
}
