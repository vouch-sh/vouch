// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 (RFC 7643/7644) database operations.

use super::Pool;
use super::compat::{BuildSql, now_expr};
use super::schema::{ScimAuditLog, ScimGroupMembers, ScimGroups, ScimTokens, Users};
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional, tx_execute};
use anyhow::Result;
use sea_query::{Expr, OnConflict, Order, Query, SimpleExpr};
use uuid::Uuid;

// ============================================================================
// SCIM Tokens
// ============================================================================

/// SCIM token record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimToken {
    pub id: String,
    pub token_hash: String,
    pub org_id: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
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

    let sql = {
        let query = Query::update()
            .table(ScimTokens::Table)
            .value(
                ScimTokens::LastUsedAt,
                SimpleExpr::Custom(now_expr(db_type).to_string()),
            )
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
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::insert()
            .into_table(ScimTokens::Table)
            .columns([
                ScimTokens::Id,
                ScimTokens::TokenHash,
                ScimTokens::OrgId,
                ScimTokens::Description,
                ScimTokens::ExpiresAt,
            ])
            .values_panic([
                id.clone().into(),
                token_hash.into(),
                org_id.into(),
                description.into(),
                expires_at.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Delete a SCIM token.
///
/// Performs application-level SET NULL for DSQL compatibility:
/// 1. Set scim_audit_log.actor_token_id to NULL for this token
/// 2. Delete the token
#[allow(dead_code)]
pub async fn delete_scim_token(pool: &Pool, token_id: &str) -> Result<()> {
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

    // 2. Delete the token
    let sql2 = {
        let query = Query::delete()
            .from_table(ScimTokens::Table)
            .and_where(Expr::col(ScimTokens::Id).eq(token_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&sql2))?;

    tx.commit().await?;
    Ok(())
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
            ])
            .values_panic([
                id.clone().into(),
                operation.into(),
                resource_type.into(),
                resource_id.into(),
                actor_token_id.into(),
                details.into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
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
    pub created_at: String,
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
    // Parse simple SCIM filter (userName eq "value" or email eq "value")
    let (sql, filter_value) = if let Some(f) = filter {
        if let Some(value) = parse_scim_filter(f, "userName") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE email = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else if let Some(value) = parse_scim_filter(f, "email") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE email = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else if let Some(value) = parse_scim_filter(f, "externalId") {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users WHERE external_id = ? ORDER BY email LIMIT ? OFFSET ?",
                Some(value),
            )
        } else {
            (
                "SELECT id, email, name, created_at, active, external_id FROM users ORDER BY email LIMIT ? OFFSET ?",
                None,
            )
        }
    } else {
        (
            "SELECT id, email, name, created_at, active, external_id FROM users ORDER BY email LIMIT ? OFFSET ?",
            None,
        )
    };

    let offset = start_index.saturating_sub(1); // SCIM is 1-indexed

    let users = if let Some(val) = filter_value {
        db_fetch_all!(
            pool,
            sqlx::query_as::<_, ScimUserRecord>(sql)
                .bind(val)
                .bind(count as i64)
                .bind(offset as i64)
        )?
    } else {
        db_fetch_all!(
            pool,
            sqlx::query_as::<_, ScimUserRecord>(sql)
                .bind(count as i64)
                .bind(offset as i64)
        )?
    };

    Ok(users)
}

/// Count users for SCIM pagination.
pub async fn count_scim_users(pool: &Pool, filter: Option<&str>) -> Result<usize> {
    let (sql, filter_value) = if let Some(f) = filter {
        if let Some(value) = parse_scim_filter(f, "userName") {
            ("SELECT COUNT(*) FROM users WHERE email = ?", Some(value))
        } else if let Some(value) = parse_scim_filter(f, "email") {
            ("SELECT COUNT(*) FROM users WHERE email = ?", Some(value))
        } else if let Some(value) = parse_scim_filter(f, "externalId") {
            (
                "SELECT COUNT(*) FROM users WHERE external_id = ?",
                Some(value),
            )
        } else {
            ("SELECT COUNT(*) FROM users", None)
        }
    } else {
        ("SELECT COUNT(*) FROM users", None)
    };

    let count: (i64,) = if let Some(val) = filter_value {
        db_fetch_one!(pool, sqlx::query_as(sql).bind(val))?
    } else {
        db_fetch_one!(pool, sqlx::query_as(sql))?
    };

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

    let insert_sql = {
        let query = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Email,
                Users::Name,
                Users::ExternalId,
                Users::Active,
            ])
            .values_panic([
                id.clone().into(),
                email.into(),
                name.into(),
                external_id.into(),
                active.into(),
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
    pub created_at: String,
    pub updated_at: String,
}

/// SCIM Group member record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ScimGroupMemberRecord {
    pub group_id: String,
    pub user_id: String,
    pub created_at: String,
}

/// Create a new SCIM group.
pub async fn create_scim_group(
    pool: &Pool,
    display_name: &str,
    external_id: Option<&str>,
) -> Result<ScimGroupRecord> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::insert()
            .into_table(ScimGroups::Table)
            .columns([
                ScimGroups::Id,
                ScimGroups::DisplayName,
                ScimGroups::ExternalId,
            ])
            .values_panic([id.clone().into(), display_name.into(), external_id.into()])
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
    let offset = if start_index > 0 { start_index - 1 } else { 0 };

    let groups = if let Some(filter_str) = filter {
        // Parse simple filter: displayName eq "value"
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            db_fetch_all!(
                pool,
                sqlx::query_as::<_, ScimGroupRecord>(
                    "SELECT id, display_name, external_id, created_at, updated_at
                     FROM scim_groups WHERE display_name = ?
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?",
                )
                .bind(value)
                .bind(count as i64)
                .bind(offset as i64)
            )?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            db_fetch_all!(
                pool,
                sqlx::query_as::<_, ScimGroupRecord>(
                    "SELECT id, display_name, external_id, created_at, updated_at
                     FROM scim_groups WHERE external_id = ?
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?",
                )
                .bind(value)
                .bind(count as i64)
                .bind(offset as i64)
            )?
        } else {
            // Unknown filter, return all
            db_fetch_all!(
                pool,
                sqlx::query_as::<_, ScimGroupRecord>(
                    "SELECT id, display_name, external_id, created_at, updated_at
                     FROM scim_groups
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?",
                )
                .bind(count as i64)
                .bind(offset as i64)
            )?
        }
    } else {
        db_fetch_all!(
            pool,
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(count as i64)
            .bind(offset as i64)
        )?
    };

    Ok(groups)
}

/// Count SCIM groups (for pagination).
pub async fn count_scim_groups(pool: &Pool, filter: Option<&str>) -> Result<usize> {
    let count = if let Some(filter_str) = filter {
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            db_fetch_one!(
                pool,
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM scim_groups WHERE display_name = ?"
                )
                .bind(value)
            )?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            db_fetch_one!(
                pool,
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM scim_groups WHERE external_id = ?"
                )
                .bind(value)
            )?
        } else {
            db_fetch_one!(
                pool,
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
            )?
        }
    } else {
        db_fetch_one!(
            pool,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
        )?
    };

    Ok(count as usize)
}

/// Update a SCIM group.
/// Uses a single atomic query with COALESCE to update only specified fields.
pub async fn update_scim_group(
    pool: &Pool,
    id: &str,
    display_name: Option<&str>,
    external_id: Option<&str>,
) -> Result<()> {
    let db_type = pool.db_type();

    // COALESCE is tricky in sea-query, so we keep using raw SQL for this
    let sql = format!(
        "UPDATE scim_groups SET
            display_name = COALESCE(?, display_name),
            external_id = COALESCE(?, external_id),
            updated_at = {}
         WHERE id = ?",
        now_expr(db_type)
    );

    db_execute!(
        pool,
        sqlx::query(&sql)
            .bind(display_name)
            .bind(external_id)
            .bind(id)
    )?;

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

    // Update group's updated_at
    let update_sql = format!(
        "UPDATE scim_groups SET updated_at = {} WHERE id = ?",
        now_expr(db_type)
    );
    tx_execute!(tx, sqlx::query(&update_sql).bind(group_id))?;

    tx.commit().await?;
    Ok(())
}

/// Remove a member from a SCIM group.
/// This operation is atomic - both the delete and timestamp update happen together.
pub async fn remove_scim_group_member(pool: &Pool, group_id: &str, user_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

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
                .value(
                    ScimGroups::UpdatedAt,
                    SimpleExpr::Custom(now_expr(db_type).to_string()),
                )
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
    let users = db_fetch_all!(
        pool,
        sqlx::query_as::<_, ScimUserRecord>(
            "SELECT u.id, u.email, u.name, u.external_id, u.active, u.created_at
             FROM users u
             JOIN scim_group_members m ON m.user_id = u.id
             WHERE m.group_id = ?
             ORDER BY u.email",
        )
        .bind(group_id)
    )?;

    Ok(users)
}

/// Get all groups a user belongs to.
#[allow(dead_code)]
pub async fn get_user_scim_groups(pool: &Pool, user_id: &str) -> Result<Vec<ScimGroupRecord>> {
    let groups = db_fetch_all!(
        pool,
        sqlx::query_as::<_, ScimGroupRecord>(
            "SELECT g.id, g.display_name, g.external_id, g.created_at, g.updated_at
             FROM scim_groups g
             JOIN scim_group_members m ON m.group_id = g.id
             WHERE m.user_id = ?
             ORDER BY g.display_name",
        )
        .bind(user_id)
    )?;

    Ok(groups)
}

/// Replace all members of a SCIM group.
/// This operation is atomic - either all members are replaced or none are.
pub async fn replace_scim_group_members(
    pool: &Pool,
    group_id: &str,
    user_ids: &[String],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let db_type = tx.db_type();

    // Delete all existing members
    let delete_sql = {
        let query = Query::delete()
            .from_table(ScimGroupMembers::Table)
            .and_where(Expr::col(ScimGroupMembers::GroupId).eq(group_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&delete_sql))?;

    // Add new members using sea-query
    for user_id in user_ids {
        // Build SQL in a block to ensure query is dropped before await
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
            .value(
                ScimGroups::UpdatedAt,
                SimpleExpr::Custom(now_expr(db_type).to_string()),
            )
            .and_where(Expr::col(ScimGroups::Id).eq(group_id))
            .to_owned();
        query.build_sql(db_type)
    };
    tx_execute!(tx, sqlx::query(&update_sql))?;

    tx.commit().await?;
    Ok(())
}
