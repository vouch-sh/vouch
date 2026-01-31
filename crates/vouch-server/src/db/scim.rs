// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 (RFC 7643/7644) database operations.

use anyhow::Result;
use sqlx::SqlitePool;
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
pub async fn get_scim_token_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<ScimToken>> {
    let token = sqlx::query_as::<_, ScimToken>(
        "SELECT id, token_hash, org_id, description, created_at, last_used_at, expires_at FROM scim_tokens WHERE token_hash = ?"
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Update SCIM token last used timestamp.
pub async fn update_scim_token_last_used(pool: &SqlitePool, token_id: &str) -> Result<()> {
    sqlx::query("UPDATE scim_tokens SET last_used_at = datetime('now') WHERE id = ?")
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create a new SCIM token.
#[allow(dead_code)]
pub async fn create_scim_token(
    pool: &SqlitePool,
    token_hash: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
    org_id: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_tokens (id, token_hash, org_id, description, expires_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(token_hash)
    .bind(org_id)
    .bind(description)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Delete a SCIM token.
#[allow(dead_code)]
pub async fn delete_scim_token(pool: &SqlitePool, token_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scim_tokens WHERE id = ?")
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// List SCIM tokens, optionally filtered by organization.
#[allow(dead_code)]
pub async fn list_scim_tokens(pool: &SqlitePool, org_id: Option<&str>) -> Result<Vec<ScimToken>> {
    let tokens = if let Some(org_id) = org_id {
        sqlx::query_as::<_, ScimToken>(
            "SELECT id, token_hash, org_id, description, created_at, last_used_at, expires_at FROM scim_tokens WHERE org_id = ? ORDER BY created_at DESC"
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, ScimToken>(
            "SELECT id, token_hash, org_id, description, created_at, last_used_at, expires_at FROM scim_tokens ORDER BY created_at DESC"
        )
        .fetch_all(pool)
        .await?
    };

    Ok(tokens)
}

/// Insert SCIM audit log entry.
pub async fn insert_scim_audit(
    pool: &SqlitePool,
    operation: &str,
    resource_type: &str,
    resource_id: &str,
    actor_token_id: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_audit_log (id, operation, resource_type, resource_id, actor_token_id, details) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(operation)
    .bind(resource_type)
    .bind(resource_id)
    .bind(actor_token_id)
    .bind(details)
    .execute(pool)
    .await?;

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
    pool: &SqlitePool,
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
        sqlx::query_as::<_, ScimUserRecord>(sql)
            .bind(val)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query_as::<_, ScimUserRecord>(sql)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    };

    Ok(users)
}

/// Count users for SCIM pagination.
pub async fn count_scim_users(pool: &SqlitePool, filter: Option<&str>) -> Result<usize> {
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
        sqlx::query_as(sql).bind(val).fetch_one(pool).await?
    } else {
        sqlx::query_as(sql).fetch_one(pool).await?
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
pub async fn get_scim_user(pool: &SqlitePool, user_id: &str) -> Result<Option<ScimUserRecord>> {
    let user = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT id, email, name, created_at, active, external_id FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Create a user via SCIM.
pub async fn create_scim_user(
    pool: &SqlitePool,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<ScimUserRecord> {
    let id = Uuid::now_v7().to_string();

    sqlx::query("INSERT INTO users (id, email, name, external_id, active) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .bind(external_id)
        .bind(active)
        .execute(pool)
        .await?;

    // Fetch and return the created user
    let user = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT id, email, name, created_at, active, external_id FROM users WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Update a user via SCIM.
pub async fn update_scim_user(
    pool: &SqlitePool,
    user_id: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<()> {
    sqlx::query("UPDATE users SET name = ?, external_id = ?, active = ? WHERE id = ?")
        .bind(name)
        .bind(external_id)
        .bind(active)
        .bind(user_id)
        .execute(pool)
        .await?;

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
    pool: &SqlitePool,
    display_name: &str,
    external_id: Option<&str>,
) -> Result<ScimGroupRecord> {
    let id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO scim_groups (id, display_name, external_id)
         VALUES (?, ?, ?)",
    )
    .bind(&id)
    .bind(display_name)
    .bind(external_id)
    .execute(pool)
    .await?;

    // Return the created group
    get_scim_group(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created group"))
}

/// Get a SCIM group by ID.
pub async fn get_scim_group(pool: &SqlitePool, id: &str) -> Result<Option<ScimGroupRecord>> {
    let group = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT id, display_name, external_id, created_at, updated_at
         FROM scim_groups WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Get a SCIM group by display name.
#[allow(dead_code)]
pub async fn get_scim_group_by_name(
    pool: &SqlitePool,
    display_name: &str,
) -> Result<Option<ScimGroupRecord>> {
    let group = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT id, display_name, external_id, created_at, updated_at
         FROM scim_groups WHERE display_name = ?",
    )
    .bind(display_name)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// List SCIM groups with pagination.
pub async fn list_scim_groups(
    pool: &SqlitePool,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<Vec<ScimGroupRecord>> {
    let offset = if start_index > 0 { start_index - 1 } else { 0 };

    let groups = if let Some(filter_str) = filter {
        // Parse simple filter: displayName eq "value"
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups WHERE display_name = ?
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(value)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups WHERE external_id = ?
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(value)
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        } else {
            // Unknown filter, return all
            sqlx::query_as::<_, ScimGroupRecord>(
                "SELECT id, display_name, external_id, created_at, updated_at
                 FROM scim_groups
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?",
            )
            .bind(count as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
        }
    } else {
        sqlx::query_as::<_, ScimGroupRecord>(
            "SELECT id, display_name, external_id, created_at, updated_at
             FROM scim_groups
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(count as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await?
    };

    Ok(groups)
}

/// Count SCIM groups (for pagination).
pub async fn count_scim_groups(pool: &SqlitePool, filter: Option<&str>) -> Result<usize> {
    let count = if let Some(filter_str) = filter {
        if let Some(value) = parse_scim_filter(filter_str, "displayName") {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE display_name = ?")
                .bind(value)
                .fetch_one(pool)
                .await?
        } else if let Some(value) = parse_scim_filter(filter_str, "externalId") {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE external_id = ?")
                .bind(value)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
                .fetch_one(pool)
                .await?
        }
    } else {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups")
            .fetch_one(pool)
            .await?
    };

    Ok(count as usize)
}

/// Update a SCIM group.
/// Uses a single atomic query with COALESCE to update only specified fields.
pub async fn update_scim_group(
    pool: &SqlitePool,
    id: &str,
    display_name: Option<&str>,
    external_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE scim_groups SET
            display_name = COALESCE(?, display_name),
            external_id = COALESCE(?, external_id),
            updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(display_name)
    .bind(external_id)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a SCIM group.
pub async fn delete_scim_group(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scim_groups WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add a member to a SCIM group.
/// This operation is atomic - both the insert and timestamp update happen together.
pub async fn add_scim_group_member(pool: &SqlitePool, group_id: &str, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
         VALUES (?, ?)",
    )
    .bind(group_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    // Update group's updated_at
    sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

/// Remove a member from a SCIM group.
/// This operation is atomic - both the delete and timestamp update happen together.
pub async fn remove_scim_group_member(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    let result = sqlx::query("DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?")
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() > 0 {
        // Update group's updated_at
        sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    } else {
        tx.commit().await?;
        Ok(false)
    }
}

/// Get all members of a SCIM group.
pub async fn get_scim_group_members(
    pool: &SqlitePool,
    group_id: &str,
) -> Result<Vec<ScimUserRecord>> {
    let users = sqlx::query_as::<_, ScimUserRecord>(
        "SELECT u.id, u.email, u.name, u.external_id, u.active, u.created_at
         FROM users u
         JOIN scim_group_members m ON m.user_id = u.id
         WHERE m.group_id = ?
         ORDER BY u.email",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// Get all groups a user belongs to.
#[allow(dead_code)]
pub async fn get_user_scim_groups(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ScimGroupRecord>> {
    let groups = sqlx::query_as::<_, ScimGroupRecord>(
        "SELECT g.id, g.display_name, g.external_id, g.created_at, g.updated_at
         FROM scim_groups g
         JOIN scim_group_members m ON m.group_id = g.id
         WHERE m.user_id = ?
         ORDER BY g.display_name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Replace all members of a SCIM group.
/// This operation is atomic - either all members are replaced or none are.
pub async fn replace_scim_group_members(
    pool: &SqlitePool,
    group_id: &str,
    user_ids: &[String],
) -> Result<()> {
    let mut tx = pool.begin().await?;

    // Delete all existing members
    sqlx::query("DELETE FROM scim_group_members WHERE group_id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    // Add new members
    for user_id in user_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
             VALUES (?, ?)",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }

    // Update group's updated_at
    sqlx::query("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}
