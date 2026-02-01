# Aurora DSQL Migration Plan: CASCADE and CHECK Constraints

This document outlines the plan to move all `ON DELETE CASCADE` and `CHECK` constraints from the database layer into application code for AWS Aurora DSQL compatibility.

## Background

Aurora DSQL does not support:
- `ON DELETE CASCADE` / `ON DELETE SET NULL` foreign key actions
- `CHECK` constraints

All this logic must be implemented in application code within transactions.

---

## 1. Dependency Graph for Deletion Order

When deleting parent records, child records must be deleted first:

```
users
├── authenticators
│   └── sessions (via authenticator_id)
├── sessions (via user_id)
├── oauth_clients
│   ├── oauth_client_secrets
│   └── oauth_usage_events
├── enrollment_sessions
├── auth_events
├── scim_group_members
├── token_exchanges (subject_user_id, actor_user_id)
├── github_credential_events
└── ssh_revoked_certificates

organizations
├── cloud_integrations
├── github_installations
├── scim_tokens → scim_audit_log (SET NULL)
└── users.org_id (SET NULL)

scim_groups
└── scim_group_members

oauth_clients
├── oauth_client_secrets
└── oauth_usage_events

device_auth_requests
└── oidc_states

scim_tokens
└── scim_audit_log.actor_token_id (SET NULL)
```

---

## 2. Affected Tables and Current Constraints

### Foreign Keys with CASCADE

| Migration | Table | Constraint |
|-----------|-------|------------|
| 001 | `authenticators` | `REFERENCES users(id) ON DELETE CASCADE` |
| 001 | `sessions` | `REFERENCES users(id) ON DELETE CASCADE` |
| 001 | `sessions` | `REFERENCES authenticators(id) ON DELETE CASCADE` |
| 002 | `oidc_states` | `REFERENCES device_auth_requests(id) ON DELETE CASCADE` |
| 007 | `scim_audit_log` | `REFERENCES scim_tokens(id) ON DELETE SET NULL` |
| 008 | `oauth_clients` | `REFERENCES users(id) ON DELETE CASCADE` |
| 008 | `oauth_client_secrets` | `REFERENCES oauth_clients(id) ON DELETE CASCADE` |
| 008 | `oauth_usage_events` | `REFERENCES oauth_clients(id) ON DELETE CASCADE` |
| 013 | `scim_group_members` | `REFERENCES scim_groups(id) ON DELETE CASCADE` |
| 013 | `scim_group_members` | `REFERENCES users(id) ON DELETE CASCADE` |

### CHECK Constraints

| Migration | Table | Constraint |
|-----------|-------|------------|
| 008 | `oauth_clients` | `CHECK (application_type IN ('web', 'native', 'spa', 'service'))` |
| 008 | `oauth_usage_events` | `CHECK (event_type IN (...))` |

---

## 3. Implementation Plan

### Phase 1: Create Validation Module

Create `crates/vouch-server/src/db/validation.rs`:

```rust
/// Valid OAuth client application types
pub const VALID_APPLICATION_TYPES: &[&str] = &["web", "native", "spa", "service"];

/// Valid OAuth usage event types
pub const VALID_OAUTH_EVENT_TYPES: &[&str] = &[
    "token_issued",
    "token_refreshed",
    "token_revoked",
    "auth_success",
    "auth_failure"
];

pub fn validate_application_type(app_type: &str) -> Result<(), ValidationError> {
    if VALID_APPLICATION_TYPES.contains(&app_type) {
        Ok(())
    } else {
        Err(ValidationError::InvalidApplicationType(app_type.to_string()))
    }
}
```

### Phase 2: Update Delete Functions

#### `delete_user()` in `users.rs`

```rust
pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    // 1. Delete sessions
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 2. Delete enrollment sessions
    sqlx::query("DELETE FROM enrollment_sessions WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 3. Delete auth events
    sqlx::query("DELETE FROM auth_events WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 4. Delete SCIM group memberships
    sqlx::query("DELETE FROM scim_group_members WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 5. Handle token exchanges
    sqlx::query("UPDATE token_exchanges SET actor_user_id = NULL WHERE actor_user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM token_exchanges WHERE subject_user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 6. Delete SSH revoked certificates
    sqlx::query("DELETE FROM ssh_revoked_certificates WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 7. Delete OAuth clients and their children
    let client_ids: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM oauth_clients WHERE user_id = ?"
    ).bind(user_id).fetch_all(&mut *tx).await?;

    for (client_id,) in client_ids {
        sqlx::query("DELETE FROM oauth_usage_events WHERE oauth_client_id = ?")
            .bind(&client_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM oauth_client_secrets WHERE oauth_client_id = ?")
            .bind(&client_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
            .bind(&client_id).execute(&mut *tx).await?;
    }

    // 8. Delete authenticators and handle their references
    sqlx::query("UPDATE device_auth_requests SET authenticator_id = NULL
                 WHERE authenticator_id IN (SELECT id FROM authenticators WHERE user_id = ?)")
        .bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM authenticators WHERE user_id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    // 9. Delete the user
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(())
}
```

#### `delete_authenticator()` in `authenticators.rs`

```rust
pub async fn delete_authenticator(pool: &SqlitePool, authenticator_id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    // 1. Clear device_auth_requests references
    sqlx::query("UPDATE device_auth_requests SET authenticator_id = NULL WHERE authenticator_id = ?")
        .bind(authenticator_id).execute(&mut *tx).await?;

    // 2. Delete sessions using this authenticator
    sqlx::query("DELETE FROM sessions WHERE authenticator_id = ?")
        .bind(authenticator_id).execute(&mut *tx).await?;

    // 3. Delete the authenticator
    let result = sqlx::query("DELETE FROM authenticators WHERE id = ?")
        .bind(authenticator_id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}
```

#### `delete_oauth_client()` in `oauth.rs`

```rust
pub async fn delete_oauth_client(pool: &SqlitePool, id: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM oauth_usage_events WHERE oauth_client_id = ?")
        .bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM oauth_client_secrets WHERE oauth_client_id = ?")
        .bind(id).execute(&mut *tx).await?;
    let result = sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
        .bind(id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}
```

#### `delete_scim_group()` in `scim.rs`

```rust
pub async fn delete_scim_group(pool: &SqlitePool, id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM scim_group_members WHERE group_id = ?")
        .bind(id).execute(&mut *tx).await?;
    let result = sqlx::query("DELETE FROM scim_groups WHERE id = ?")
        .bind(id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}
```

#### `delete_scim_token()` in `scim.rs`

```rust
pub async fn delete_scim_token(pool: &SqlitePool, token_id: &str) -> Result<()> {
    let mut tx = pool.begin().await?;

    // SET NULL behavior for audit log
    sqlx::query("UPDATE scim_audit_log SET actor_token_id = NULL WHERE actor_token_id = ?")
        .bind(token_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM scim_tokens WHERE id = ?")
        .bind(token_id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(())
}
```

#### `delete_expired_device_auth_requests()` in `device_auth.rs`

```rust
pub async fn delete_expired_device_auth_requests(pool: &SqlitePool, now: &str) -> Result<u64> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM oidc_states WHERE device_auth_id IN
                 (SELECT id FROM device_auth_requests WHERE expires_at < ?)")
        .bind(now).execute(&mut *tx).await?;
    let result = sqlx::query("DELETE FROM device_auth_requests WHERE expires_at < ?")
        .bind(now).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}
```

#### `delete_organization()` in `organizations.rs` (new function)

```rust
pub async fn delete_organization(pool: &SqlitePool, org_id: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;

    // Delete cloud integrations
    sqlx::query("DELETE FROM cloud_integrations WHERE org_id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    // Delete GitHub installations
    sqlx::query("DELETE FROM github_installations WHERE org_id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    // Handle SCIM tokens (SET NULL for audit log first)
    let token_ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM scim_tokens WHERE org_id = ?")
        .bind(org_id).fetch_all(&mut *tx).await?;
    for (token_id,) in token_ids {
        sqlx::query("UPDATE scim_audit_log SET actor_token_id = NULL WHERE actor_token_id = ?")
            .bind(&token_id).execute(&mut *tx).await?;
    }
    sqlx::query("DELETE FROM scim_tokens WHERE org_id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    // SET NULL for audit references
    sqlx::query("UPDATE github_credential_events SET org_id = NULL WHERE org_id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    // SET NULL for users
    sqlx::query("UPDATE users SET org_id = NULL, is_org_admin = 0 WHERE org_id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    // Delete organization
    let result = sqlx::query("DELETE FROM organizations WHERE id = ?")
        .bind(org_id).execute(&mut *tx).await?;

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}
```

### Phase 3: Add Validation to Insert/Update Functions

Update `create_oauth_client()` and `record_oauth_event()` to validate before insert (already done via enums, but add explicit checks for defense in depth).

### Phase 4: Migration to Drop Constraints

Create `migrations/024_dsql_compatibility.sql` that recreates all affected tables without CASCADE/CHECK constraints. SQLite requires table recreation to modify constraints.

---

## 4. Testing Strategy

### Unit Tests for Validation

```rust
#[test]
fn test_valid_application_types() {
    assert!(validate_application_type("web").is_ok());
    assert!(validate_application_type("invalid").is_err());
}
```

### Integration Tests for Cascade Deletes

```rust
#[tokio::test]
async fn test_delete_user_cascades_to_children() {
    let pool = test_pool().await;

    // Create user with children
    let user = db::upsert_user(&pool, "test@example.com", None).await.unwrap();
    let auth_id = db::create_authenticator(&pool, &user.id, ...).await.unwrap();
    db::create_session(&pool, &user.id, "hash", Some(&auth_id), ...).await.unwrap();

    // Delete user
    db::delete_user(&pool, &user.id).await.unwrap();

    // Verify all children are deleted
    assert!(db::get_user_by_id(&pool, &user.id).await.unwrap().is_none());
    assert!(db::get_authenticator_by_id(&pool, &auth_id).await.unwrap().is_none());
}
```

### Orphan Prevention Tests

```rust
#[tokio::test]
async fn test_no_orphans_after_delete() {
    // Verify no orphan records exist after cascade delete
    let orphan_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE user_id NOT IN (SELECT id FROM users)"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(orphan_count, 0);
}
```

---

## 5. Implementation Sequence

| Step | Task | Risk | Dependencies |
|------|------|------|--------------|
| 1 | Create validation module | Low | None |
| 2 | Update `delete_user()` | Medium | Step 1 |
| 3 | Update `delete_authenticator()` | Medium | None |
| 4 | Update `delete_oauth_client()` | Medium | None |
| 5 | Update `delete_scim_group()` | Medium | None |
| 6 | Update `delete_scim_token()` | Medium | None |
| 7 | Update `delete_expired_device_auth_requests()` | Medium | None |
| 8 | Add `delete_organization()` | Medium | None |
| 9 | Add validation to inserts | Low | Step 1 |
| 10 | Write tests | Low | Steps 2-9 |
| 11 | Run migration (requires backup) | High | Steps 2-10 |

---

## 6. Rollback Plan

If issues are discovered after migration:

1. Restore database from backup
2. Revert code changes
3. Re-run original migrations

---

## 7. DSQL-Specific Considerations

### Transaction Row Limits

DSQL limits transactions to 10,000 row modifications. The `delete_user()` function could exceed this if a user has:
- Thousands of sessions
- Thousands of auth events
- Many OAuth clients with thousands of events each

**Mitigation**: For users with large amounts of data, batch deletions:

```rust
// Delete in batches of 5000
loop {
    let deleted = sqlx::query("DELETE FROM sessions WHERE user_id = ? LIMIT 5000")
        .bind(user_id).execute(&mut *tx).await?.rows_affected();
    if deleted == 0 { break; }
}
```

### Optimistic Concurrency Control

DSQL uses OCC. Concurrent deletes of the same user could cause transaction conflicts. The code should handle `SerializationFailure` errors with retry logic.

---

## 8. Files to Modify

| File | Changes |
|------|---------|
| `crates/vouch-server/src/db/mod.rs` | Add `validation` module |
| `crates/vouch-server/src/db/validation.rs` | New file |
| `crates/vouch-server/src/db/users.rs` | Update `delete_user()` |
| `crates/vouch-server/src/db/authenticators.rs` | Update `delete_authenticator()` |
| `crates/vouch-server/src/db/oauth.rs` | Update `delete_oauth_client()`, add validation |
| `crates/vouch-server/src/db/scim.rs` | Update `delete_scim_group()`, `delete_scim_token()` |
| `crates/vouch-server/src/db/device_auth.rs` | Update `delete_expired_device_auth_requests()` |
| `crates/vouch-server/src/db/organizations.rs` | Add `delete_organization()` |
| `crates/vouch-server/migrations/024_dsql_compatibility.sql` | New migration |
