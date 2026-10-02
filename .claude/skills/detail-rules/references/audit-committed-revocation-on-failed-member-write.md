# Audit Committed Revocation on Failed Member Write

Every member action that revokes access before its final write must record an audit event with a non-`None` refusal when that write fails, so the committed revocation is attributable and the OCSF export reports Failure.

## What to look for

A violation exists when **all three** of the following are true:

1. **Access revocation commits first** — the handler calls `auth::revoke_user_access` or `auth::revoke_then_persist` (which internally calls `revoke_user_access`) before the authoritative write (deactivate, delete, remove, revoke-credentials).

2. **The final write fails** — an error arm is reached where revocation already ran and committed (sessions deleted, SSH certificates revoked, GitHub refresh token cleared), but the authoritative write did not succeed.

3. **No audit event is recorded** — the error arm returns (with an HTTP error or `Err(...)`) without calling `state.audit.record_event(...)` or `db::record_scim_audit(...)`, **or** it calls one of those functions with `refusal: None`.

### Patterns that signal revocation has committed before the error arm

- `Err(DeactivationError::Persist(...))` — inside a `match auth::revoke_then_persist(...)` block. Revocation committed when this arm is reached; `DeactivationError::Revoke` did not run the persist, so that arm is safe to omit an audit event.
- Any error arm after a direct `auth::revoke_user_access(...).await?` or `.await.is_err()` check — the call succeeded (no `?` short-circuit, no `is_err()` early return), so revocation committed before this arm.

### Specific patterns to flag

- A `match auth::revoke_then_persist(...)` arm matching `Err(DeactivationError::Persist(...))` (or a subset of its variants) that `return`s without a preceding `state.audit.record_event(...)` call.
- A bare `tracing::error!(...); return Err(ServiceError::Internal(...))` (or equivalent) in an error arm that follows committed revocation.
- A `match db::delete_user(...)` or `match db::demote_or_deactivate_member(...)` error arm that occurs after `revoke_user_access` succeeded, without a preceding audit call.
- An audit call in only **some** error variants but not others — e.g., recording for `LastAdmin` but not for the generic `Err(e)` catch-all, even though revocation committed in both cases.
- `refusal: None` on an audit event recorded in an error arm — a refusal-less row is byte-identical to a success row and exports to OCSF as Success, defeating attributability.

### Actions in scope (all revoke-before-write)

- `deactivate_member` — `revoke_then_persist` → `db::demote_or_deactivate_member`
- `remove_member` — `revoke_user_access` → `db::delete_user`
- `revoke_member_credentials` — `revoke_then_persist` → authenticator-deletion transaction
- SCIM `PATCH /Users/{id}` deactivation — `revoke_then_persist` → `db::update_scim_user`
- SCIM `DELETE /Users/{id}` — `revoke_user_access` → `db::delete_user`

## Violation examples

### Admin deactivate — only `LastAdmin` arm audited; generic error skips audit

```rust
// VIOLATION: Err(OccConflict) and Err(Other) return with no audit event
// even though revocation already committed.
Err(DeactivationError::Persist(err)) => {
    if matches!(err, db::MemberDowngradeError::LastAdmin) {
        state.audit.record_event(
            db::AuditEventKind::AdminDeactivate,
            Some(&admin.id),
            Some(&target.email),
            &AdminMemberActionData {
                action: "deactivate",
                target_user_id: &target_id,
                admin_user_id: &admin.id,
                keys_revoked: None,
                refusal: Some("last_admin"),
            },
        ).await;
    }
    // OccConflict and Other fall through here with NO audit event
    return Err(last_admin_error(err));
}
```

### Admin remove — generic error arm has no audit event

```rust
// auth::revoke_user_access commits here — revocation is irreversible
auth::revoke_user_access(&state, &target_id, "User removed by admin", &admin.id).await?;

let deleted = match db::delete_user(...).await {
    Ok(deleted) => deleted,
    Err(db::DeleteUserError::LastAdmin) => {
        state.audit.record_event(..., &AdminMemberActionData {
            ..., refusal: Some("last_admin"),
        }).await;
        return Err(last_admin_refusal());
    }
    Err(e) => {
        // VIOLATION: revocation committed above but no audit event here
        tracing::error!("Failed to delete user: {e}");
        return Err(ServiceError::Internal("Failed to delete user".to_string()));
    }
};
```

### Audit call with `refusal: None` in error arm

```rust
// VIOLATION: refusal: None makes this indistinguishable from success
// and exports to OCSF as Success instead of Failure.
Err(DeactivationError::Persist(e)) => {
    state.audit.record_event(
        db::AuditEventKind::AdminDeactivate,
        Some(&admin.id),
        Some(&target.email),
        &AdminMemberActionData {
            action: "deactivate",
            target_user_id: &target_id,
            admin_user_id: &admin.id,
            keys_revoked: None,
            refusal: None,  // BUG: should be Some(Refusal::LastAdmin) or Some(Refusal::PersistError)
        },
    ).await;
    return Err(last_admin_error(err));
}
```

## Correct patterns

### Single audit call covering all persist error variants

```rust
// CORRECT: one record_event call covers all Persist variants,
// distinguishing LastAdmin from other failures via Refusal.
Err(DeactivationError::Persist(err)) => {
    let refusal = if matches!(err, db::MemberDowngradeError::LastAdmin) {
        Refusal::LastAdmin
    } else {
        Refusal::PersistError
    };
    state.audit.record_event(
        db::AuditEventKind::AdminDeactivate,
        Some(&admin.id),
        Some(&target.email),
        &AdminMemberActionData {
            action: "deactivate",
            target_user_id: &target_id,
            admin_user_id: &admin.id,
            keys_revoked: None,
            refusal: Some(refusal),
        },
    ).await;
    return Err(last_admin_error(err));
}
```

### Generic error arm after `revoke_user_access`

```rust
// CORRECT: every delete-error arm records an audit event before returning.
Err(e) => {
    let (refusal, error) = match e {
        db::DeleteUserError::LastAdmin => (Refusal::LastAdmin, last_admin_refusal()),
        e => {
            tracing::error!("Failed to delete user: {e}");
            (Refusal::PersistError, ServiceError::Internal("Failed to delete user".to_string()))
        }
    };
    state.audit.record_event(
        db::AuditEventKind::AdminRemoveUser,
        Some(&admin.id),
        Some(&target_email),
        &AdminMemberActionData {
            action: "remove_user",
            target_user_id: &target_id,
            admin_user_id: &admin.id,
            keys_revoked: None,
            refusal: Some(refusal),
        },
    ).await;
    return Err(error);
}
```

### SCIM error arm (uses `db::record_scim_audit` and `ScimAuditData`)

```rust
// CORRECT: both Persist error arms record a SCIM audit row with a non-None refusal.
Err(DeactivationError::Persist(db::ScimUpdateError::LastAdmin)) => {
    if deactivated {
        db::record_scim_audit(&state.audit, &db::ScimAuditData {
            operation,
            resource_type: "User",
            resource_id: id,
            actor_token_id: Some(&auth.token_id),
            details: Some(&serde_json::json!({
                "active": updated.active, "deactivated": true,
                "accessRevoked": true, "persisted": false
            }).to_string()),
            refusal: Some(db::Refusal::LastAdmin),
        }, auth.org_domain.as_deref()).await;
    }
    return last_admin_scim_error();
}
Err(DeactivationError::Persist(e)) => {
    if deactivated {
        db::record_scim_audit(&state.audit, &db::ScimAuditData {
            ...,
            refusal: Some(db::Refusal::PersistError),
        }, auth.org_domain.as_deref()).await;
    }
    // ... return 500
}
```

## Scope

- `crates/vouch-server/src/handlers/admin/members.rs` — all handler functions that call `auth::revoke_user_access` or `auth::revoke_then_persist`
- `crates/vouch-server/src/handlers/scim/users.rs` — `persist_user_update`, `delete_user`
- Any future handler in `crates/vouch-server/src/handlers/` that calls `auth::revoke_user_access` or `auth::revoke_then_persist` before a write that can fail
