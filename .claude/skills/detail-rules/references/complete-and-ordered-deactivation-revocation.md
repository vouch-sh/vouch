# Complete and Ordered Deactivation and Revocation

Detects handlers or services that deactivate, delete, or revoke user access without closing every live credential path, or that commit the state change before revocation instead of revoking first.

## What to look for

### 1. Persist-before-revoke ordering (critical)

Any path that calls `db::update_user_active_status(..., false)`, `db::delete_user`, `db::delete_authenticator` (the authenticator-deletion loop in `revoke_member_credentials`), or `db::update_scim_user` with a deactivation before calling `revoke_user_access` / `revoke_then_persist` is wrong. The correct helper in this codebase is `services::auth::revoke_then_persist`, which runs revocation atomically first and only persists the state change if revocation succeeds.

**Smell**: `update_user_active_status(..., false)`, `delete_authenticator`, or `update_scim_user` appears above, or is awaited before, `revoke_user_access` / `revoke_then_persist`.

**Correct ordering**: `revoke_then_persist(&state, &user_id, reason, by, || persist_fn())`.

### 2. Missing `user.active` check on credential-issuing or token-accepting paths

Any handler or service that issues or accepts credentials without reading `user.active` after the session/authenticator lookup is a bypass. Paths that must re-check `user.active` immediately after loading the user row:

- **FIDO2 assertion grant** (`services/oidc/fido2_grant.rs`): enforced inside `lookup_and_verify_authenticator` via `if !user.active { return Err(Forbidden) }`.
- **JWT bearer grant** (`services/auth.rs` / `exchange_jwt_bearer_grant`): must load user and check `user.active`.
- **Token exchange actor path** (`services/oidc/exchange.rs`): subject user checked at line ~303, actor user checked at line ~368 — both must be present.
- **Device flow** (`handlers/device.rs`): must check user loaded for org_domain lookup.
- **Authorization code exchange** (`services/oidc/token.rs`): must check authenticator still exists.
- **OIDC introspection** (`services/oidc/introspection.rs`): must return `inactive()` when `!user.active` — skip for `M2MAccessToken` session types.
- **CLI key registration complete** (`handlers/keys.rs`): must check `account.active` before registering.
- **SSO/OIDC enrollment** (`db/enrollment.rs → resolve_user`): must return `EnrollUserError::Deactivated` before any identity-binding side effect.
- **Kubernetes/AWS/GitHub credential minting** (`services/integrations/`): must check `user.active`.

### 3. Revocation scope is too narrow (missing a credential type)

`revoke_user_access` must cover all three: sessions, SSH certificates, and the GitHub refresh token. Omitting any one leaves live credentials after deactivation.

- Sessions: `db::delete_sessions_for_user` + `session_cache.invalidate_for_user`.
- SSH certificates: `db::revoke_user_credentials` (calls `revoke_all_ssh_certificates_for_user` using the issued-cert records' real numeric serials, not synthetic `user:{id}` strings).
- GitHub refresh token: cleared inside `revoke_user_credentials`.

**Smell**: Code that calls only `delete_sessions_for_user` (or only SSH revocation) without the other two, or a `revoke_all_ssh_certificates_for_user` that inserts a synthetic serial like `"user:{user_id}"` that never matches a real SSH certificate serial.

### 4. Revocation scope is too broad (missing ownership check)

`/oauth/revoke` (RFC 7009) must refuse cross-client and cross-user revocation. The ownership check is:

```rust
if caller_client_id != claims.client_id {
    return RevocationResult { revoked: false, .. };
}
```

Any call to `delete_sessions_for_user` that proceeds without first verifying the token belongs to `caller_client_id` violates RFC 7009 §2.1.

Similarly, auth-code replay revocation must call `delete_sessions_for_code_replay(code_hash)` (revoke only sessions linked to the replayed code's `source_code_hash`) rather than `delete_sessions_for_user` (revoke all sessions), to avoid unintended logout-as-DoS.

### 5. JTI not committed at revocation/introspection endpoints

`private_key_jwt` client authentication at `/oauth/revoke` and `/oauth/introspect` must commit the JTI claim. A `PendingJti` dropped without calling `commit_jti` means the same JWT assertion can be replayed indefinitely.

### 6. Malformed SCIM `active` values silently coercing to `true`

SCIM PATCH `active` attribute must be a `bool`. Non-boolean values (e.g., the JSON string `"false"`) must return `400 invalidValue`, not be silently coerced. A coercion to `true` reactivates a deactivated user on a malformed request.

### 7. Session-cache invalidation after partial DB delete

`delete_sessions_for_code_replay` iterates per-session deletes; a mid-loop DB failure must still return the hashes of already-deleted sessions (on the `Ok` arm or equivalent) so the caller's session cache evicts them. An `Err` arm that discards already-deleted hashes leaves stale cache entries valid for up to the cache TTL.

## Violation examples

**Persist-before-revoke (admin deactivation — pre-fix)**
```rust
// WRONG: active=false commits before revocation runs
let updated = db::update_user_active_status(&state.store, &target_id, false).await?;
crate::services::auth::revoke_user_access(&state, &target_id, "...", &admin.id).await?;
```

**Persist-before-revoke (SCIM patch_user — pre-fix)**
```rust
// WRONG: update_scim_user persists active=false, revoke_user_access called after
db::update_scim_user(&state.store, &id, &auth.org_id, ..., patched.active).await?;
crate::services::auth::revoke_user_access(&state, &id, "...", "scim").await?;
```

**Persist-before-revoke (admin revoke_member_credentials — pre-fix)**
```rust
// WRONG: the authenticator-deletion transaction commits first, then
// revoke_user_access runs; a partial failure of the non-atomic
// revoke_user_access locks the member out while long-lived SSH certs /
// the GitHub refresh token stay live.
let mut tx = state.store.begin().await?;
for auth in &authenticators { db::delete_authenticator(&mut tx, &auth.id).await?; }
tx.commit().await?;
crate::services::auth::revoke_user_access(&state, &target_id, "...", &admin.id).await?;
```

**SSH revocation serial mismatch (pre-fix)**
```rust
// WRONG: synthetic serial never matches a real 64-bit SSH cert serial
store.insert(&SshRevokedCertDoc {
    serial: format!("user:{user_id}"),  // can never match issued certs
    ..
}).await?;
```

**Missing `user.active` check in device flow (pre-fix)**
```rust
// WRONG: only loads user for org_domain, never checks active
let org_domain = match db::get_user_by_id(&state.store, &user_id).await? {
    Some(u) => match u.org_id { Some(org_id) => ..., None => None },
    None => None,
};
// issues token without checking u.active
```

**Cross-client revocation — missing ownership check (pre-fix)**
```rust
// WRONG: revokes all sessions for the token's sub, regardless of caller_client_id
if let Some(ref user_id) = sub {
    db::delete_sessions_for_user(&state.store, user_id).await?;
}
```

**Auth-code replay revokes all sessions instead of code-scoped ones (pre-fix)**
```rust
// WRONG: revokes ALL user sessions on replay detection
db::delete_sessions_for_user(&state.store, &user_id).await?;
// should be:
// db::delete_sessions_for_code_replay(&state.store, &code_hash).await?;
```

## Correct patterns

**Deactivation ordering via `revoke_then_persist`**
```rust
let updated = crate::services::auth::revoke_then_persist(
    &state,
    &target_id,
    "User deactivated by admin",
    &admin.id,
    || db::update_user_active_status(&state.store, &target_id, false),
)
.await
.map_err(|e| match e {
    DeactivationError::Revoke(err) => err,
    DeactivationError::Persist(err) => ServiceError::from(err),
})?;
```

**Credential-revocation ordering via `revoke_then_persist` (admin revoke_member_credentials)**

`delete_authenticator` is a persisted state change that withdraws the member's login path: the same ordering invariant as `active=false` applies — revocation runs first, authenticator deletion is the `persist` closure, and only runs if revocation succeeded. This matches the helper's documented anti-pattern: persisting first and then failing `revoke_user_access` (which is non-atomic) leaves the member locked out while long-lived credentials stay live.
```rust
let authenticators = db::get_authenticators_for_user(&state.store, &target_id).await?;
let key_count = authenticators.len();
crate::services::auth::revoke_then_persist(
    &state,
    &target_id,
    "Credentials revoked by admin",
    &admin.id,
    || async {
        let mut tx = state.store.begin().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to start transaction")
        })?;
        for auth in &authenticators {
            db::delete_authenticator(&mut tx, &auth.id)
                .await
                .map_err(|e| ServiceError::from_db_contention(e, "Failed to revoke key"))?;
        }
        tx.commit().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to commit key revocation")
        })?;
        Ok::<(), ServiceError>(())
    },
)
.await
.map_err(|e| match e {
    DeactivationError::Revoke(err) => err,
    DeactivationError::Persist(err) => err,
})?;
```

**`user.active` check in FIDO2 / lookup paths**
```rust
// Inside lookup_and_verify_authenticator:
if !user.active {
    return Err(ServiceError::Forbidden("user_deactivated"));
}
```

**`user.active` check in introspection (non-M2M tokens)**
```rust
if session.session_type != db::SessionPurpose::M2MAccessToken {
    let user_active = db::get_user_by_id(&state.store, &session.user_id)
        .await
        .map_err(|e| ServiceError::Internal(...))?
        .is_some_and(|u| u.active);
    if !user_active {
        return Ok(IntrospectionResult::inactive());
    }
}
```

**Token-exchange actor check**
```rust
let actor_user = db::get_user_by_id(&state.store, actor_decoded.sub()).await?
    .ok_or_else(|| ServiceError::oauth(InvalidGrant, "Actor not found"))?;
if !actor_user.active {
    return Err(ServiceError::oauth(InvalidGrant, "Actor account is deactivated"));
}
```

**RFC 7009 ownership check before revocation**
```rust
if let Some(DecodedToken::AccessToken(ref claims)) = decoded
    && caller_client_id != claims.client_id
{
    return RevocationResult { revoked: false, user_email: None };
}
```

**SSH revocation using real issued-cert serials**
```rust
// revoke_all_ssh_certificates_for_user looks up SshIssuedCertDoc by user_id,
// then inserts one SshRevokedCertDoc per real numeric serial from those records.
let issued = store.find_all::<SshIssuedCertDoc>("user_id", user_id).await?;
for cert in &issued {
    store.insert(&SshRevokedCertDoc { serial: cert.data.serial.clone(), .. }).await?;
}
```

## Scope

All files under `crates/vouch-server/src/` in these directories:

- `handlers/admin/members.rs` — deactivate_member, remove_member, revoke_member_credentials
- `handlers/scim/users.rs` — patch_user (deactivation branch), delete_user
- `handlers/scim/mod.rs` — SCIM active-value parsing
- `handlers/device.rs` — device_token (approved branch)
- `handlers/keys.rs` — register_complete
- `handlers/applications/mod.rs` — revoke_tokens_api
- `handlers/oidc/introspect.rs` — JTI commit after private_key_jwt auth
- `services/auth.rs` — revoke_user_access, revoke_then_persist, exchange_jwt_bearer_grant
- `services/oidc/token.rs` — exchange_authorization_code (authenticator existence check)
- `services/oidc/fido2_grant.rs` — exchange_fido2_assertion
- `services/oidc/exchange.rs` — exchange_token (subject and actor active checks)
- `services/oidc/introspection.rs` — introspect_token, revoke_token
- `services/oidc/authorization.rs` — replay revocation scope
- `services/oidc/registration.rs` — misdirected-token revocation ownership
- `services/integrations/kubernetes.rs`, `aws.rs`, `github/` — credential minting
- `db/enrollment.rs` — enroll_user_with_org (SSO deactivation gate)
- `db/credentials.rs` — revoke_all_ssh_certificates_for_user (serial matching)
- `db/sessions.rs` — delete_sessions_for_code_replay (partial-failure cache sync)
