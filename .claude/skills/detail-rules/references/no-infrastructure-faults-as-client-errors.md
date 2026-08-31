# No Infrastructure Faults as Client Errors

Infrastructure or transient backend failures must never be reported to the caller as a client-side error code, and a partial write failure must never be reported as success.

## What to look for

### 1. DB/store error mapped to a client-fault error code

Any `Err(...)` arm that converts a database, store, cache, or network failure into a 4xx OAuth error code or a SCIM client error is a violation:

- `invalid_dpop_proof` / `InvalidDpopProof` — valid only for proof defects, never for a JTI or nonce persistence failure
- `invalid_grant` — valid for missing/revoked sessions; a `db::get_session_by_token_hash` that returns `Err(e)` must become `ServiceError::Internal`, not `ServiceError::oauth(InvalidGrant, …)`
- `invalid_client` — valid for credential mismatches; a JWKS cache lookup failure for an inline-JWKS client must not produce `ClientAuthError::InvalidCredentials`
- `409 Conflict` / SCIM `"uniqueness"` — valid for actual uniqueness violations; a serialization timeout or OCC-retry exhaustion must produce `500 INTERNAL_SERVER_ERROR`
- `404 Not Found` — a DB `Err(e)` must not be collapsed into `Ok(None)` and silently treated as "not found"

Pattern to search for: catch-all `Err(e) =>` or `Err(_) =>` arms inside DB call results that emit `invalid_dpop_proof`, `invalid_grant`, `invalid_client`, `409`, or log-and-return-Ok.

### 2. Infrastructure error swallowed; partial write reported as success

An `if let Err(e) = db_call() { tracing::warn!(...) }` (without `return`) or a `let Ok(…) = db_call() else { continue }` that silently discards a write failure, then proceeds to return `200 OK` / `201 Created`, is a violation. Every write that materially changes state must propagate its error (the deliberate best-effort exception is `db::delete_sessions_for_code_replay`, which logs and skips per-session delete failures so already-committed deletes still surface on its `Ok` arm for the caller's cache invalidation; see the `complete-and-ordered-deactivation-revocation` rule).

Pattern to search for:
- `if let Err(e) = db::add_scim_group_member(…) { tracing::warn!(…) }` with no early `return`
- `let Ok(Some(user)) = db::get_user_by_id(…) else { /* skip */ }` after a rotation that already invalidated the old token
- `matches!(…, Ok(Some(_)))` used to collapse `Err(e)` and `Ok(None)` into the same client-error branch

### 3. Catch-all `_` or `Err(e)` that collapses a distinct backend-fault variant

Error enums in this codebase use separate variants for client faults vs. infrastructure faults. Collapsing a `Database(…)` or `Internal(…)` variant into the same arm as `AlreadyConsumed` or `InvalidInput` is a violation.

Pattern to search for:
- `Err(e) => return Err(SomeClientError(format!("… {e}")))` as a catch-all after specific client-fault arms
- A `ClaimError::Database` arm mapped to `DpopError::InvalidFormat` (correct is `DpopError::Database`)
- A `ServiceError::Internal` case falling through `into_oauth_response` — acceptable only if the catch-all maps it to `500 server_error`, not to a 4xx

### 4. Missing-auth vs. bad-auth conflation in RFC 6750 responses

RFC 6750 §3.1: a request that *lacks* credentials entirely must get a bare `WWW-Authenticate: Bearer` (no `error=`). A request that *carries* an invalid token gets `error="invalid_token"`. Emitting `error="invalid_token"` for a missing Authorization header is a violation.

### 5. Retryable DB errors incorrectly classified as non-retryable (or vice versa)

`is_retryable_code` in `db/pool.rs` matches SQLSTATE strings verbatim. Any logic that masks, truncates, or bitwise-ANDs a numeric string before matching can cause a Postgres SQLSTATE (e.g. `"22021"`, `"42501"`) to alias a SQLite retryable primary code (`"5"`, `"6"`). The correct approach is explicit enumeration of the small, stable set of retryable codes.

## Violation examples

**DB error mapped to `invalid_dpop_proof` (400):**
```rust
// Catch-all collapses DB failure into client-proof error
Err(e) => return Err(DpopError::InvalidFormat(format!("JTI check failed: {e}"))),
// and nonce path:
Err(e) => return Err(DpopError::InvalidFormat(format!("nonce validation failed: {e}"))),
```

**Actor session DB error mapped to `invalid_grant`:**
```rust
// !matches! collapses Err(db_error) and Ok(None) into the same InvalidGrant arm
if !matches!(
    state.session_cache.get_session_by_token_hash(&state.store, &hash).await,
    Ok(Some(_))
) {
    return Err(ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Actor token session not found or revoked"));
}
```

**Infrastructure error swallowed; PATCH returns 200 with stale membership:**
```rust
if let Err(e) = db::add_scim_group_member(db, group_id, org_id, user_id).await {
    tracing::warn!("Failed to add member: {e}");
    // Ok(()) returned — PATCH continues and handler returns 200 OK with stale data
}
```

**Group create returns `409 Conflict` for all non-uniqueness DB errors:**
```rust
Err(e) => {
    let detail = if e.to_string().contains("UNIQUE") { "Group already exists" } else { "Failed to create group" };
    return (StatusCode::CONFLICT, Json(ScimError::new(409, detail).with_type("uniqueness"))).into_response();
}
```

**Wrong OAuth error code: `invalid_client` instead of `invalid_token` for bearer-token failure:**
```rust
Err(_) => {
    return ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid Bearer token")
        .into_oauth_response().into_response();
}
```

**Missing-auth emits `error="invalid_token"` in WWW-Authenticate (RFC 6750 §3.1 violation):**
```rust
fn missing_token_response() -> Response {
    (StatusCode::UNAUTHORIZED,
     [("www-authenticate", bearer_challenge(OAuthErrorCode::InvalidToken.as_str(), "Bearer token required"))],
     Json(json!({"error": "invalid_token"}))).into_response()
}
```

**GitHub refresh-token rotation: DB error swallowed, invalidated token permanently lost:**
```rust
if let Some(new_refresh_token) = &token_response.refresh_token
    && let Ok(Some(user)) = db::get_user_by_id(self.store, user_id).await  // Err swallowed
    && let (Some(github_id), Some(github_login)) = (user.github_id, &user.github_login)
{
    // Best-effort rotation — "the next refresh will retry" (incorrect: old token was already invalidated)
}
```

**JWKS cache lookup unconditionally gates inline-JWKS client authentication:**
```rust
// Loads cache even for inline-JWKS clients; DB error becomes 401 InvalidCredentials
let jwks_cache = crate::db::get_jwks_cache(&state.store, &client.id)
    .await
    .map_err(|_| ClientAuthError::InvalidCredentials)?;
```

**SQLSTATE masking produces false-positive retries:**
```rust
let primary = numeric & 0xFF;   // Postgres "42501" → 5 → collides with SQLITE_BUSY
let primary_str = primary.to_string();
RETRYABLE_SQL_STATES.contains(&primary_str.as_str())
```

## Correct patterns

**DB error in DPoP mapped to `DpopError::Database` (500), not `InvalidFormat` (400):**
```rust
Err(db::claim::ClaimError::AlreadyConsumed) => return Err(DpopError::ReplayDetected),
Err(db::claim::ClaimError::InvalidInput(msg)) => return Err(DpopError::InvalidFormat(msg)),
Err(db::claim::ClaimError::Database(msg)) => {
    return Err(DpopError::Database(format!("JTI check failed: {msg}")));
}
```

**Actor session lookup: Err propagated as Internal, Ok(None) as InvalidGrant:**
```rust
let _actor_session = state.session_cache
    .get_session_by_token_hash(&state.store, &actor_token_hash)
    .await
    .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    .ok_or_else(|| ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Actor token session not found or revoked"))?;
```

**Group member write failure returns 500, not swallowed:**
```rust
if let Err(e) = db::add_scim_group_member(db, group_id, org_id, user_id).await {
    return Err(member_op_error_response(e));
}
```

**Group create infrastructure error returns 500:**
```rust
pub(super) fn create_scim_group_error_response(err: anyhow::Error) -> Response {
    if let Some(resp) = super::invalid_index_value_response(&err) {
        return resp.into_response();
    }
    tracing::error!("Failed to create group: {err}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ScimError::new(500, "Failed to create group"))).into_response()
}
```

**Missing-auth response has no error code; invalid-token response does:**
```rust
// Missing auth — RFC 6750 §3.1: bare Bearer, no error= parameter, no body
fn missing_token_response() -> Response {
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, bearer_challenge(&[]))]).into_response()
}
// Invalid token — error= included
fn into_registration_response(err: ServiceError) -> Response { ... /* error="invalid_token" */ }
```

**GitHub rotation propagates DB errors instead of swallowing them:**
```rust
let user = db::get_user_by_id(self.store, user_id)
    .await
    .map_err(GitHubError::Database)?          // propagate
    .ok_or(GitHubError::UserNotFound)?;
db::update_user_github_identity(self.store, user_id, github_id, github_login, Some(new_refresh_token.expose_secret()))
    .await
    .map_err(GitHubError::Database)?;         // propagate
```

**JWKS cache skipped for inline-JWKS clients:**
```rust
let jwks_cache = if client.jwks_uri.is_some() {
    crate::db::get_jwks_cache(&state.store, &client.id).await.ok().flatten()
} else {
    None  // inline JWKS: skip DB lookup entirely
};
```

**SQLSTATE retryable check uses verbatim list, no masking:**
```rust
const RETRYABLE_SQL_STATES: &[&str] = &["40001", "OC000", "OC001", "5", "6", "261", "517", "773", "262", "518"];
fn is_retryable_code(code: &str) -> bool {
    RETRYABLE_SQL_STATES.contains(&code)
}
```

**`ServiceError::from_db_contention` separates retryable from non-retryable DB errors:**
```rust
pub(crate) fn from_db_contention(err: anyhow::Error, msg: &'static str) -> Self {
    tracing::error!("{msg}: {err}");
    if crate::db::pool::is_retryable_db_error(&err) {
        Self::OccConflict
    } else {
        Self::Internal(msg.to_string())
    }
}
```

## Scope

All files under `crates/vouch-server/src/`:

- `handlers/oidc/` — token, PAR, register, introspect, authorize, par endpoints
- `handlers/scim/` — users, groups, mod (SCIM CRUD and auth)
- `services/oidc/` — dpop, exchange, jwt_bearer/client_auth, registration
- `services/integrations/github/oauth.rs`
- `db/` — dpop, oauth, scim, pool (error classification and retry logic)
- `infra/jwks.rs`
- `error.rs` — `ServiceError::into_oauth_response` catch-all mapping

Out of scope: CLI crates, test-only code, and infrastructure that never returns a client-facing HTTP response.
