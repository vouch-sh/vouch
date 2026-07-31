# OAuth Infrastructure Error Misclassification

Detect OAuth/OIDC error paths that return a 4xx client error (`invalid_client`, `invalid_dpop_proof`, `active:false`) when the underlying failure is a transient infrastructure or database error that should instead return a 5xx `server_error`.

## What to look for

### Pattern 1: Collapsing DB errors into `invalid_client`

A database `Result` is flattened (`.ok()`, `.ok().flatten()`, or a catch-all `Err(_)`) before checking whether a client exists, making a DB failure indistinguishable from a missing/inactive client.

Key signal: a DB lookup whose `Err` arm emits `OAuthErrorCode::InvalidClient` or the string `"invalid_client"` rather than `OAuthErrorCode::ServerError` / `ServiceError::Internal`.

### Pattern 2: Collapsing DB errors into `invalid_dpop_proof`

A `DpopError` match arm uses a catch-all `Err(e)` that maps all variants — including `DpopError::Database(_)` — to `OAuthErrorCode::InvalidDpopProof` (HTTP 400). DB failures during JTI persistence or nonce generation must be matched before the catch-all and routed to `OAuthErrorCode::ServerError` (HTTP 500).

Key signal: a `match validate_dpop_*` or `match DpopError` that lacks an explicit `Err(e @ DpopError::Database(_))` arm before `Err(e)`.

### Pattern 3: Silently returning `{"active": false}` on a server-side error

`IntrospectionResult::inactive()` is the correct response only for expired/unknown tokens. Returning it from any error path — JWT signing failure after a successful introspection, or a DB error from the introspection service itself — misrepresents the token state and gives operators no signal of failure. Server-side failures must surface as HTTP 500 `server_error`.

Key signals: a `match sign_introspection_jwt(...)` (previously `wrap_introspection_jwt`) whose `Err` arm produces `IntrospectionResult::inactive()` or any `active: false` response; or `svc_introspect(...).await` whose `Err` arm (or `.ok()` / `.unwrap_or(...)` collapse) yields `IntrospectionResult::inactive()`.

### Pattern 4: Catch-all mapping `ClaimError::Database` to a 4xx

`ClaimError` has three variants: `AlreadyConsumed` (→ 4xx), `InvalidInput` (→ 4xx), and `Database` (→ 500). A catch-all `Err(e)` arm after only `AlreadyConsumed` will silently map `Database` to the same 4xx as `InvalidInput`. Each `ClaimError` match must either handle all three variants explicitly or use `Database` as an intermediate arm before the catch-all.

A related service-layer variant: producing the wrong `DpopError` variant in the first place. Mapping a `ClaimError::Database` (or any DB error) to `DpopError::InvalidFormat` in `services/oidc/dpop.rs` guarantees the handler classifies it as a 400 even with correct handler-side matching. DB errors must be raised as `DpopError::Database(_)` at the point of production.

### Pattern 5: Using `into_response()` instead of `into_oauth_response()` for OAuth endpoints

On OAuth endpoints, calling `e.into_response()` on a `ServiceError` emits the API envelope `{"code": ..., "message": ...}` instead of the RFC 6749 §5.2 OAuth envelope `{"error": ..., "error_description": ...}`. Always use `e.into_oauth_response().into_response()` (or a dedicated helper like `introspect_error_response`) on OAuth endpoints.

## Violation examples

**Collapsing DB error into `invalid_client` (fixed in c63387d)**

```rust
// VIOLATION: .ok().flatten() swallows DB errors as missing client
match crate::db::get_oauth_client_by_client_id(&state.store, &c.client_id)
    .await
    .ok()           // DB error → None
    .flatten()
    .filter(|oc| oc.active)
{
    Some(client) => client,
    None => {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,  // fires for BOTH missing and DB error
            "Unknown client_id",
        )
        .into_oauth_response()
        .into_response());
    }
}
```

**Collapsing `DpopError::Database` into `invalid_dpop_proof` (fixed in 0f18196)**

```rust
// VIOLATION: catch-all maps DB failures to HTTP 400 invalid_dpop_proof
match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
    Ok(proof) => proof,
    Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
        return dpop_use_nonce_response(&nonce);
    }
    Err(e) => {  // DpopError::Database(_) falls here → HTTP 400
        return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
            .into_oauth_response()
            .into_response();
    }
}
```

**Returning `active: false` on JWT signing failure (fixed in f418a74)**

```rust
// VIOLATION: signing failure silently produces {"active": false}
match wrap_introspection_jwt(&result, &issuer, &client_id, &state.oidc_key).await {
    Ok(jwt) => (StatusCode::OK, [("content-type", "application/token-introspection+jwt")], jwt)
        .into_response(),
    Err(_) => Json(IntrospectionResult::inactive()).into_response(),  // hides the failure
}
```

**All `commit_jti` errors mapped to `invalid_client` (fixed in ea1e4a3)**

```rust
// VIOLATION: DB failure during JTI commit → invalid_client, not server_error
if let Err(e) = commit_jti(&state, pending_jti).await {
    tracing::warn!("JTI commit failed: {e:?}");
    return ServiceError::oauth(
        OAuthErrorCode::InvalidClient,   // DB error looks like bad credentials
        "Client authentication failed",
    )
    .into_oauth_response()
    .into_response();
}
```

**DB error from introspection service returning `{"active": false}` (issue #540)**

```rust
// VIOLATION: Err discarded, DB failure reported as inactive token
let result = match svc_introspect(&state, ...).await {
    Ok(r) => r,
    Err(_) => IntrospectionResult::inactive(),
};
```

**DPoP DB failure raised as `InvalidFormat` in the service layer (issue #427)**

```rust
// VIOLATION in dpop.rs: DB error → InvalidFormat → 400 in handler
Err(e) => return Err(DpopError::InvalidFormat(format!("JTI check failed: {e}"))),
```

**`into_response()` instead of `into_oauth_response()` on an OAuth endpoint (fixed in 91a00b3)**

```rust
// VIOLATION: emits {"code": ..., "message": ...} instead of RFC 6749 error shape
Err(e) => {
    tracing::error!("Introspection failed: {e}");
    return e.into_response();  // API envelope, not OAuth envelope
}
```

## Correct patterns

**Fail-closed DB lookup:**

```rust
let db_result = crate::db::get_oauth_client_by_client_id(&state.store, &c.client_id)
    .await
    .map_err(|e| {
        tracing::error!(client_id = %c.client_id, "DB error looking up OAuth client: {e}");
        ServiceError::Internal("Database error".to_string())
            .into_oauth_response()
            .into_response()
    })?;
match db_result.filter(|oc| oc.active) {
    Some(client) => client,
    None => return Err(ServiceError::oauth(OAuthErrorCode::InvalidClient, "Unknown client_id")
        .into_oauth_response().into_response()),
}
```

**Explicit `DpopError::Database` arm before catch-all:**

```rust
match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
    Ok(proof) => proof,
    Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
        return dpop_use_nonce_response(&nonce);
    }
    Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
        return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
            .into_oauth_response().into_response();
    }
    Err(e) => {
        return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
            .into_oauth_response().into_response();
    }
}
```

**Signing failure → `server_error`, never `active: false`:**

```rust
// Route both error-producing paths through one helper:
fn jwt_introspect_response(jwt_result: Result<String, ServiceError>) -> Response {
    match jwt_result {
        Ok(jwt) => (StatusCode::OK, [("content-type", "application/token-introspection+jwt")], jwt)
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to sign introspection JWT: {e}");
            introspect_error_response(e)  // → 500 server_error, no "active" field
        }
    }
}
```

**Routing `commit_jti` errors by variant:**

```rust
// ClientAuthError::into_service_error() discriminates correctly:
//   InvalidCredentials → invalid_client (401)
//   DatabaseError      → Internal       (500)
if let Err(e) = commit_jti(&state, pending_jti).await {
    return e.into_service_error().into_oauth_response().into_response();
}
```

**OAuth-shaped error on OAuth endpoints:**

```rust
Err(e) => {
    tracing::error!("Introspection failed: {e}");
    return introspect_error_response(e);  // → into_oauth_response()
}
```

**`DpopError::Database` variant raised explicitly in the service layer:**

```rust
Err(db::claim::ClaimError::Database(msg)) => {
    return Err(DpopError::Database(format!("JTI check failed: {msg}")));
}
```

## Scope

All files under:

- `crates/vouch-server/src/handlers/oidc/` — primary scope: `token.rs`, `par.rs`, `userinfo.rs`, `introspect.rs`, `authorize.rs`, `logout.rs`, and any future handler files in this directory
- `crates/vouch-server/src/handlers/session.rs` — DPoP validation on the session resource-auth path
- `crates/vouch-server/src/services/oidc/dpop.rs` — `DpopError` variant routing, and where variants are produced from `ClaimError`
- `crates/vouch-server/src/services/oidc/introspection.rs` — where `IntrospectionResult::inactive()` is constructed
- `crates/vouch-server/src/services/oidc/token.rs` — `ClientAuthError::into_service_error` and `commit_jti`
- `crates/vouch-server/src/db/claim.rs` — `ClaimError` definition (verify `Database` variant remains distinct)

Out of scope: non-OAuth HTTP API handlers, CLI code, agent code.
