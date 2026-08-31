# Transient-Failure Mapped to Client Error

Detect error-handling paths where a transient database or server-side failure is mapped to a client-facing 4xx error code or a semantically misleading success response (such as `invalid_client`, `invalid_dpop_proof`, or `{"active": false}`), masking infrastructure failures as permanent client errors and hiding them from operators.

## What to look for

### 1. Catch-all `Err(_)` or `_ =>` swallowing `DpopError::Database`, `ClaimError::Database`, or `ClientAuthError::DatabaseError`

In this repo, `DpopError`, `ClaimError`, and `ClientAuthError` each have a `Database(String)` / `DatabaseError(String)` variant that must be routed to HTTP 500 (`server_error`). A catch-all arm that covers all remaining variants after handling the expected cases will silently absorb `Database` errors and return a 4xx instead.

**Pattern to flag:** A `match` on one of these error enums that uses a catch-all `Err(e) =>` or `_ =>` arm emitting `invalid_dpop_proof`, `invalid_client`, a 4xx status code, or `IntrospectionResult::inactive()`, **without** a prior explicit arm for `DpopError::Database(_)`, `ClaimError::Database(_)`, or `ClientAuthError::DatabaseError(_)`.

### 2. `.ok()` or `.ok().flatten()` collapsing a DB `Result` into `None`

Using `.ok()` on a `Result<Option<T>, DbError>` discards a database error, making a connectivity failure indistinguishable from "not found". When the resulting `None` triggers an `invalid_client` or similar response, infrastructure failures are misrepresented as client errors.

**Pattern to flag:** `store_call().await.ok().flatten().filter(|x| x.active)` or similar, feeding into an `invalid_client` response when `None`.

### 3. Returning `{"active": false}` on a server-side error

`IntrospectionResult::inactive()` is the correct response for expired/unknown tokens. Returning it from an error path (signing failure, DB error) misrepresents a validated active token as inactive and gives operators no signal of failure.

**Pattern to flag:** A `match jwt_signing_result { Err(_) => Json(IntrospectionResult::inactive()) }` or `Err(_) => IntrospectionResult::inactive()` where the error is a server failure, not a logical token state.

### 4. DB errors from `commit_jti` mapped to `invalid_client`

`commit_jti` can fail with either `ClientAuthError::InvalidCredentials` (JTI replay — a real client error) or `ClientAuthError::DatabaseError` (transient). A flat mapping of all `commit_jti` failures to `OAuthErrorCode::InvalidClient` hides connectivity failures.

**Pattern to flag:** `let Err(e) = commit_jti(...).await { return ServiceError::oauth(OAuthErrorCode::InvalidClient, ...) }` with no discrimination by error variant.

### 5. DB lookup errors collapsed with "not found" into `invalid_client`

`db::get_oauth_client_by_client_id(...).await.ok().flatten().filter(|oc| oc.active)` maps DB errors, unknown clients, AND inactive clients all to `None`, so a connectivity failure looks like an unknown client and returns `invalid_client`.

## Violation examples

**Catch-all DPoP handler returning `invalid_dpop_proof` on DB error (issue #427):**
```rust
// BEFORE (violation): DpopError::Database swallowed by catch-all
match validate_dpop_if_present(...).await {
    Err(DpopError::UseNonce(nonce)) => return dpop_use_nonce_response(&nonce),
    Err(e) => {
        return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
            .into_oauth_response()
            .into_response();
    }
}
```

**JWT signing failure returning `{"active": false}` instead of 500 (issue #396):**
```rust
// BEFORE (violation): signing error returns inactive token, not 500
match wrap_introspection_jwt(&result, &issuer, &client_id, &state.oidc_key).await {
    Ok(jwt) => (StatusCode::OK, ..., jwt).into_response(),
    Err(_) => Json(IntrospectionResult::inactive()).into_response(),
}
```

**DB error from introspection service returning `{"active": false}` (issue #540):**
```rust
// BEFORE (violation): .ok() discards DB error, returns inactive
let result = match svc_introspect(&state, ...).await {
    Ok(r) => r,
    Err(_) => IntrospectionResult::inactive(),
};
```

**`commit_jti` failure mapped to `invalid_client` regardless of cause (issue fixed in ea1e4a3):**
```rust
// BEFORE (violation): all commit_jti failures -> invalid_client, including DB errors
if let Err(e) = commit_jti(&state, pending_jti).await {
    return ServiceError::oauth(OAuthErrorCode::InvalidClient, "Client authentication failed")
        .into_oauth_response()
        .into_response();
}
```

**Client lookup collapsing DB error with "not found" (issue fixed in c63387d):**
```rust
// BEFORE (violation): DB error + None + inactive all yield invalid_client
match db::get_oauth_client_by_client_id(&state.store, &c.client_id)
    .await
    .ok()
    .flatten()
    .filter(|oc| oc.active)
{
    Some(client) => client,
    None => return Err(ServiceError::oauth(OAuthErrorCode::InvalidClient, "Unknown client_id")
        .into_oauth_response().into_response()),
}
```

**DPoP nonce/JTI DB failure mapped to `invalid_dpop_proof` via `InvalidFormat` (issue #427):**
```rust
// BEFORE (violation in dpop.rs service layer): DB error -> InvalidFormat -> 400 in handler
Err(e) => return Err(DpopError::InvalidFormat(format!("JTI check failed: {e}"))),
```

## Correct patterns

**Explicit `Database` arm routes to 500:**
```rust
match validate_dpop_if_present(...).await {
    Err(DpopError::UseNonce(nonce)) => return dpop_use_nonce_response(&nonce),
    Err(e @ DpopError::Database(_)) => {
        return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
            .into_oauth_response()
            .into_response();
    }
    Err(e) => {
        return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
            .into_oauth_response()
            .into_response();
    }
}
```

**JWT signing failure returns 500 `server_error`, never `{"active": false}`:**
```rust
fn jwt_introspect_response(jwt_result: Result<String, ServiceError>) -> Response {
    match jwt_result {
        Ok(jwt) => (StatusCode::OK, ..., jwt).into_response(),
        Err(e) => {
            tracing::error!("Failed to sign introspection JWT: {e}");
            introspect_error_response(e) // routes through into_oauth_response -> server_error
        }
    }
}
```

**DB introspection failure propagated as 500:**
```rust
let result = match svc_introspect(&state, ...).await {
    Ok(r) => r,
    Err(e) => {
        tracing::error!("Introspection failed: {e}");
        return introspect_error_response(e);
    }
};
```

**`commit_jti` failure discriminated by variant:**
```rust
if let Err(e) = commit_jti(&state, pending_jti).await {
    // ClientAuthError::into_service_error() maps DatabaseError -> Internal -> 500
    // and InvalidCredentials -> InvalidClient -> 401
    return e.into_service_error().into_oauth_response().into_response();
}
```

**Client lookup separates DB error from "not found":**
```rust
let db_result = db::get_oauth_client_by_client_id(&state.store, &c.client_id)
    .await
    .map_err(|e| {
        tracing::error!("DB error looking up OAuth client: {e}");
        ServiceError::Internal("Database error".to_string())
            .into_oauth_response().into_response()
    })?;
match db_result.filter(|oc| oc.active) {
    Some(client) => client,
    None => return Err(ServiceError::oauth(OAuthErrorCode::InvalidClient, "Unknown client_id")
        .into_oauth_response().into_response()),
}
```

**`DpopError::Database` variant raised explicitly in service layer:**
```rust
Err(db::claim::ClaimError::Database(msg)) => {
    return Err(DpopError::Database(format!("JTI check failed: {msg}")));
}
```

## Scope

Check all files under:

- `crates/vouch-server/src/handlers/oidc/` — `token.rs`, `par.rs`, `userinfo.rs`, `introspect.rs`, `authorize.rs`, `logout.rs`, and any future handler files in this directory
- `crates/vouch-server/src/handlers/session.rs` — DPoP validation on the resource-auth path
- `crates/vouch-server/src/services/oidc/dpop.rs` — where `DpopError` variants are produced from `ClaimError`
- `crates/vouch-server/src/services/oidc/introspection.rs` — where `IntrospectionResult::inactive()` is constructed
- `crates/vouch-server/src/services/oidc/token.rs` — `ClientAuthError` and `commit_jti`
- `crates/vouch-server/src/db/claim.rs` — `ClaimError` definition (verify `Database` variant remains distinct)

The key error types to track: `DpopError`, `ClaimError`, `ClientAuthError`, and `ServiceError`. The key incorrect output signals are: `OAuthErrorCode::InvalidClient`, `OAuthErrorCode::InvalidDpopProof`, `IntrospectionResult::inactive()`, and any HTTP 4xx returned from a match arm that handles a `Database`/`DatabaseError` variant.
