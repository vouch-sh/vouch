# Secret-Gate Must Key On Token Endpoint Auth Method

Secret-holding, secret-minting, secret-deletion, and secret-authentication decisions must be keyed on `TokenEndpointAuthMethod::uses_client_secret()`, never on `OAuthClient::client_type()`, `OAuthClientType::requires_secret()`, or `is_fapi()` alone.

## What to look for

Any code that decides whether a client **holds**, **may mint**, **may revoke**, or **may authenticate with** a `client_secret` must use `token_endpoint_auth_method.uses_client_secret()` as its primary predicate. The following predicates are incorrect substitutes:

**Wrong predicates:**
- `client.client_type() == ClientType::Confidential` / `client.client_type() != ClientType::Confidential` — `client_type()` returns `Confidential` for `private_key_jwt`, `tls_client_auth`, and `self_signed_tls_client_auth`, none of which authenticate with a secret.
- `client.application_type.requires_secret()` — returns `true` only for `Web`/`Service`, excluding dynamically-registered `Native`/`SPA` clients that have a `client_secret_*` method, and does not exclude `private_key_jwt` or mTLS clients.
- `!client.is_fapi()` alone as the sole guard — blocks FAPI clients but not non-FAPI `private_key_jwt` or non-FAPI mTLS clients.

**Correct predicate:**
- `client.token_endpoint_auth_method.uses_client_secret()` — returns `true` only for `ClientSecretBasic` and `ClientSecretPost`; returns `false` for `PrivateKeyJwt`, `TlsClientAuth`, `SelfSignedTlsClientAuth`, and `None`.

**The five enforcement points** where the correct predicate must be used:

1. **Secret-mint handler (web):** `add_secret_form` in `handlers/applications/web.rs`
2. **Secret-mint handler (API):** `add_secret_api` in `handlers/api/applications.rs`
3. **Last-secret deletion floor (handler):** pre-flight check before `revoke_oauth_client_secret` in both `web.rs` and `api/applications.rs`
4. **Last-secret deletion floor (in-transaction):** `revoke_oauth_client_secret` in `db/oauth.rs`
5. **Token endpoint secret verification:** `authenticate_client` in `services/oidc/token.rs`

**Also check:**
- UI template guard: `ApplicationInfo::can_add_secret` in `handlers/applications/types.rs` must use `uses_client_secret() && !is_fapi()`.
- Creation-time secret generation: dynamic registration in `services/oidc/registration.rs` must gate `create_oauth_client_secret` on `uses_client_secret()`.

## Violation examples

**Pattern A — mint gated on client_type() (introduced by c9c89a0f, caused auth downgrade for private_key_jwt and dead secrets for mTLS):**
```rust
// In add_secret_api / add_secret_form
if client.client_type() != crate::db::ClientType::Confidential {
    return Err(ServiceError::api(StatusCode::BAD_REQUEST, "no_secret", ...));
}
// Only checks is_fapi() after; non-FAPI private_key_jwt and non-FAPI mTLS
// clients slip through and can mint a client_secret.
if client.is_fapi() { ... }
```
`client_type()` returns `Confidential` for `private_key_jwt`, `tls_client_auth`, and `self_signed_tls_client_auth`, so these non-secret auth methods pass the gate.

**Pattern B — mint gated on application_type (pre-c9c89a0f):**
```rust
// In add_secret_api / add_secret_form
if !client.application_type.requires_secret() {
    return Err(ServiceError::api(StatusCode::BAD_REQUEST, "no_secret", ...));
}
```
`requires_secret()` is `true` only for `Web`/`Service`. This rejects a Native client with a dynamically-registered `client_secret_post`, and allows a Web client with `private_key_jwt` to mint an unusable secret.

**Pattern C — last-secret deletion floor exempts only is_fapi():**
```rust
// In revoke handler or db/oauth.rs transaction
if other_active == 0 && !client.is_fapi() {
    return error_page(...); // or 409 last_secret
}
```
A non-FAPI mTLS or `private_key_jwt` client with a dead secret row is pinned — it can never revoke the stray secret without deleting the entire application.

**Pattern D — token endpoint verifies secret without checking registered method:**
```rust
// In authenticate_client (token.rs)
let is_confidential = client.client_type() == crate::db::ClientType::Confidential;
// mTLS branch exits early; FAPI returns error; then:
if is_confidential {
    let secret = credentials.client_secret.as_ref().ok_or(SecretRequired)?;
    let validated = db::validate_oauth_client_credentials(...).await?;
    Ok((client, Some(ClientSecretVerification { ... })))
    // BUG: never checks that token_endpoint_auth_method is client_secret_*
    // A private_key_jwt client with a minted secret authenticates here.
}
```

## Correct patterns

**Mint gate (both handlers must match):**
```rust
// Check FAPI first for the FAPI-specific error message.
if client.is_fapi() {
    return Err(...); // FAPI-specific message
}
// Then gate on the registered method, not on client_type().
if !client.token_endpoint_auth_method.uses_client_secret() {
    return Err(ServiceError::api(StatusCode::BAD_REQUEST, "no_secret",
        "This client does not use client secrets"));
}
```

**Last-secret deletion floor (handler and in-transaction):**
```rust
// Exempt clients whose secrets authenticate_client never accepts.
let secret_usable = client.token_endpoint_auth_method.uses_client_secret()
    && !client.is_fapi();
if other_active == 0 && secret_usable {
    return Err(/* 409 last_secret */);
}
```

**Token endpoint:**
```rust
let is_confidential = client.client_type() == crate::db::ClientType::Confidential;
let is_mtls_auth = matches!(client.token_endpoint_auth_method,
    TlsClientAuth | SelfSignedTlsClientAuth);
if is_confidential && is_mtls_auth { return Ok((client, None)); } // cert auth
if is_confidential {
    if client.is_fapi() { return Err(ClientAuthError::FapiSecretRejected); }
    // OIDC Core 1.0 §3.1.3.1: client must use its registered method.
    if !client.token_endpoint_auth_method.uses_client_secret() {
        return Err(ClientAuthError::SecretNotRegistered);
    }
    // ... validate secret hash ...
}
```

**UI template guard (`ApplicationInfo::can_add_secret`):**
```rust
let can_add_secret =
    client.token_endpoint_auth_method.uses_client_secret() && !client.is_fapi();
```

**Dynamic registration — creation-time secret:**
```rust
let client_secret = if jwks_auth.auth_method.uses_client_secret() {
    // generate and store secret
} else {
    None
};
```

## Scope

All files under `crates/vouch-server/src/` that touch client-secret decisions:

- `handlers/applications/web.rs` — `add_secret_form`, `delete_secret_form`
- `handlers/api/applications.rs` — `add_secret_api`, `delete_secret_api`
- `handlers/applications/types.rs` — `ApplicationInfo::can_add_secret`
- `db/oauth.rs` — `revoke_oauth_client_secret` (in-transaction floor), `OAuthClient::client_type`
- `services/oidc/token.rs` — `authenticate_client`
- `services/oidc/registration.rs` — creation-time `client_secret` generation
- `handlers/applications/validate.rs` — `build_create_params` creation-time method assignment
- `db/documents/oauth.rs` — `TokenEndpointAuthMethod::uses_client_secret` definition
- Templates: `templates/applications/detail.html`, `templates/applications/created.html`
