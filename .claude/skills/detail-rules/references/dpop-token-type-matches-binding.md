# DPoP Token Type Must Match Sender Constraint Binding

Token endpoint handlers must compute `token_type` from whether a DPoP proof was validated and threaded into the issued token (`cnf.jkt`), never hardcode it. When `dpop_jkt` is `Some`, the response must advertise `token_type: "DPoP"`; when it is `None`, it must advertise `token_type: "Bearer"` (RFC 9449 Section 5).

## What to look for

Examine every code path that constructs a token response struct (`TokenResponse`, `TokenExchangeResponse`, `DeviceTokenResponse`, or any custom struct with a `token_type: String` field) in the token handlers and grant services:

1. **Hardcoded `"Bearer"` when a DPoP proof may have been validated.** Any call site that sets `token_type: "Bearer".to_string()` (or `"Bearer".to_owned()`) while the surrounding code also holds a `dpop_proof`, `dpop_jkt`, or `dpop_jkt: Option<&str>` binding is a violation — the code minted a `cnf.jkt`-bound token but lied to the client about it.

2. **Inconsistency between `CreateOAuthTokenParams::dpop_jkt` and the returned `token_type`.** If `dpop_jkt: Some(...)` is passed to `create_oauth_access_token` (meaning `cnf.jkt` will be embedded in the JWT), but the constructed response carries `token_type: "Bearer"`, the response is wrong.

3. **Missing conditional before setting `token_type`.** The correct pattern is always:
   ```rust
   let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
   ```
   or equivalently testing `dpop_proof.is_some()`. A grant handler that reaches token issuance without this conditional is suspect.

The grants to check in this codebase:
- `crates/vouch-server/src/handlers/device.rs` — `device_token` (the site of the confirmed bug)
- `crates/vouch-server/src/services/oidc/token.rs` — `exchange_authorization_code`
- `crates/vouch-server/src/services/oidc/client_credentials.rs` — `exchange_client_credentials`
- `crates/vouch-server/src/services/oidc/exchange.rs` — `exchange_token` (access-token path)
- `crates/vouch-server/src/services/oidc/fido2_grant.rs` — `exchange_fido2_assertion`

Note: the ID-token path in `exchange.rs` (`issue_id_token`) legitimately returns `"Bearer"` because no DPoP-bound access token is issued there; do not flag it.

## Violation examples

**Device flow hardcodes Bearer after threading dpop_jkt into the token (confirmed bug, `handlers/device.rs`)**
```rust
// dpop_jkt is derived from the validated DPoP proof above and passed to
// create_oauth_access_token — the token carries cnf.jkt — but the response says Bearer.
let session_result = create_oauth_access_token(
    &state,
    CreateOAuthTokenParams {
        dpop_jkt: dpop_jkt.as_deref(), // Some("...") when DPoP proof was present
        // ...
    },
    proof,
).await?;

Ok(Json(DeviceTokenResponse {
    access_token: token.expose_secret().to_string(),
    token_type: "Bearer".to_string(), // BUG: hardcoded; should be "DPoP" when dpop_jkt is Some
    expires_in,
    email: user_email,
}))
```

**Generic pattern — hardcoded Bearer after DPoP validation**
```rust
// dpop_proof is Some(...) — token will be cnf.jkt-bound
let dpop_jkt = dpop_proof.as_ref().map(|p| p.jkt.clone());
// ... create_oauth_access_token called with dpop_jkt: dpop_jkt.as_deref() ...
Ok(TokenResponse {
    access_token: result.access_token,
    token_type: "Bearer".to_string(), // VIOLATION
    expires_in: result.expires_in,
})
```

## Correct patterns

**Compute token_type from dpop_jkt (used in `client_credentials.rs`, `exchange.rs`, `fido2_grant.rs`, `token.rs`)**
```rust
// RFC 9449 Section 5: token_type is "DPoP" when the token is sender-constrained
let token_type = if bindings.dpop_jkt.is_some() {
    "DPoP"
} else {
    "Bearer"
};
Ok(SomeResult {
    access_token: ...,
    token_type: token_type.to_string(),
    expires_in: ...,
})
```

**Equivalent form using the proof object directly**
```rust
let token_type = if dpop_proof.is_some() { "DPoP" } else { "Bearer" };
```

Both forms are correct as long as the variable tested (`dpop_jkt` or `dpop_proof`) is the same binding that was passed to `create_oauth_access_token` as `dpop_jkt`.

## Scope

All files under `crates/vouch-server/src/` that construct and return an OAuth token response, specifically:

- `crates/vouch-server/src/handlers/device.rs`
- `crates/vouch-server/src/handlers/oidc/token.rs`
- `crates/vouch-server/src/services/oidc/token.rs`
- `crates/vouch-server/src/services/oidc/client_credentials.rs`
- `crates/vouch-server/src/services/oidc/exchange.rs`
- `crates/vouch-server/src/services/oidc/fido2_grant.rs`

Any new grant handler added under `crates/vouch-server/src/` that calls `create_oauth_access_token` is automatically in scope.
