# DPoP Token Type Must Match Sender Constraint Binding

The `token_type` in an OAuth token response must be derived from the same value the issued token's `cnf` claim was derived from — never hardcoded and never recomputed in parallel. `create_oauth_access_token` already derives it from `params.binding.token_type()` and returns it as `CreateSessionResult::token_type`, so grant handlers take it from there rather than spelling the derivation themselves. For an access token the value is `DPoP` when `cnf.jkt` is set (RFC 9449 §5) and `Bearer` otherwise, including mTLS-bound tokens (`cnf.x5t#S256`, RFC 8705 defines no distinct token type).

## What to look for

Examine every code path that constructs a token response struct (`TokenResponse`, `TokenExchangeResponse`, `DeviceTokenResponse`, or any custom struct with a `token_type: String` field) in the token handlers and grant services:

1. **Hardcoded `"Bearer"` (or `"DPoP"`) at a grant site.** Any call site that sets `token_type: "Bearer".to_string()` (or `"DPoP"`) instead of `session_result.token_type.to_string()` after calling `create_oauth_access_token` is a violation — the response is no longer tied to the `cnf` claim the issuance pipeline stamped.

2. **Inconsistency between `CreateOAuthTokenParams::binding` and the returned `token_type`.** If `binding: TokenBinding::Dpop(_)` was passed to `create_oauth_access_token` (so `cnf.jkt` will be embedded in the JWT) but the constructed response carries anything other than `"DPoP"`, the response is wrong. The same goes for `TokenBinding::Bearer` / `TokenBinding::MutualTls(_)` producing anything other than `"Bearer"`.

3. **Recomputing `token_type` from the proof/binding instead of using `session_result.token_type`.** Spelling `let token_type = if dpop_proof.is_some() { "DPoP" } else { "Bearer" };` (or `if dpop_jkt.is_some()`) at a grant site is a violation — it duplicates the derivation that lives behind `params.binding.token_type()` / `CnfClaim::token_type`, and the two can drift. Grant handlers that take `CreateSessionResult` and reach the response without referencing `session_result.token_type` are suspect.

The grants to check in this codebase:
- `crates/vouch-server/src/handlers/device.rs` — `device_token`
- `crates/vouch-server/src/services/oidc/token.rs` — `exchange_authorization_code`
- `crates/vouch-server/src/services/oidc/client_credentials.rs` — `exchange_client_credentials`
- `crates/vouch-server/src/services/oidc/exchange.rs` — `exchange_token` (access-token path)
- `crates/vouch-server/src/services/oidc/fido2_grant.rs` — `exchange_fido2_assertion`

Note: the ID-token path in `exchange.rs` (`issue_id_token`) legitimately returns `token_type: "N_A"` (`protocol::TOKEN_TYPE_NOT_APPLICABLE`), not `"Bearer"` — RFC 8693 §2.2.1 mandates `N_A` because the issued token is not usable as an access token. Do not flag it.

## Violation examples

**Recomputing token_type after issuance already derived it**
```rust
// create_oauth_access_token already derives `token_type` from `params.binding`;
// it is returned on session_result.token_type and that is the whole point.
let token_type = if dpop_proof.is_some() {
    "DPoP"
} else {
    "Bearer"
};
Ok(TokenResponse {
    access_token: session_result.token.clone(),
    token_type: token_type.to_string(), // VIOLATION — use session_result.token_type
    expires_in: session_result.expires_in,
})
```

## Correct patterns

**Take `token_type` from `CreateSessionResult` (used in `client_credentials.rs`, `exchange.rs`, `fido2_grant.rs`, `token.rs`, `device.rs`)**
```rust
Ok(SomeResult {
    access_token: session_result.token.clone(),
    token_type: session_result.token_type.to_string(),
    expires_in: session_result.expires_in,
    // ...
})
```

`session_result.token_type` is set inside `create_oauth_access_token` from `params.binding.token_type()` — the same `TokenBinding` whose `cnf()` was stamped into the JWT — so the advertisement cannot disagree with the confirmation the token carries.

## Scope

All files under `crates/vouch-server/src/` that construct and return an OAuth token response, specifically:

- `crates/vouch-server/src/handlers/device.rs`
- `crates/vouch-server/src/handlers/oidc/token.rs`
- `crates/vouch-server/src/services/oidc/token.rs`
- `crates/vouch-server/src/services/oidc/client_credentials.rs`
- `crates/vouch-server/src/services/oidc/exchange.rs`
- `crates/vouch-server/src/services/oidc/fido2_grant.rs`

Any new grant handler added under `crates/vouch-server/src/` that calls `create_oauth_access_token` is automatically in scope.
