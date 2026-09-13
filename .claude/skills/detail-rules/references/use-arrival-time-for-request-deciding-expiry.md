# Use ArrivalTime for Request-Deciding Expiry Comparisons

Every time comparison that decides whether a request succeeds must use the request's `ArrivalTime`, never a fresh `Timestamp::now()`. An `#[expect(clippy::disallowed_methods)]` exemption must be attached only to individual functions and must name a sanctioned case; module-level exemptions and mismatched reasons are violations even when no bare `Timestamp::now()` is visible.

## What to look for

### 1. Ambient clock in a request-deciding DB helper

A db-layer helper that compares `expires_at` to determine whether a request succeeds must receive the instant as a parameter and not stamp its own. The canonical shape is:

```rust
pub async fn get_session_by_token_hash(
    store: &DocumentStore,
    token_hash: &str,
    now: Timestamp,     // caller supplies arrival.timestamp()
) -> Result<Option<Session>>
```

Request-deciding helpers include:
- DPoP nonce consume (`validate_and_consume_dpop_nonce`)
- Authorization code consume (`try_consume_authorization_code`)
- PAR lookup and consume (`get_pushed_authorization_request`, `ParConsumptionProof::consume`)
- OIDC state consume (`try_consume_oidc_state`)
- Pending-auth lookup and consume (`get_pending_oauth_authorization`, `consume_pending_oauth_authorization`)
- SCIM token lookup (`get_scim_token_by_hash`)
- Client credential validation (`validate_oauth_client_credentials`)

A helper that stamps `let now = Timestamp::now()` and uses that value in an `expires_at` comparison is a violation **even when the function itself carries no `#[expect]`** (the lint may already be suppressed at the module level — see below).

### 2. Module-level `#[expect(clippy::disallowed_methods)]` on a `mod` declaration

An exemption on a `mod` declaration silently covers every function that module later grows. The only correct granularity is per-function. Compare:

**Violation** (on the `mod` declaration):
```rust
#[expect(clippy::disallowed_methods, reason = "db layer stamps row timestamps …")]
pub(crate) mod dpop;
```

**Correct** (on each individual function that actually stamps):
```rust
// in dpop.rs:
#[expect(clippy::disallowed_methods, reason = "stamps the nonce's expires_at")]
pub async fn generate_dpop_nonce(…) { … }
```

Look specifically at `crates/vouch-server/src/db/mod.rs`. If any `mod` declaration there carries `#[expect(clippy::disallowed_methods, …)]`, that is a violation.

### 3. Mismatched `reason` on a per-function exemption

An exemption is valid only when the named reason matches what the function actually does with `Timestamp::now()`. Two common mismatches:

- **Minting reason on a comparison function**: A function that compares `expires_at` to decide a request cannot claim `reason = "mints the ID token's exp"` or similar — only a function that genuinely writes a row or issues a JWT can hold a minting reason.
- **OCC-retry reason on a non-retry function**: `reason = "re-reads per OCC attempt"` is valid only inside a retry closure that needs a fresh per-attempt value; it is not valid on a function that reads the clock once to compare against stored data.

### 4. Request-scoped temporal claim stamped from ambient clock in a service function

In `services/oidc/`, any function that stamps `exp`/`iat` on a JWT and is called from a request path (not a background task) must derive its instant from the caller-supplied `ArrivalTime`, not from an independent `Timestamp::now()`. The function must not carry `#[expect(clippy::disallowed_methods)]` with a minting reason if the value it computes must agree with other timestamps in the same response.

**Sanctioned exceptions** (these genuinely use an ambient clock and may carry a per-function `#[expect]`):
- `ArrivalTime::stamp()` in `arrival.rs` — the one place that reads the clock for an incoming request
- Writing `created_at`, `expires_at`, `last_used_at` on a row being **inserted** (not compared)
- Re-reading the clock inside an OCC retry closure for a fresh per-attempt stamp
- Background sweeps with no `ArrivalTime` (e.g., `delete_expired_*` functions in `infra/cleanup.rs`)
- Code reached from a trait that carries no request instant (e.g., `infra/httpsig.rs`)

## Violation examples

### Module-level exemption masking request-deciding comparisons (from commit `addbaecd`, `db/mod.rs`)

```rust
// VIOLATION — module-wide exemption hid five request-deciding comparisons
// that the modules grew after the exemption was granted.
#[expect(
    clippy::disallowed_methods,
    reason = "db layer stamps row timestamps and re-reads the clock per OCC attempt"
)]
pub(crate) mod dpop;

#[expect(
    clippy::disallowed_methods,
    reason = "db layer stamps row timestamps and re-reads the clock per OCC attempt"
)]
pub(crate) mod par;
```

The modules `dpop`, `par`, `authorization_codes`, `scim`, and `pending_oauth` each acquired a function that stamped its own clock for an `expires_at` comparison; the module-level exemption prevented the lint from reporting any of them.

### Ambient clock in a request-deciding DB helper (from bug `db/dpop.rs`, fixed in commit `f153b13e`)

```rust
// VIOLATION — stamps a fresh clock for a request-path expiry comparison
pub async fn validate_and_consume_dpop_nonce(
    store: &DocumentStore,
    nonce: &str,
) -> std::result::Result<(), ClaimError> {
    let id = deterministic_dpop_nonce_id(nonce);
    let now = Timestamp::now();   // BUG: uses a fresh clock, not request arrival
    let won = store
        .delete_if_not_expired(&id, &now)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won { Ok(()) } else { Err(ClaimError::AlreadyConsumed) }
}
```

### Mismatched reason — minting exemption on a comparison function (from bug `services/oidc/token.rs`, fixed in commit `6f351660`)

```rust
// VIOLATION — claims "mints the ID token's exp" but the value must agree
// with the access token exp and session expires_at in the same response,
// making it a request-scoped comparison, not an artifact mint.
#[expect(clippy::disallowed_methods, reason = "mints the ID token's exp")]
async fn generate_id_token(
    state: &Arc<AppState>,
    params: IdTokenParams<'_>,
) -> ServiceResult<String> {
    let now = Timestamp::now();   // BUG: diverges from arrival used by access-token mint
    let exp = now.as_second().checked_add(expires_seconds)…;
    …
}
```

### Mismatched reason — minting exemption in RFC 8693 builder (from bug `services/oidc/claims.rs`, fixed in commit `b35ddd3e`)

```rust
// VIOLATION — the builder stamps exp/iat from its own clock while the
// exchange cap and audit expires_at are anchored on the request's arrival;
// all three must agree.
#[expect(
    clippy::disallowed_methods,
    reason = "mints the ID token's iat and exp"
)]
pub fn build(self) -> Result<OidcIdTokenClaims, ClaimsBuildError> {
    let now = jiff::Timestamp::now();   // BUG: diverges from arrival used for cap/audit
    let exp = now.as_second()
        .saturating_add(i64::try_from(self.valid_for_seconds).unwrap_or(28800));
    …
}
```

## Correct patterns

### Per-function exemption for a genuine row-stamping function

```rust
// CORRECT — exemption is on the function, reason matches what the function does
#[expect(clippy::disallowed_methods, reason = "stamps the nonce's expires_at")]
pub async fn generate_dpop_nonce(store: &DocumentStore, validity_seconds: i64) -> Result<String> {
    let now = Timestamp::now();
    let expires_at = now.checked_add(validity_seconds.seconds())…;
    …
}
```

### Request-deciding helper takes instant as a parameter

```rust
// CORRECT — no #[expect] needed; the helper does not call Timestamp::now()
pub async fn validate_and_consume_dpop_nonce(
    store: &DocumentStore,
    nonce: &str,
    now: &Timestamp,          // caller passes arrival.timestamp()
) -> std::result::Result<(), ClaimError> {
    let id = deterministic_dpop_nonce_id(nonce);
    let won = store.delete_if_not_expired(&id, now).await…;
    …
}
```

### Service function that threads arrival through to the token builder

```rust
// CORRECT — no ambient clock; arrival is threaded from the handler
async fn generate_id_token(
    state: &Arc<AppState>,
    params: IdTokenParams<'_>,
    arrival: ArrivalTime,     // threaded from caller
) -> ServiceResult<String> {
    let now = arrival.timestamp();   // same instant as access token and session
    let exp = now.as_second().checked_add(expires_seconds)…;
    …
}
```

### Builder that requires a supplied instant

```rust
// CORRECT — build() requires issued_at(Timestamp) to be set; no fallback to Timestamp::now()
pub fn build(self) -> Result<OidcIdTokenClaims, ClaimsBuildError> {
    let now = self.issued_at.ok_or(ClaimsBuildError::MissingField("issued_at"))?;
    let exp = now.as_second().saturating_add(…);
    …
}
```

## Scope

Check all files under:
- `crates/vouch-server/src/db/` — especially `mod.rs` (for module-level exemptions) and every file that contains an `#[expect(clippy::disallowed_methods, …)]` or that has a function comparing `expires_at`
- `crates/vouch-server/src/services/oidc/` — especially `token.rs`, `claims.rs`, `exchange.rs`, `dpop.rs`
- `crates/vouch-server/src/handlers/` — any handler that carries `#[expect(clippy::disallowed_methods, …)]` whose reason names a temporal concept
- `crates/vouch-server/src/arrival.rs` — the canonical reference for which clock each comparison should use

Out of scope: `crates/vouch-server/src/infra/httpsig.rs` (trait boundary prevents threading `ArrivalTime`; the ambient clock there is documented and intentional).
