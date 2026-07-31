# Normalize Email Before Store or Compare

Detect email addresses stored, indexed, or compared without first being normalized to ASCII lowercase, which causes cross-protocol identity mismatches and broken SCIM eq-filter lookups.

## What to look for

Email addresses flow into this codebase from three sources — OIDC `id_token` claims, SAML assertions, and SCIM provisioning payloads — and any of them may deliver mixed-case addresses (e.g. `Alice@CORP.Example.COM`). The stored canonical form is always ASCII lowercase. A violation occurs when code uses a caller-supplied email string to:

1. **Write a `UserDoc` row** via `store.insert`, `tx.insert`, or `tx.insert_with_id` without calling `.to_ascii_lowercase()` on the email before building the doc.
2. **Look up a user by email index** via `store.find_one::<UserDoc>("email", …)` or `store.find_by_indexes::<UserDoc>(&[("email", …), …])` without normalizing the value argument first.
3. **Compute an HMAC for the audit index** via `self.crypto.hmac_index(email)` without normalizing the email first — the HMAC at query time must match the HMAC computed at insert time.
4. **Extract the domain for audit or org filtering** via `rsplit_once('@')` without calling `.to_ascii_lowercase()` on the resulting domain fragment.
5. **Evaluate a SCIM `eq` filter** for `userName` or `email` attributes without lowercasing `filter.value` before the indexed lookup. (`externalId` is `caseExact: true` per RFC 7643 §3.1 and must **not** be lowercased.)
6. **Derive a deterministic user ID** for concurrent-create protection without lowercasing the email inside the derivation — two casings of the same address must produce the same primary key.

The correct normalization call is `.to_ascii_lowercase()` (not `.to_lowercase()`). `to_ascii_lowercase` folds only A–Z without altering multibyte characters or changing byte lengths, which is sufficient for well-formed email addresses and matches the existing convention throughout this repo.

## Violation examples

**Enrollment without normalization (pre-fix pattern, `db/enrollment.rs`)**
```rust
// VIOLATION: email from IdP written directly to UserDoc without lowercasing
pub async fn enroll_user_with_org(store: &DocumentStore, email: &str, ...) {
    let existing_user = tx.find_one::<UserDoc>("email", email).await?;
    // ...
    let doc = UserDoc { email: email.to_string(), ... };
    tx.insert(&doc).await?;
}
```

**SCIM create without normalization (pre-fix pattern, `db/scim.rs`)**
```rust
// VIOLATION: email stored as-is; Alice@example.com and alice@example.com
// produce two distinct rows for the same person
pub async fn create_scim_user(store: &DocumentStore, email: &str, ...) {
    if tx.find_one::<UserDoc>("email", email).await?.is_some() {
        bail!("UNIQUE constraint failed: ...");
    }
    let doc = UserDoc { email: email.to_string(), ... };
    tx.insert(&doc).await?;
}
```

**SCIM eq-filter without normalization (pre-fix pattern, `db/scim.rs`)**
```rust
// VIOLATION: filter value passed directly to indexed lookup;
// `userName eq "Alice@example.com"` misses the stored `alice@example.com`
if f.op == ScimFilterOp::Eq {
    let docs = store
        .find_by_indexes::<UserDoc>(&[("email", &f.value), ("org_id", org_id)])
        .await?;
}
```

**Audit HMAC without normalization (pre-fix pattern, `db/audit.rs`)**
```rust
// VIOLATION: HMAC of mixed-case email differs from HMAC of stored lowercase
// email — query by email returns no results
let email_hmac = email.map(|e| self.crypto.hmac_index(e));

// VIOLATION (query side): lookup HMAC won't match stored HMAC
let hmac = self.crypto.hmac_index(email);
```

**Domain extraction without normalization (pre-fix pattern, `db/audit.rs`)**
```rust
// VIOLATION: domain retains IdP casing; org domains are stored lowercase,
// so email_domain filter returns no results
fn extract_domain(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, domain)| domain.to_string())
}
```

**Upsert helpers without normalization (pre-fix pattern, `db/users.rs`)**
```rust
// VIOLATION: test-utils path stores mixed-case email, breaking uniqueness
pub async fn upsert_user(store: &DocumentStore, email: &str, ...) {
    if let Some(doc) = store.find_one::<UserDoc>("email", email).await? {
        return Ok((doc.id, false));
    }
    let user_doc = UserDoc { email: email.to_string(), ... };
    ...
}
```

## Correct patterns

**Enrollment — normalize at entry point**
```rust
pub async fn enroll_user_with_org(store: &DocumentStore, email: &str, ...) {
    let email = email.to_ascii_lowercase();
    let email = email.as_str();
    // All subsequent uses of `email` are already lowercase
    let existing_user = tx.find_one::<UserDoc>("email", email).await?;
    let doc = UserDoc { email: email.to_string(), ... };
}
```

**SCIM create — normalize before duplicate check and insert**
```rust
pub async fn create_scim_user(store: &DocumentStore, email: &str, ...) {
    let email = email.to_ascii_lowercase();
    let email = email.as_str();
    if tx.find_one::<UserDoc>("email", email).await?.is_some() {
        bail!("UNIQUE constraint failed: ...");
    }
    let doc = UserDoc { email: email.to_string(), ... };
    tx.insert_with_id(&deterministic_user_id(email), &doc).await?;
}
```

**SCIM eq-filter — lowercase filter value, preserve externalId casing**
```rust
if f.op == ScimFilterOp::Eq {
    let email_lower = f.value.to_ascii_lowercase();
    let docs = store
        .find_by_indexes::<UserDoc>(&[("email", &email_lower), ("org_id", org_id)])
        .await?;
}
// externalId: caseExact true — do NOT lowercase
if f.op == ScimFilterOp::Eq {
    let docs = store
        .find_by_indexes::<UserDoc>(&[("external_id", &f.value), ("org_id", org_id)])
        .await?;
}
```

**Audit HMAC — normalize before hashing (both insert and query)**
```rust
// Insert
let email_hmac = email.map(|e| self.crypto.hmac_index(&e.to_lowercase()));

// Query
let hmac = self.crypto.hmac_index(&email.to_lowercase());
```

**Domain extraction — normalize domain portion**
```rust
fn extract_domain(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
}
```

**Deterministic user ID — normalize inside derivation**
```rust
pub(crate) fn deterministic_user_id(email: &str) -> String {
    let email = email.to_ascii_lowercase(); // defense-in-depth
    // ... SHA-256 derivation over normalized email ...
}
```

## Scope

All files in `crates/vouch-server/src/db/` and `crates/vouch-server/src/handlers/` are in scope, with particular attention to:

- `crates/vouch-server/src/db/enrollment.rs` — OIDC/SAML enrollment path
- `crates/vouch-server/src/db/scim.rs` — SCIM create, update, and filter paths
- `crates/vouch-server/src/db/users.rs` — `upsert_user`, `upsert_user_with_org`, `get_user_by_email`
- `crates/vouch-server/src/db/audit.rs` — `insert_event`, `query_events`, `extract_domain`
- `crates/vouch-server/src/db/documents/user.rs` — `deterministic_user_id`
- `crates/vouch-server/src/handlers/scim/users.rs` — SCIM HTTP handler (email extraction before passing to db layer)
- `crates/vouch-server/src/services/idp/oidc.rs` and `saml/response.rs` — IdP identity extraction (domain normalization already present; watch for email field itself)

Files outside `crates/vouch-server/` and pure test files (`db/tests.rs`, handler `#[cfg(test)]` modules) are lower priority but should still use normalized values in fixtures that seed the database.
