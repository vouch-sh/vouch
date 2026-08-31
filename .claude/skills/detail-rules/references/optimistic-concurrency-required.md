# Optimistic Concurrency Required for Shared-Document Mutations

Concurrent mutation of the same document, or enforcement of a cross-row invariant, must use optimistic concurrency (`store.modify` / `compare_and_update` with a version bump and a bounded retry via `with_dsql_retry!`), never a blind `store.get()`-then-`store.update()` or a check-then-write TOCTOU pattern.

## What to look for

### 1. Blind get-then-update (lost-update race)

A call to `store.get::<T>()` or `find_one::<T>()` followed by `store.update()` on the same document ID, outside a `store.modify` closure, in any path reachable from concurrent HTTP requests, webhooks, or background tasks.

The blind write clobbers every field the concurrent writer changed, silently discarding the other update. Security-sensitive fields — `is_org_admin`, `active`, signature `counter` — are the highest-risk targets.

**Pattern to flag:**
```rust
let doc = store.get::<FooDoc>(id).await?;  // READ (version captured but ignored)
let mut data = doc.data;
data.some_field = new_value;               // MODIFY
store.update(id, &data).await?;            // BLIND WRITE — loses concurrent changes
```

### 2. Count-cap / floor / uniqueness guards outside a version-bumped transaction

Any read-then-insert or count-then-insert pattern where the counted document type and the inserted document live on different rows and no shared row is version-bumped inside the same transaction:

- SCIM token count cap (`MAX_SCIM_TOKENS = 2`) checked outside the insert transaction
- OAuth secret cap (≤ `MAX_ACTIVE_SECRETS`) or floor (≥ 1) checked before `store.insert()`
- Authenticator count-before-delete check (`count_before <= 1`) performed without serializing on the user doc's version
- Organization admin uniqueness — "first enrollee wins admin" — without a `compare_and_update` on the org row
- Domain ownership uniqueness (additional domain verification) without a shared claim slot
- SCIM group membership duplicate check (`find_by_indexes` then `insert`) outside a single transaction
- JTI replay protection via `find_by_indexes` then `insert` instead of a deterministic document ID

The fix pattern is to **version-bump a shared serialization-point document** (e.g., the `OrganizationDoc` for org-scoped invariants, the `UserDoc` for per-user invariants) inside the same transaction, so concurrent writers collide on the CAS and the loser re-reads and re-checks.

### 3. Derived value computed outside the `modify` closure

A value derived from the document's current state (e.g., the merged repository list, the applied-flag `AtomicBool`, a successor user ID) must be re-computed inside the `store.modify` closure. If it is computed before calling `modify`, an OCC retry re-runs the closure with stale input, producing wrong output.

**Pattern to flag:**
```rust
let merged = compute_delta(&current_repos, added, removed);  // OUTSIDE closure — stale on retry
store.modify::<Doc, _>(&id, |data| {
    data.repositories = Some(merged.clone());  // BUG: merged is stale if CAS races
}).await?;
```

### 4. Unchecked `Ok(false)` / `Ok(None)` from OCC operations in callers

When `store.modify`, `compare_and_update`, or a higher-level function that wraps them returns `Ok(false)` / `Ok(None)` to signal "document not found" or "OCC conflict not won", callers that silently discard the signal (e.g., `if let Err(e) = ...`) will treat a failed update as a success and log spurious audit events, redirect the user to a success page, or skip required error handling.

### 5. Cross-row invariant enforced only by a pre-flight read (not by a shared write)

Under PostgreSQL READ COMMITTED, two concurrent transactions can each observe a predicate result that the other's uncommitted write would change. A count, find-by-index, or membership check does not create a write-write conflict. The only reliable serialization point is a `compare_and_update` on a row both writers must update.

## Violation examples

**Blind get-then-update (authenticator name / GitHub fields):**
```rust
// update_authenticator_name — before fix (commit c63387dd)
if let Some(doc) = store.get::<AuthenticatorDoc>(authenticator_id).await? {
    let mut data = doc.data;
    data.name = name.to_string();
    store.update(authenticator_id, &data).await?;  // clobbers concurrent counter update
    Ok(true)
} else {
    Ok(false)
}
```

**Count-then-insert TOCTOU (SCIM token cap — before fix):**
```rust
let active = db::count_active_scim_tokens(&state.store, &org_id).await?;  // separate tx
if active >= MAX_SCIM_TOKENS {
    return Err(...);
}
let token_id = db::create_scim_token(&state.store, ...).await?;  // another tx — race window
```

**Count-then-delete TOCTOU (last-key floor — before fix):**
```rust
let key_count = db::count_authenticators_for_user(store, user_id).await?;
if key_count <= 1 {
    return Err(ServiceError::api(400, "last_key", "..."));
}
// No tx boundary or version bump — two concurrent deletes can both pass the check
db::delete_authenticator(store, key_id).await?;
```

**JTI replay via check-then-insert (JWT bearer — before fix):**
```rust
let existing = store
    .find_by_indexes::<JwtAssertionJtiDoc>(&[("jti", jti), ("client_id", client_id)])
    .await?;
if !existing.is_empty() { return Ok(false); }
store.insert(&doc).await?;  // no UNIQUE constraint on (jti, client_id) — both inserts succeed
```

**Delta computed outside modify closure (GitHub repos — before fix, commit 5dfdf31e):**
```rust
// delta read before entering the modify closure
let merged = compute_merged(&current_repos, added, removed);
store.modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
    data.repositories = Some(merged.clone());  // stale if OCC retried
}).await?;
```

**Stale applied-flag not reset between OCC retries (commit c63387dd):**
```rust
// AtomicBool set inside closure on first attempt, never reset at top of closure
let applied = AtomicBool::new(false);
store.modify::<FooDoc, _>(id, |data| {
    if data.org_id != expected_org { return; }  // bails without setting applied
    applied.store(true, Ordering::Release);
    data.field = new_value;
}).await?;
// If first attempt set applied=true then lost the CAS, and second attempt bails
// (org changed), applied stays true — caller reports success for a no-op.
```

**Ignoring Ok(false) / Ok(None) from OCC (policies handler — before fix):**
```rust
db::update_custom_policy(&state.store, &id, &org_id, params)
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to toggle policy: {e}")))?;
// Ok(None) silently discarded — audit event logged for a policy that wasn't toggled
```

## Correct patterns

**Use `store.modify` for single-document field mutations:**
```rust
// update_authenticator_counter — correct
store
    .modify::<AuthenticatorDoc, _>(authenticator_id, |data| {
        data.counter = std::cmp::max(data.counter, counter);  // max, not assignment
    })
    .await?;

// update_user_admin_status — correct
store
    .modify::<UserDoc, _>(user_id, |data| {
        data.is_org_admin = is_admin;
    })
    .await
```

**Version-bump a shared row for cross-row cap/floor invariants:**
```rust
// create_scim_token — correct (scim.rs)
crate::with_dsql_retry!(async {
    let mut tx = store.begin().await?;
    let org_doc = tx.get::<OrganizationDoc>(&org_id).await?.ok_or(...)?;
    let active = tx.find_all::<ScimTokenDoc>("org_id", &org_id).await?
        .iter().filter(|d| !d.is_expired()).count();
    if active >= MAX_SCIM_TOKENS { return Err(terminal_error); }
    tx.insert(&doc).await?;
    // Bump org version — concurrent creator that committed changes this version,
    // so compare_and_update returns Ok(false) and the block re-runs.
    if !tx.compare_and_update::<OrganizationDoc>(&org_id, org_doc.version, &org_doc.data).await? {
        return Err(ServiceError::OccConflict);
    }
    tx.commit().await?;
    Ok(inserted_id)
})
```

**Compute derived values inside the closure:**
```rust
// update_github_installation_repos_delta — correct
store.modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
    let repos = data.repositories.get_or_insert_default();
    for repo in &added_owned { if !repos.contains(repo) { repos.push(repo.clone()); } }
    repos.retain(|r| !removed_owned.contains(r));
    repos.sort();
}).await?;
```

**Use deterministic document ID for insert-once uniqueness:**
```rust
// enrollment org creation — correct
fn deterministic_org_id(domain: &str) -> String { /* SHA-256 of domain */ }
// Concurrent inserts collide on the primary key; the loser gets a unique-violation
// and re-fetches rather than inserting a duplicate.
```

**Check and handle `Ok(false)` / `Ok(None)` from OCC functions:**
```rust
// toggle_custom_policy — correct
let updated = db::update_custom_policy(&state.store, &id, &org_id, params)
    .await
    .map_err(|e| ServiceError::Internal(format!("{e}")))?;
if updated.is_none() {
    return Err(ServiceError::NotFound("Policy"));
}
// Only log audit event after confirming the update happened.
```

**Reset applied-flag at the top of the modify closure:**
```rust
let applied = AtomicBool::new(false);
store.modify::<FooDoc, _>(id, |data| {
    applied.store(false, Ordering::Release);  // reset first on every retry
    if data.org_id != expected_org { return; }
    applied.store(true, Ordering::Release);
    data.field = new_value;
}).await?;
```

## Scope

All files in:
- `crates/vouch-server/src/db/` — document-layer mutation functions
- `crates/vouch-server/src/services/` — business-logic services (keys, enrollment, OIDC grants, GitHub integrations)
- `crates/vouch-server/src/handlers/` — HTTP request handlers that call db functions directly or enforce counts

Exclude `#[cfg(test)]` blocks and files under `src/db/tests/`, `src/db/store/tests.rs`, and files whose only `store.update` calls are inside `test_helpers` modules — these are intentional fault-injection fixtures.
