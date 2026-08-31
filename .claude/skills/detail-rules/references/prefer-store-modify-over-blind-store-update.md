# Prefer store.modify Over Blind store.update

Detect blind read-modify-write patterns where `store.get()` + `store.update()` is used instead of `store.modify()` for documents that can be concurrently mutated, causing lost-update races that silently clobber concurrent writes.

## What to look for

Any non-test async function in `crates/vouch-server/src/db/` that:

1. **Calls `store.get::<T>(id)` (or `store.find_one`)**, captures the returned document, mutates one or more fields of `doc.data`, then calls **`store.update(id, &data)`** — without going through `store.modify()`. This is the canonical blind read-modify-write.

2. **Computes derived state outside a `store.modify` closure** and then writes it back. Examples:
   - A delta merge (add/remove items from a `Vec` field) done before calling `update_github_installation_repos`, so two concurrent callers each read a stale list and lose the other's changes.
   - A candidate removal set built from a paginated snapshot, then applied inside a `retain()` without re-checking whether entries have since transitioned state (e.g., `Pending → Verified`).

3. **Uses `AtomicBool` to signal success from a `store.modify` closure but does not reset it at the top of the closure body.** Each OCC retry re-invokes the closure; if a prior attempt set the flag and then lost the version race, the flag stays set and a subsequent retry that bails early (e.g., org-scope check fails) reports success instead of skipping.

The rule does **not** apply to:
- `store.update_last_used_at()` — updates only a metadata timestamp, no semantic fields.
- `store.update_by_index()` — bulk index-targeted writes with their own semantics.
- `tx.update()` — writes inside an explicit `StoreTransaction`; atomicity is handled by the transaction.
- `#[cfg(test)]` blocks — test helpers may use blind writes to set up fixture state.
- Documents that are never mutated concurrently (e.g., write-once records like `DpopJtiDoc`). Use judgment; prefer `store.modify()` when in doubt.
- `set_preconfigured_active` (posture_policies.rs): uses a full-replace pattern with caller-controlled `active_slugs`; the caller is authoritative for the entire field.

## Violation examples

**Pattern 1 — Direct field update (users.rs, fixed in fd75771)**

```rust
// VIOLATION: blind get + update; a concurrent admin-status change is lost
pub async fn update_user_admin_status(
    store: &DocumentStore,
    user_id: &str,
    is_admin: bool,
) -> Result<bool> {
    if let Some(doc) = store.get::<UserDoc>(user_id).await? {
        let mut data = doc.data;
        data.is_org_admin = is_admin;
        store.update(user_id, &data).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
```

**Pattern 2 — Counter regression (authenticators.rs, fixed in fd75771)**

```rust
// VIOLATION: two concurrent counter updates can regress the WebAuthn counter
pub async fn update_authenticator_counter(
    store: &DocumentStore,
    authenticator_id: &str,
    counter: i32,
) -> Result<()> {
    if let Some(doc) = store.get::<AuthenticatorDoc>(authenticator_id).await? {
        let mut data = doc.data;
        data.counter = counter;   // overwrites; does not take max()
        store.update(authenticator_id, &data).await?;
    }
    Ok(())
}
```

**Pattern 3 — find_one + update on webhook events (github.rs, fixed in c63387d)**

```rust
// VIOLATION: two concurrent suspend/unsuspend webhooks can clobber each other
pub async fn suspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;
    if let Some(doc) = doc {
        let mut data = doc.data;
        data.suspended_at = Some(Timestamp::now());
        store.update(&doc.id, &data).await?;
        return Ok(true);
    }
    Ok(false)
}
```

**Pattern 4 — Delta merge outside the modify closure (github.rs, fixed in 5dfdf31)**

```rust
// VIOLATION: merge runs before store.modify, so two concurrent delta webhooks
// each read a stale repo list and lose each other's additions/removals
pub async fn update_github_installation_repos_delta(...) -> Result<bool> {
    let installation = get_github_installation_by_installation_id(store, installation_id).await?;
    let Some(installation) = installation else { return Ok(false); };

    let mut repos: Vec<String> = installation.repositories.unwrap_or_default();
    for repo in added { if !repos.contains(repo) { repos.push(repo.clone()); } }
    repos.retain(|r| !removed.contains(r));
    repos.sort();

    // update_github_installation_repos calls store.modify, but the merge
    // already happened on stale data — the modify window does not re-merge
    update_github_installation_repos(store, installation_id, &repos).await
}
```

**Pattern 5 — AtomicBool not reset between OCC retries (scim.rs / posture_policies.rs, fixed in c63387d)**

```rust
// VIOLATION: applied flag not reset at top of closure; if attempt N sets it
// then loses the version race, attempt N+1 that bails early still reports success
let applied = std::sync::atomic::AtomicBool::new(false);
let found = store
    .modify::<UserDoc, _>(user_id, |data| {
        // BUG: missing `applied.store(false, ...)` reset here
        if data.org_id.as_deref() == Some(org_id) {
            data.name = name.map(String::from);
            applied.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    })
    .await?;
```

**Pattern 6 — State check using snapshot data inside modify closure (organizations.rs, fixed in d9fccba)**

```rust
// VIOLATION: domains_to_drop was built from a paginated snapshot; by the time
// the modify closure runs, an entry may have flipped Pending → Verified and
// must be preserved, but the old code blindly retains/removes based on the
// stale snapshot name set without re-checking current state
let domains_to_drop: HashSet<String> = to_remove.iter().map(|(d, _)| d.clone()).collect();
store.modify::<OrganizationDoc, _>(&org.id, |doc| {
    doc.additional_domains
        .retain(|ad| !domains_to_drop.contains(&ad.domain));  // never re-checks state
})
```

## Correct patterns

**Pattern 1 fix — `store.modify` for single-field updates**

```rust
pub async fn update_user_admin_status(
    store: &DocumentStore,
    user_id: &str,
    is_admin: bool,
) -> Result<bool> {
    store
        .modify::<UserDoc, _>(user_id, |data| {
            data.is_org_admin = is_admin;
        })
        .await
}
```

**Pattern 2 fix — monotonic counter via `max()` inside modify**

```rust
store
    .modify::<AuthenticatorDoc, _>(authenticator_id, |data| {
        data.counter = std::cmp::max(data.counter, counter);
    })
    .await?;
```

**Pattern 3 fix — resolve doc ID, then modify**

```rust
let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
    return Ok(false);
};
store
    .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
        data.suspended_at = Some(Timestamp::now());
    })
    .await
```

**Pattern 4 fix — delta merge inside the modify closure**

```rust
let Some(doc_id) = resolve_installation_doc_id(store, installation_id).await? else {
    return Ok(false);
};
let added_owned = added.to_vec();
let removed_owned = removed.to_vec();
store
    .modify::<GitHubInstallationDoc, _>(&doc_id, |data| {
        let repos = data.repositories.get_or_insert_default();
        for repo in &added_owned {
            if !repos.contains(repo) { repos.push(repo.clone()); }
        }
        repos.retain(|r| !removed_owned.contains(r));
        repos.sort();
    })
    .await
```

**Pattern 5 fix — reset AtomicBool at top of every closure invocation**

```rust
let applied = std::sync::atomic::AtomicBool::new(false);
store
    .modify::<UserDoc, _>(user_id, |data| {
        applied.store(false, std::sync::atomic::Ordering::Relaxed); // reset first
        if data.org_id.as_deref() == Some(org_id) {
            data.name = name.map(String::from);
            applied.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    })
    .await?;
```

**Pattern 6 fix — re-check live state inside the modify closure**

```rust
store.modify::<OrganizationDoc, _>(&org.id, |doc| {
    doc.additional_domains.retain(|ad| {
        // Never remove a Verified entry, even if it was Pending in the snapshot
        if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
            return true;
        }
        !drop_candidates.contains_key(&ad.domain)
    });
})
```

## Scope

Check all non-test Rust source files under:

- `crates/vouch-server/src/db/` (including subdirectories such as `organizations/`)
- `crates/vouch-server/src/services/`
- `crates/vouch-server/src/handlers/`

Focus on async functions that interact with a `DocumentStore` (`store: &DocumentStore` or `state.store`). The highest-risk document types — those touched by multiple concurrent request paths — are: `UserDoc`, `AuthenticatorDoc`, `GitHubInstallationDoc`, `ScimGroupDoc`, `CustomPosturePolicyDoc`, `OrganizationDoc`, and `OAuthClientDoc`.

Skip `#[cfg(test)]` modules: test helpers legitimately use blind writes to inject fixture state without racing other writers.
