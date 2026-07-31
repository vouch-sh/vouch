# Use store.modify for Concurrent Document Updates

Detect blind read-modify-write sequences that call `store.get()` + `store.update()` on documents that can be concurrently mutated, instead of the required `store.modify()` optimistic-concurrency primitive, which causes lost-update races where concurrent writers silently overwrite each other's changes.

## What to look for

Any code in `crates/vouch-server/src/db/` that follows this shape is a violation:

```
let doc = store.get::<SomeDoc>(id).await?;
// ... mutate doc.data fields ...
store.update(id, &data).await?;
```

This pattern is a blind read-modify-write: the `get` reads a snapshot, the caller mutates it, and `update` unconditionally overwrites the whole document — no version check. A concurrent writer that commits between `get` and `update` will have its changes silently discarded by the overwrite.

**Specific conditions that constitute a violation:**

1. **`store.get()` + `store.update()` on the same document ID within the same function**, where the function is reachable from a concurrent request handler, webhook, or background task. Look for:
   - `store.get::<T>(id).await?` followed later by `store.update(id, &data).await?`
   - `if let Some(doc) = store.get::<T>(id).await? { ... store.update(id, &doc.data) ... }`

2. **Read-compute-write where computation happens outside `store.modify`**: if a merge, delta application, or derived value is computed from a `get` result and then written back, that computation is stale the moment a concurrent writer modifies the document. The computation must be inside the `store.modify` closure so it re-runs on each OCC retry with fresh data.

3. **`find_one` + `store.update` on the same document**: using `store.find_one` to resolve a document then calling `store.update` on it has the same race as `get` + `update`.

4. **`AtomicBool` success flag not reset at the top of a `store.modify` closure**: each OCC retry re-invokes the closure; if a prior attempt set the flag and then lost the version race, the flag stays set and a subsequent retry that bails early (e.g., org-scope check fails) reports success instead of skipping.

5. **State check using stale snapshot data inside the closure**: a candidate set built from a paginated snapshot before `store.modify`, then applied inside the closure (e.g., via `retain()`) without re-checking whether entries have since transitioned state (e.g., `Pending → Verified`). The membership test runs against fresh data, but the decision was made against stale data.

**What is safe (not a violation):**

- `store.get()` used purely to read a document for the caller to return/display (no write follows).
- `store.get()` as a pre-check before entering `store.modify`, where the `modify` closure re-checks the relevant condition — this is acceptable for fast-fail before the OCC loop.
- `store.get()` after `store.modify` to re-fetch updated timestamps (read-after-write, not a race).
- `store.update()` inside test helper functions under `#[cfg(test)]` or `mod test_helpers` — these are test scaffolding, not production paths.
- `store.update_by_index()` — this is a bulk updater with internal batching, not a single document read-modify-write.
- `compare_and_update()` called with a freshly-read version — this is the OCC mechanism itself.
- `store.update_last_used_at()` — updates only a metadata timestamp, no semantic fields.
- `tx.update()` — writes inside an explicit `StoreTransaction`; atomicity is handled by the transaction.
- Documents that are never mutated concurrently (e.g., write-once records like `DpopJtiDoc`). Use judgment; prefer `store.modify()` when in doubt.
- `set_preconfigured_active` (posture_policies.rs): uses a full-replace pattern with caller-controlled `active_slugs`; the caller is authoritative for the entire field.

**Document types at highest risk** (all have concurrent writers):
- `UserDoc` — admin status and active flag mutated by org admin + SCIM
- `AuthenticatorDoc` — counter updated by parallel WebAuthn verifications; name updated by admin
- `GitHubInstallationDoc` — suspend/unsuspend/repo-list updated by concurrent webhooks
- `ScimGroupDoc` — display name, external ID mutated by SCIM API
- `CustomPosturePolicyDoc` — name, CEL expression, active flag mutated by org admin
- `OrganizationDoc` — additional domains, signing keys updated by admin + recheck task
- `OAuthClientDoc` — registration metadata, active flag updated by concurrent API clients

## Violation examples

**Blind field update (admin status, pre-#537 fix)**

```rust
// update_user_admin_status — BEFORE fix (fd75771)
if let Some(doc) = store.get::<UserDoc>(user_id).await? {
    let mut data = doc.data;
    data.is_org_admin = is_admin;
    store.update(user_id, &data).await?;
    Ok(true)
} else {
    Ok(false)
}
```

**Counter regressing under concurrency (WebAuthn, pre-#545 fix)**

```rust
// update_authenticator_counter — BEFORE fix (fd75771)
if let Some(doc) = store.get::<AuthenticatorDoc>(authenticator_id).await? {
    let mut data = doc.data;
    data.counter = counter;   // always overwrites; never takes max()
    store.update(authenticator_id, &data).await?;
}
```

**Webhook field update (GitHub installation suspend, pre-#551 fix)**

```rust
// suspend_github_installation — BEFORE fix (c63387d)
let doc = store
    .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
    .await?;
if let Some(doc) = doc {
    let mut data = doc.data;
    data.suspended_at = Some(Timestamp::now());
    store.update(&doc.id, &data).await?;
    return Ok(true);
}
```

**Org-scoped update without OCC (SCIM group, pre-#551 fix)**

```rust
// update_scim_group — BEFORE fix (c63387d)
let Some(doc) = store.get::<ScimGroupDoc>(id).await? else { return Ok(false); };
if doc.data.org_id != org_id { return Ok(false); }
let mut data = doc.data;
if let Some(name) = display_name { data.display_name = name.to_string(); }
store.update(id, &data).await?;
Ok(true)
```

**Delta merge outside modify closure (GitHub repo delta, pre-#655 fix)**

```rust
// update_github_installation_repos_delta — BEFORE fix (5dfdf31)
// Read + delta computation happen OUTSIDE modify, so two concurrent
// webhook calls each see a stale repo list.
let installation = get_github_installation_by_installation_id(store, installation_id).await?;
let Some(installation) = installation else { return Ok(false); };
let mut repos = installation.repositories.unwrap_or_default();
for repo in added { if !repos.contains(repo) { repos.push(repo.clone()); } }
repos.retain(|r| !removed.contains(r));
update_github_installation_repos(store, installation_id, &repos).await
```

**AtomicBool not reset between OCC retries (scim.rs / posture_policies.rs, fixed in c63387d)**

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

**State check using snapshot data inside modify closure (organizations.rs, fixed in d9fccba)**

```rust
// VIOLATION: domains_to_drop was built from a paginated snapshot; by the time
// the modify closure runs, an entry may have flipped Pending → Verified and
// must be preserved, but the code blindly removes based on the stale snapshot
// name set without re-checking current state
let domains_to_drop: HashSet<String> = to_remove.iter().map(|(d, _)| d.clone()).collect();
store.modify::<OrganizationDoc, _>(&org.id, |doc| {
    doc.additional_domains
        .retain(|ad| !domains_to_drop.contains(&ad.domain));  // never re-checks state
})
```

## Correct patterns

**Use `store.modify` — only touch the target fields**

```rust
store
    .modify::<UserDoc, _>(user_id, |data| {
        data.is_org_admin = is_admin;
    })
    .await
```

**Use `store.modify` with a monotonic merge for counters**

```rust
store
    .modify::<AuthenticatorDoc, _>(authenticator_id, |data| {
        data.counter = std::cmp::max(data.counter, counter);
    })
    .await?;
```

**Move delta computation inside the closure so it re-reads on each retry**

```rust
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

**Pre-check before modify is acceptable; re-check invariants inside the closure**

```rust
// Fast-fail before the OCC loop
let Some(doc) = store.get::<ScimGroupDoc>(id).await? else { return Ok(false); };
if doc.data.org_id != org_id { return Ok(false); }

let applied = std::sync::atomic::AtomicBool::new(false);
let found = store
    .modify::<ScimGroupDoc, _>(id, |data| {
        // Reset flag on every retry attempt
        applied.store(false, std::sync::atomic::Ordering::Relaxed);
        // Re-check org inside the closure — the owning org might have changed
        if data.org_id != org_id { return; }
        if let Some(ref name) = display_name_owned { data.display_name = name.clone(); }
        applied.store(true, std::sync::atomic::Ordering::Relaxed);
    })
    .await?;
Ok(found && applied.load(std::sync::atomic::Ordering::Relaxed))
```

**Re-check live state inside the modify closure**

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

**In scope** — all production database functions in:
- `crates/vouch-server/src/db/*.rs` (users.rs, authenticators.rs, github.rs, scim.rs, posture_policies.rs, oauth.rs, organizations/mod.rs, organizations/domains.rs, organizations/issuer.rs, enrollment.rs, device_auth.rs, credentials.rs)
- `crates/vouch-server/src/services/*.rs` and `crates/vouch-server/src/handlers/` if they call `store.get` + `store.update` directly

**Out of scope:**
- `crates/vouch-server/src/db/store.rs` itself (the implementation)
- `crates/vouch-server/src/db/tests.rs` and any `mod tests` / `mod test_helpers` blocks — `store.update` in test scaffolding is intentional
- `crates/vouch-server/src/db/organizations/domains.rs` test helper functions that use `store.update` to set up test state
- Pure reads: `store.get` with no subsequent `store.update` on the same document
