# GitHub Identity-Credential Pair Consistency

Detect code paths that can leave a user document with a mismatched `github_id`/`github_login` and `github_refresh_token`, either by rotating a credential without checking the stored identity, or by writing a new identity without clearing the paired credential when the account changed.

## What to look for

Two directions can break the invariant that `github_id`, `github_login`, and `github_refresh_token` in a `UserDoc` all belong to the same GitHub account:

**Direction 1 — Credential rotation path (`update_user_github_refresh_token`):**

The rotation path reads a refresh token, performs a network round-trip (`refresh_oauth_token`), and then writes the rotated token back. A concurrent re-link can commit during that window, so:

1. `github_id` and `github_refresh_token` must be read from a **single doc snapshot** (one `store.get` call returning a `GitHubLink`). Reading them in separate queries — e.g., one call to `get_user_github_refresh_token` and a separate call or field access to get `github_id` — lets a re-link land between the reads, defeating the identity guard.

2. The write-back inside `store.transition` (or `store.modify`) must **condition the write on `data.github_id == expected_github_id`**. An unconditional `data.github_refresh_token = Some(...)` clobbers the new account's token whenever a re-link committed during the network round-trip.

3. When the identity check fails, the path must return `RefreshOutcome::SkippedIdentityChanged` (not an error) and the caller must **not** surface the rotated token.

**Direction 2 — Identity update path (`update_user_github_identity`):**

The re-link path receives a `github_refresh_token: Option<&str>` — `None` when GitHub omits the field (expiring tokens disabled). The invariant requires:

1. The `same_account` comparison (`data.github_id == Some(github_id)`) must happen **inside the `store.modify` closure**, not outside it. Capturing the old `github_id` before calling `store.modify` and comparing against a captured value is wrong under OCC because the closure reruns against the newest doc on every retry.

2. Token handling must follow the three-way logic:
   - `Some(token)` supplied → always write the new token.
   - `None` supplied **and** `same_account` → keep the stored token (same-account re-link with expiring tokens disabled).
   - `None` supplied **and** `!same_account` → **clear** the stored token (`data.github_refresh_token = None`). Keeping a stored token here leaves the doc with the new identity and the old account's credential.

## Violation examples

**Rotation — unconditional overwrite (introduced in dfd69cf8, fixed in bee88c7a):**

```rust
// WRONG: no identity check — clobbers re-link's refresh token
pub async fn update_user_github_refresh_token(
    store: &DocumentStore,
    user_id: &str,
    new_refresh_token: &str,
) -> Result<()> {
    let found = store
        .modify::<UserDoc, _>(user_id, |data| {
            data.github_refresh_token = Some(secrecy::SecretString::from(new_refresh_token));
        })
        .await?;
    ...
}
```

**Rotation — split-snapshot read (present before bee88c7a):**

```rust
// WRONG: two separate reads let a re-link land between them
let refresh_token = match db::get_user_github_refresh_token(self.store, user_id).await? {
    Some(token) => token,
    None => return Ok(None),
};
// ... network call (race window) ...
db::update_user_github_refresh_token(self.store, user_id, new_refresh_token.expose_secret())
    .await?;
```

**Identity update — missing credential clear on different-account re-link (fixed in bee88c7a):**

```rust
// WRONG: None refresh token silently keeps the old account's credential
pub async fn update_user_github_identity(...) -> Result<()> {
    store.modify::<UserDoc, _>(user_id, |data| {
        data.github_id = Some(github_id);
        data.github_login = Some(github_login.to_string());
        if let Some(token) = github_refresh_token {
            data.github_refresh_token = Some(secrecy::SecretString::from(token));
        }
        // BUG: when github_refresh_token is None AND a different account,
        // data.github_refresh_token is left pointing at the old account's token
    }).await?;
    ...
}
```

**Identity update — `same_account` captured outside the closure:**

```rust
// WRONG: stale capture; re-link that commits on a retry sees the wrong value
let old_id = store.get::<UserDoc>(user_id).await?.map(|d| d.data.github_id);
let same_account = old_id == Some(github_id);
store.modify::<UserDoc, _>(user_id, |data| {
    data.github_id = Some(github_id);
    if let Some(token) = github_refresh_token {
        data.github_refresh_token = Some(secrecy::SecretString::from(token));
    } else if !same_account {  // BUG: stale — not re-evaluated on OCC retry
        data.github_refresh_token = None;
    }
}).await?;
```

## Correct patterns

**Rotation — single-snapshot read + conditional write:**

```rust
// Correct: read id + token together, condition write on stored id
let linked = db::get_user_github_link(store, user_id).await?;
// linked: Option<GitHubLink { github_id, github_refresh_token }>
let expected_github_id = linked.github_id;
// ... network call ...
let outcome = store
    .transition::<UserDoc, RefreshOutcome, RefreshOutcome, _>(user_id, |data| {
        if data.github_id == expected_github_id {
            data.github_refresh_token = Some(secrecy::SecretString::from(new_refresh_token));
            Ok(RefreshOutcome::Written)
        } else {
            Err(RefreshOutcome::SkippedIdentityChanged)
        }
    })
    .await?;
```

**Identity update — `same_account` inside the closure, three-way token logic:**

```rust
// Correct: compare runs against newest doc on every OCC retry
store.modify::<UserDoc, _>(user_id, |data| {
    let same_account = data.github_id == Some(github_id);  // inside closure
    data.github_id = Some(github_id);
    data.github_login = Some(github_login.to_string());
    if let Some(token) = github_refresh_token {
        data.github_refresh_token = Some(secrecy::SecretString::from(token));
    } else if !same_account {
        data.github_refresh_token = None;  // clear old account's credential
    }
    // else: same account, no new token supplied — keep existing token
}).await?;
```

## Scope

Check the following files, which contain or call the identity/credential write paths:

- `crates/vouch-server/src/db/users.rs` — `update_user_github_identity`, `update_user_github_refresh_token`, `get_user_github_link`
- `crates/vouch-server/src/services/integrations/github/oauth.rs` — `get_user_access_token`, `link_user_account`
- Any future file in `crates/vouch-server/src/` that calls `update_user_github_refresh_token` or `update_user_github_identity`
