# Wire Format Compat on Persisted Structs

A required field must not be removed, renamed, or made stricter on a struct that is persisted in the document store (`DocumentType` impl) or carried in a server-minted state JWT (`encode_state_token`/`decode_state_token`), unless the field already has `Option` type or `#[serde(default)]` in the currently deployed release.

## What to look for

### In-scope struct categories

1. **Document store types** — every struct in `crates/vouch-server/src/db/documents/` that implements `DocumentType` (e.g. `ChallengeStateDoc`, `SessionDoc`, `AuthorizationCodeDoc`, `OAuthClientDoc`, `PushedAuthorizationRequestDoc`, `TokenExchangeDoc`).
2. **State JWT payloads** — every struct in `crates/vouch-server/src/handlers/` that is passed to `StateTokenSigner::encode_state_token` / `decode_state_token` (e.g. `RegistrationState`, `BrowserRegistrationState`, `BrowserAuthenticationState`, `GitHubStateToken`, `Fido2ChallengeState`).

Both categories are written by one server instance and decoded by another during rolling deploys or after a rollback. Serde rejects data that is missing a required field or that fails a custom `Deserialize` impl, so any narrowing change to the consumer breaks in-flight data written by the old producer.

### Violation patterns

Flag any of the following when the field does not already carry `Option` or `#[serde(default)]` in the **currently deployed** code (i.e. in the base branch, not the PR under review):

- **Field deleted** — the field is removed from the struct body in one release.
- **Field renamed** — the field name changes without a `#[serde(rename = "old_name")]` alias.
- **Type made stricter** — the field's type changes from a permissive type (e.g. `String`, `i64`) to a type whose `Deserialize` impl rejects previously-valid values (e.g. a newtype whose `Deserialize` calls `parse` and returns an error for empty / whitespace-only / over-length strings).
- **Option removed** — `Option<T>` becomes `T` (required field) in one release.
- **Dead-code removal without two-release expand/contract** — a field no code reads is still a wire-format contract; removing it skips the expand/contract requirement only when `#[serde(default)]` was already in the prior release.

### Safe patterns

- **Adding a new field** — always safe if it carries `#[serde(default)]` or is `Option<T>`, so the old producer's payloads (which lack it) still decode.
- **Two-release expand/contract for removal** — Release 1: add `#[serde(default)]` to the field (old producer still writes it, new decoder accepts its absence). Release 2: stop writing the field and delete it.
- **Two-release expand/contract for type tightening** — Release 1: validate at the write path so no new non-conforming values are minted, but keep the decode type permissive (`String`). Release 2: switch the decode type to the strict newtype.

## Violation examples

### Example 1 — Required field deleted in a single release (dead-code removal)

`ChallengeStateDoc` previously held two required fields that no application code read:

```rust
// BEFORE (deployed):
pub(crate) struct ChallengeStateDoc {
    pub doc_id: String,           // required — no #[serde(default)]
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
}
```

Both were deleted in one commit (commit `f98e2b092`). An old instance writing a `ChallengeStateDoc` row with `doc_id` is still readable by the new code, but a new instance writing a row without `doc_id` is **unreadable** by a rolled-back old instance (serde rejects the missing required field).

```rust
// AFTER — violation:
pub(crate) struct ChallengeStateDoc {
    pub expires_at: Timestamp,    // doc_id and consumed_at deleted outright
}
```

The safe path for `doc_id`: add `#[serde(default)]` in Release 1, delete in Release 2.
`consumed_at` was already `Option<Timestamp>` and could be dropped in one release.

### Example 2 — Field type tightened to a validating newtype in a single release

`RegistrationState` is a server-minted 5-minute JWT decoded by whichever instance handles `register_complete`. Commit `37fcc923` changed `device_name` from `String` to `ResourceLabel`:

```rust
// BEFORE (deployed):
struct RegistrationState {
    device_name: String,   // permissive; accepts any non-empty content
    ...
}
```

```rust
// AFTER — violation:
struct RegistrationState {
    device_name: ResourceLabel,  // Deserialize calls parse(), rejects
                                 // empty / whitespace-only / >100-char values
    ...
}
```

`ResourceLabel`'s `Deserialize` impl runs validation:
```rust
impl<'de> Deserialize<'de> for ResourceLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)  // rejects previously-valid strings
    }
}
```

Old instances that minted tokens with a non-conforming `device_name` produce JWTs that the new instance deterministically rejects with `400 invalid_state` during the rolling deploy overlap.

### Example 3 — Required field deleted that also needed two-release treatment

`RegistrationState.iat` is a required `i64` field that no application code validates. An attempt to delete it in one release (commit `ed48213f`) was blocked and reverted because:

```rust
// Attempted removal — violation:
struct RegistrationState {
    user_id: Uuid,
    device_name: ResourceLabel,
    challenge: Challenge<Raw>,
    rp_id: String,
    // iat: i64  <-- deleted; old tokens still carry it but that is fine;
    //               new tokens lack it, and old decoders reject the absence
    exp: i64,
}
```

The field was restored (kept with `#[serde(default)]` semantics acknowledged in comments) because removing it safely requires two releases.

## Correct patterns

### Adding a new optional field (always safe)

```rust
// SessionDoc: new fields always get #[serde(default)]
pub struct SessionDoc {
    pub user_id: String,
    pub token_hash: String,
    // ... existing required fields ...
    #[serde(default)]
    pub hardware_aaguid: Option<String>,   // safe: old rows decode to None
    #[serde(default)]
    pub org_domain: Option<String>,        // safe: old rows decode to None
    #[serde(default)]
    pub client_id: Option<String>,         // safe: old rows decode to None
}
```

### Adding a new field with a non-Option default (safe when #[serde(default)] is present)

```rust
// OAuthClientDoc: new field that has a Default impl
#[serde(default)]
pub id_token_signed_response_alg: JwsAlgorithm,  // defaults to ES256 for old rows
```

### Removing an already-optional field (safe in one release)

```rust
// consumed_at was Option<Timestamp> in ChallengeStateDoc — safe to drop:
pub(crate) struct ChallengeStateDoc {
    pub expires_at: Timestamp,
    // consumed_at removed: was Option, so old decoders ignore extra JSON key;
    // new payloads without it still decode on old code (field was optional).
}
```

### Two-release expand/contract for a required field removal

Release 1:
```rust
pub struct SomeDoc {
    #[serde(default)]  // add this; now old code can decode rows that lack it
    pub the_field: SomeType,
    // keep writing the_field at all write sites
}
```

Release 2 (after Release 1 is fully deployed and rollback window has passed):
```rust
pub struct SomeDoc {
    // the_field deleted; Release 1 already made old code tolerant of its absence
}
```

## Scope

**Primary targets** (check every file for modifications to existing struct fields):

- `crates/vouch-server/src/db/documents/*.rs` — all `DocumentType` impls
- `crates/vouch-server/src/handlers/keys.rs` — `RegistrationState`
- `crates/vouch-server/src/handlers/enroll.rs` — `BrowserRegistrationState`
- `crates/vouch-server/src/handlers/browser_login.rs` — `BrowserAuthenticationState`
- `crates/vouch-server/src/handlers/github.rs` — `GitHubStateToken`
- `crates/vouch-server/src/handlers/oidc/fido2_challenge.rs` and `crates/vouch-server/src/services/oidc/fido2_grant.rs` — `Fido2ChallengeState`

**Out of scope**: request/response types in `vouch-common`, CLI-only structs, structs that are never serialized to the store or encoded as JWTs.
