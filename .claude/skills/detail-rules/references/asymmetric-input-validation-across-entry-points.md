# Asymmetric Input Validation Across Entry Points

Detect cases where a validation rule applied on one entry point (create, register, initial path) is missing, weaker, or incorrect on a paired entry point (update, PUT, PATCH, rename, alternate config source) that writes the same data.

## What to look for

### 1. Create/register enforces checks that update/rename/PUT omits

When a create handler trims, rejects empty, checks non-empty lists, or enforces character limits — look for the matching update handler to confirm it applies the **same** checks to the same fields. Flag any update path that:

- Persists a `name`, `display_name`, or label without calling `ResourceLabel::parse` (or equivalent trim + non-empty + `chars().count()` guard).
- Accepts `redirect_uris: []` for a non-service OAuth client when create rejects it with `MissingRedirectUris`.
- Accepts a field value (e.g. `access_scope`, `fapi_profile`, `client_name`) via `and_then(|s| s.parse().ok()).unwrap_or_default()` silently falling back to default instead of returning an error.

Key example pattern (validate.rs): `validate_create_application` checks `input.redirect_uris.is_empty()` for non-service apps and errors; the paired `validate_update_format` did not — bug fixed by adding the check inside `validate_update_fapi`.

### 2. Shared validator called with fewer checks on one path

When a `validate_*` function or a closure has multiple mandatory checks — look for any call site that skips a check by:

- Passing `None` instead of the required option, silently disabling a branch.
- Using an older call signature that predates a new parameter.
- Calling a sub-validator but not the full top-level one.

Key example: `validate_prompt` logic was correct in the plain PAR path but the JAR path called `Prompt::parse(p)` without the rejection branch, so unsupported values silently became `None`.

### 3. User-supplied values persisted without the full sanitization chain

Flag any handler that stores a user-provided `String` field directly into the DB (via `db::create_*` or `db::update_*`) without first:

- Trimming whitespace (`.trim()`)
- Rejecting empty/whitespace-only (`.is_empty()` check after trim)
- Enforcing a length bound in **characters** (`.chars().count()`, not `.len()`)
- Rejecting NUL bytes (`\x00`) when the field is used as a DB index value

Look for `req.name`, `req.description`, or similar raw fields threaded directly into persistence params. The correct pattern is `ResourceLabel::parse(&req.name)?`.

### 4. Byte-based length checks with character-limit error messages

Flag any length check of the form:
```rust
if name.len() > N {
    return Err(... "must be between 1 and N characters" ...)
}
```
`str::len()` returns **bytes**, not characters. The correct pattern uses `chars().count()`. A 100-character CJK string is 300 bytes and must pass a 100-char limit. Key handlers affected: `handlers/keys.rs` (rename), policy name, SCIM token description.

### 5. Config values from alternate sources bypassing validation

When one config path (env vars, CLI flags) calls a validator (e.g. `validate_provider_slug`), check that alternate config paths (S3, bootstrap overlay, IMDS-merged values) call the same validator or are funneled through a shared validation step. Also flag empty-string values from env that silently override a fallback chain:

```rust
std::env::var("AWS_REGION").ok()   // Ok("") becomes Some("") and blocks IMDS fallback
```
Should be:
```rust
std::env::var("AWS_REGION").ok().filter(|v| !v.is_empty())
```

### 6. `map_or` / `unwrap_or_default` swallowing parse errors on invalid enum values

Flag patterns where an optional enum field from the request is parsed with `.ok()` and defaulted:
```rust
req.access_scope.as_ref().and_then(|s| s.parse().ok()).unwrap_or_default()
```
If the user supplies an unrecognized value (e.g., typo `"organizaton"`), this silently applies the default. It should instead return a `400 invalid_access_scope` error.

## Violation examples

**Create validates, update does not (redirect_uris)**
```rust
// CREATE — correctly rejects empty list for non-service apps
if !matches!(app_type, OAuthClientType::Service) && input.redirect_uris.is_empty() {
    return Err(AppValidationError::MissingRedirectUris);
}

// UPDATE (buggy) — only format-validates; empty list passes for non-service apps
if let Some(uris) = input.redirect_uris {
    validate_redirect_uris(uris).map_err(AppValidationError::InvalidRedirectUris)?;
    // Missing: is_empty() guard for non-service apps
}
```

**Unvalidated name stored directly**
```rust
// register_start (buggy): no trim, no empty check, no length check
let reg_state = RegistrationState {
    device_name: req.name,  // persisted verbatim
    ...
};
```

**Byte-based length check reported as character limit**
```rust
// handlers/keys.rs (buggy)
let name = req.name.trim();
if name.is_empty() || name.len() > 256 {  // .len() = bytes, not chars
    return Err(ServiceError::api(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        "Key name must be between 1 and 256 characters",  // misleading
    ));
}
```

**Silent enum fallback on update**
```rust
// api.rs (buggy): update path; parse errors become None, then unwrap_or_default
let access_scope = req
    .access_scope
    .as_ref()
    .and_then(|s| s.parse::<AccessScope>().ok())  // swallows invalid values
    .unwrap_or_default();
```

**S3 config bypasses slug validation**
```rust
// s3_config.rs (buggy): into_idp_config uses `id` directly
IdpConfig::Oidc(OidcProviderConfig {
    id,  // no validate_provider_slug() call; env-var path validates, S3 path does not
    ...
})
```

**JAR path omits prompt rejection that plain PAR enforces**
```rust
// jar.rs (buggy): None returned on unsupported values instead of erroring
let parsed_prompt = match claims.prompt.as_deref() {
    Some(p) => Prompt::parse(p),  // returns None for "select_account"; no rejection
    None => None,
};

// par.rs (correct): same field, same endpoint, but plain path rejects invalid values
let parsed_prompt = match params.prompt.as_deref() {
    Some(p) => match Prompt::parse(p) {
        Some(prompt) => Some(prompt),
        None => return par_error_response(OAuthErrorCode::InvalidRequest, ...),
    },
    None => None,
};
```

**Empty env var overrides fallback chain**
```rust
// config.rs (buggy): Ok("") becomes Some("") and blocks IMDS + SDK default chain
let aws_region = args.aws_region
    .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())  // "" is Some("")
    .or_else(|| instance.map(|b| b.region.clone()));
```

## Correct patterns

**Use `ResourceLabel::parse` for all user-assigned display labels**
```rust
// register_start, rename_key, create/update policy — correct pattern:
let name = ResourceLabel::parse(&req.name).map_err(|e| match e {
    ResourceLabelError::Empty => ServiceError::api(StatusCode::BAD_REQUEST, "invalid_name",
        "Key name must be between 1 and 100 characters"),
    ResourceLabelError::TooLong => ServiceError::api(StatusCode::BAD_REQUEST, "invalid_name",
        "Key name must be between 1 and 100 characters"),
})?;
```

**Validate enum fields explicitly; reject unknowns**
```rust
// create and update — correct:
let access_scope = match input.access_scope {
    None => AccessScope::default(),
    Some(s) => s.parse::<AccessScope>()
        .map_err(|_| AppValidationError::InvalidAccessScope)?,
};
```

**Use `chars().count()` for character limits**
```rust
if trimmed.chars().count() > ResourceLabel::MAX_CHARS {
    return Err(ResourceLabelError::TooLong);
}
```

**Filter empty strings from env/config before they enter the option chain**
```rust
std::env::var("AWS_DEFAULT_REGION").ok().filter(|v| !v.is_empty())
```

**Validate all config sources at a shared post-merge step**
```rust
// config.rs — validate() called after all sources (env, S3) have been merged:
for idp in &self.idps {
    validate_provider_slug(idp.id())?;  // catches S3-sourced slugs too
}
```

**One shared validator for equivalent paths (PAR plain vs. JAR)**
Move parameter parsing out of each handler into a shared `validate_authorize_request` function, so plain form body, pushed request, and JAR all reach the same parse-and-reject logic.

## Scope

All files in these directories are in scope:

- `crates/vouch-server/src/handlers/` — HTTP handlers for create, update, rename, register endpoints
- `crates/vouch-server/src/handlers/applications/` — OAuth app create/update validation
- `crates/vouch-server/src/handlers/keys.rs` — key register, rename
- `crates/vouch-server/src/handlers/scim/` — SCIM user/group create and PATCH
- `crates/vouch-server/src/handlers/oidc/` — PAR, JAR, dynamic client registration PUT
- `crates/vouch-server/src/services/oidc/registration.rs` — RFC 7592 PUT
- `crates/vouch-server/src/infra/s3_config.rs` — S3-sourced config merge
- `crates/vouch-server/src/config.rs` — env var config parsing and post-merge validation
- `crates/vouch-server/src/lib.rs` — AWS config resolution
- `crates/vouch-cli/src/commands/` — CLI setup, credential, and register commands
- `crates/vouch-common/src/` — shared validation types (`ResourceLabel`, `MAX_KEY_NAME_CHARS`)

Not in scope: test files (`tests.rs`, `*_test.rs`), migration scripts, documentation.
