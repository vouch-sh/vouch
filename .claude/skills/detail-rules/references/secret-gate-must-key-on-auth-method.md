# Secret Gate Must Key on Auth Method

Every decision about whether a client holds, may mint, may revoke, or may display controls for a `client_secret` must call `TokenEndpointAuthMethod::secret_is_credential(fapi_profile)` — never a hand-rolled equivalent.

## What to look for

`TokenEndpointAuthMethod::secret_is_credential(fapi_profile)` is the single canonical predicate (defined in `crates/vouch-server/src/db/documents/oauth.rs`). It returns `true` only when the registered method is `client_secret_basic` or `client_secret_post` **and** `fapi_profile` is `FapiProfile::None`.

A violation exists whenever any of the following sites makes a secret-eligibility decision without calling this predicate:

1. **`add_secret_form` / `add_secret_api`** — the guard that rejects minting a new secret must call `secret_is_credential(fapi_profile)`, not `uses_client_secret()` alone or `is_fapi()` alone.

2. **`delete_secret_form` / `delete_secret_api`** — the last-secret floor (`other_active == 0 && …`) must call `secret_is_credential(fapi_profile)`. Using `uses_client_secret() && !is_fapi()` is an inline re-derivation of the same logic; it is a violation because it will silently diverge if the predicate's definition ever changes.

3. **`revoke_oauth_client_secret` (in-transaction floor in `db/oauth.rs`)** — the floor guard must call `secret_is_credential(fapi_profile)` on the loaded `OAuthClientDoc`.

4. **`ApplicationInfo::secret_is_credential` field (in `handlers/applications/types.rs`)** — the `From<OAuthClient>` impl must set `secret_is_credential` by calling `client.token_endpoint_auth_method.secret_is_credential(client.fapi_profile)`. The field must be named `secret_is_credential`; the old name `can_add_secret` no longer exists.

5. **Templates (`templates/applications/detail.html`)** — the Add Secret button gate and the Revoke button gate must both key on the `app.secret_is_credential` template field. A template that re-derives the condition (e.g. checks `token_endpoint_auth_method` or `fapi_profile` directly) is a violation. A template that gates Revoke on `secrets_count > 1` unconditionally — without also exempting `!app.secret_is_credential` clients — hides a Revoke button that the handler would allow, recreating the bug fixed in commit `776cf615`.

Specific incorrect patterns to detect:

- `uses_client_secret()` used as a sole secret-eligibility guard (missing the `fapi_profile` axis).
- `is_fapi()` checked separately rather than folded into `secret_is_credential`.
- `uses_client_secret() && !client.is_fapi()` (hand-rolled equivalent of `secret_is_credential`).
- `can_add_secret` as a field or variable name (renamed to `secret_is_credential` in commit `776cf615`).
- A template Revoke gate of the form `secret.active && secrets_count > 1` without an `!app.secret_is_credential` bypass.

## Violation examples

**Hand-rolled add-secret guard (missing fapi axis):**
```rust
// Missing fapi_profile check — FAPI client_secret_basic clients slip through
if !client.token_endpoint_auth_method.uses_client_secret() {
    return error_page(...);
}
```

**Separate is_fapi check instead of unified predicate:**
```rust
if client.is_fapi() {
    return error_page(Tr::new("apps-error-fapi-no-secrets"), ...);
}
if !client.token_endpoint_auth_method.uses_client_secret() {
    return error_page(Tr::new("apps-error-no-client-secrets"), ...);
}
```

**Hand-rolled last-secret floor:**
```rust
if other_active == 0
    && client.token_endpoint_auth_method.uses_client_secret()
    && !client.is_fapi()
{
    return error_page(Tr::new("apps-error-secret-last-active"), ...);
}
```

**In-transaction floor using inline boolean rather than predicate:**
```rust
let secret_usable = client_doc.data.token_endpoint_auth_method.uses_client_secret()
    && client_doc.data.fapi_profile == FapiProfile::None;
if other_active_count == 0 && secret_usable {
    return Err(ServiceError::api(409, "last_secret", ...));
}
```

**`ApplicationInfo` using old field name:**
```rust
pub can_add_secret: bool,  // renamed to secret_is_credential
// ...
let can_add_secret =
    client.token_endpoint_auth_method.uses_client_secret() && !client.is_fapi();
```

**Template Revoke gate missing the non-credential bypass (the bug from commit `14a80c87`):**
```jinja
{% if secret.active && secrets_count > 1 %}
<form action="/applications/{{ app.id }}/secrets/{{ secret.id }}/delete" ...>
    <button>Revoke</button>
</form>
{% endif %}
```
This hides Revoke for a lone stray secret on a `private_key_jwt` or FAPI client even though the handler allows the revocation.

**Template Add Secret gate using old field name:**
```jinja
{% if app.can_add_secret && secrets_count < 2 %}
```

## Correct patterns

**Unified add-secret guard:**
```rust
if !client
    .token_endpoint_auth_method
    .secret_is_credential(client.fapi_profile)
{
    let message = if client.is_fapi() {
        Tr::new("apps-error-fapi-no-secrets")
    } else {
        Tr::new("apps-error-no-client-secrets")
    };
    return error_page(Tr::new("apps-error-title-error"), message, ...);
}
```

**Correct last-secret floor:**
```rust
if other_active == 0
    && client
        .token_endpoint_auth_method
        .secret_is_credential(client.fapi_profile)
{
    return error_page(Tr::new("apps-error-title-error"),
        Tr::new("apps-error-secret-last-active"), ...);
}
```

**Correct in-transaction floor:**
```rust
let secret_is_credential = client_doc
    .data
    .token_endpoint_auth_method
    .secret_is_credential(client_doc.data.fapi_profile);
if other_active_count == 0 && secret_is_credential {
    return Err(ServiceError::api(StatusCode::CONFLICT, "last_secret", ...));
}
```

**Correct `ApplicationInfo` field:**
```rust
pub secret_is_credential: bool,
// ...
let secret_is_credential = client
    .token_endpoint_auth_method
    .secret_is_credential(client.fapi_profile);
```

**Correct template section gate and Revoke gate:**
```jinja
{% if app.secret_is_credential || secrets_count > 0 %}
    {% if app.secret_is_credential && secrets_count < 2 %}
    <form action="/applications/{{ app.id }}/secrets" method="POST">
        <button>Add Secret</button>
    </form>
    {% endif %}
    {% if secret.active && (!app.secret_is_credential || secrets_count > 1) %}
    <form action="/applications/{{ app.id }}/secrets/{{ secret.id }}/delete" method="POST">
        <button>Revoke</button>
    </form>
    {% endif %}
{% endif %}
```

## Scope

- `crates/vouch-server/src/db/documents/oauth.rs` — definition of `secret_is_credential`; any change to `uses_client_secret` or the FAPI axis must keep them in sync.
- `crates/vouch-server/src/db/oauth.rs` — in-transaction floor in `revoke_oauth_client_secret`.
- `crates/vouch-server/src/handlers/applications/types.rs` — `ApplicationInfo::secret_is_credential` field and its `From<OAuthClient>` derivation.
- `crates/vouch-server/src/handlers/applications/web.rs` — `add_secret_form`, `delete_secret_form`.
- `crates/vouch-server/src/handlers/api/applications.rs` — `add_secret_api`, `delete_secret_api`.
- `crates/vouch-server/templates/applications/detail.html` — Add Secret and Revoke button gates.
- `crates/vouch-server/src/services/oidc/token.rs` — `authenticate_client` (must reject secrets for FAPI clients and for non-`client_secret_*` methods; currently uses `is_fapi()` + `uses_client_secret()` directly because it predates the unified predicate — any refactor must not weaken these two independent checks).
