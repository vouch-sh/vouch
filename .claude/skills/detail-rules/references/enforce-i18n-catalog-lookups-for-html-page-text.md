# Enforce i18n Catalog Lookups for HTML Page Text

Free-text fields on HTML page templates rendered by `vouch-server` must carry `Tr<'static>` (or `Option<Tr<'static>>`), never `String` or `Option<String>`, and flash setters must receive `admin::flash::FlashText`; upstream error detail must be wrapped as a Fluent placeable, not assigned directly to a template field.

## What to look for

### 1. Template struct field types

Every free-text field on an HTML-rendering template must be typed `Tr<'static>` or `Option<Tr<'static>>`:

- **`ErrorTemplate`** (`handlers/enroll.rs`): `title: Tr<'static>`, `message: Tr<'static>`
- **`GitHubErrorTemplate`** (`handlers/github.rs`): `title: Tr<'static>`, `message: Tr<'static>`
- **`ApplicationErrorTemplate`** (`handlers/applications/types.rs`): `title: Tr<'static>`, `message: Tr<'static>`
- **`DeviceVerifyTemplate`** (`handlers/enroll.rs`): `error: Option<Tr<'static>>`

Flag any new template struct that renders into HTML and declares a free-text field as `String` or `Option<String>`.

**Exempt fields** (legitimate `String`/`Option<String>` on templates):
- URL fields (`back_url`, `redirect_uri`, etc.)
- Machine-identifiable data (UUIDs, slugs, hostnames)
- User-supplied data not rendered as prose (application descriptions in edit forms)
- `flash.ok` / `flash.err` on GET-side templates — these hold the already-rendered `FlashText` cookie value

### 2. Template construction sites

Flag any construction of an HTML template where a free-text field is assigned:
- A raw string literal: `"Error".to_string()`, `"Missing RelayState parameter".to_string()`
- A `format!(…)` call: `format!("Key '{}' deleted", name)`
- A `Display`-formatted error: `e.to_string()`, `err.message()` (where the result goes directly to `title`/`message`)
- A `Tr::new(…).to_string()` — the `.to_string()` call is the wrong form; the field must receive the `Tr` value itself, not a pre-rendered string

The correct form is: `title: Tr::new("catalog-key")` — no `.to_string()`.

### 3. Flash setter callsites

Flash setters (`flash::set_ok`, `flash::set_err`, `flash::set_ok_at`, `flash::set_err_at`) accept `impl Into<FlashText>`. `FlashText` has no `From<String>` or `From<&str>` impl; only `From<Tr<'_>>` and `From<&Tr<'_>>` exist. Flag any attempt to pass a raw string literal or `format!(…)` output to these functions.

### 4. Upstream IdP error passthrough

When an OIDC or SAML IdP returns its own `error` / `error_description`, those strings must appear only as placeables inside a `Tr` call:

```rust
Tr::new("enroll-error-idp-returned-detail")
    .arg("error", error)
    .arg("detail", detail)
```

Assigning the IdP's raw protocol string directly to `title` or `message` is a violation, even if the string is then wrapped with `.to_string()`.

### 5. Upstream/storage detail rendered instead of logged

When a storage error or upstream API call fails, the error detail must go to `tracing::error!` / `tracing::warn!`, and the template field must receive a generic catalog key. Rendering `e.to_string()` or `err.message()` verbatim into a user-facing page is a violation even if it is wrapped in a `Tr` argument (it is only acceptable as a Fluent placeable, not as the entire field value).

## Violation examples

**Raw English literals on template fields (pre-fix saml.rs pattern):**
```rust
// VIOLATION — hardcoded English, bypasses i18n
ErrorTemplate {
    title: "Error".to_string(),
    message: "Missing RelayState parameter".to_string(),
    back_url: None,
}

ErrorTemplate {
    title: "Authentication Failed".to_string(),
    message: "Failed to verify SAML response. Please try again.".to_string(),
    back_url: None,
}
```

**`Tr::new(…).to_string()` on a field typed `Tr<'static>` (intermediate-fix pattern):**
```rust
// VIOLATION — pre-renders into String before the field holds Tr
ErrorTemplate {
    title: Tr::new("logout-error-title").to_string(),
    message: Tr::new("logout-error-message").to_string(),
    back_url: Some("/".to_string()),
}
```

**Raw string literal on `DeviceVerifyTemplate.error` (pre-fix pattern):**
```rust
// VIOLATION — Option<String> field / raw English literal
DeviceVerifyTemplate {
    error: Some("Invalid code. Please check and try again.".to_string()),
    user_code: None,
}
```

**Template struct declaring free-text field as `String` (pre-fix struct definition):**
```rust
// VIOLATION — struct field typed String, not Tr<'static>
pub(crate) struct ErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: Option<String>,
}
```

**IdP error assigned directly to template field (pre-fix oidc_callback pattern):**
```rust
// VIOLATION — IdP protocol strings become the entire title/message
ErrorTemplate {
    title: error,                                         // raw IdP error code
    message: params.error_description.unwrap_or_else(|| "Unknown error".to_string()),
    back_url: None,
}
```

**ApplicationErrorTemplate raw-literal construction (pre-fix applications/web.rs pattern):**
```rust
// VIOLATION — English literals, bypasses i18n
ApplicationErrorTemplate {
    title: "Error".to_string(),
    message: "Failed to load applications.".to_string(),
    back_url: "/".to_string(),
}
```

**GitHubError detail rendered verbatim to page (pre-fix github.rs pattern):**
```rust
// VIOLATION — upstream error string reaches the page
GitHubErrorTemplate {
    title: error.title().to_string(),
    message: error.to_string(),   // carries operator-facing detail
}
```

## Correct patterns

**Template field typed `Tr<'static>`, constructed without `.to_string()`:**
```rust
ErrorTemplate {
    title: Tr::new("error-heading"),
    message: Tr::new("saml-error-missing-relay-state"),
    back_url: None,
}
```

**`Tr` with placeables for dynamic content:**
```rust
ErrorTemplate {
    title: Tr::new("enroll-error-unknown-provider-title"),
    message: Tr::new("enroll-error-unknown-provider").arg("slug", slug.to_string()),
    back_url: Some("/device".to_string()),
}
```

**IdP upstream error as Fluent placeable, not as field value:**
```rust
let message = match params.error_description {
    Some(detail) => Tr::new("enroll-error-idp-returned-detail")
        .arg("error", error)
        .arg("detail", detail),
    None => Tr::new("enroll-error-idp-returned").arg("error", error),
};
ErrorTemplate {
    title: Tr::new("error-heading"),
    message,
    back_url: None,
}
```

**Storage/API failure: log detail, show generic message:**
```rust
GitHubError::Database(_) | GitHubError::Internal(_) => {
    tracing::error!("GitHub integration failed: {error}");
    (Tr::new("error-heading"), Tr::new("github-error-internal"))
}
```

**Flash setter receiving `Tr` (compiles; `String` literal does not):**
```rust
flash::set_ok(jar, Tr::new("admin-domains-flash-add-pending").arg("domain", added.domain.as_str()))
flash::set_err(jar, Tr::new("admin-domains-error-max-domains"))
```

**`Option<Tr<'static>>` for optional error fields:**
```rust
DeviceVerifyTemplate {
    error: Some(Tr::new("device-error-invalid-code")),
    user_code: None,
}
```

## Scope

Check all files under `crates/vouch-server/src/handlers/` (recursively), including:

- `enroll.rs` and `enroll/` — `ErrorTemplate`, `DeviceVerifyTemplate`
- `saml.rs` — SAML ACS handler using `ErrorTemplate`
- `github.rs` — `GitHubErrorTemplate`
- `applications/web.rs`, `applications/types.rs` — `ApplicationErrorTemplate`
- `admin/flash.rs` — `FlashText` type and flash setter functions
- `admin/domains.rs`, `admin/subdomain.rs`, `admin/policies.rs`, `admin/scim_tokens.rs` — flash setter callsites
- `enroll_keys.rs` — path-scoped flash callsites
- `oidc/` handlers — OIDC callback error paths
- Any new handler file that imports or constructs an `*Template` type

**Out of scope:**
- `crates/vouch-server/src/handlers/api/` and JSON-returning handlers (protocol-level `message: String` fields in JSON API responses such as `RegisterCompleteResponse`, `DeleteKeyResponse` are not HTML and are exempt)
- `crates/vouch-cli/` — CLI uses a separate i18n stack
- `crates/vouch-i18n/` — the i18n library itself
