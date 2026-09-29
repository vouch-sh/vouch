# Service Error Variant Coverage Across All Converters

Every `ServiceError` variant that carries a client-facing status and error code must be handled explicitly in ALL error-to-response converters (`into_oauth_response`, `into_api_response`, and wrapper helpers like `into_registration_response`); adding a variant to one converter while a catch-all `_ =>` arm silently collapses it to `500 server_error` in the others is a violation.

## What to look for

The `ServiceError` enum lives in `crates/vouch-server/src/error.rs` and currently has these variants that carry client-meaningful status codes and error codes:

- `NotFound` → 404 `invalid_request`
- `Validation` → 400 `invalid_request`
- `Forbidden` → 403 `access_denied`
- `Conflict` → 409 `conflict`
- `OAuth { code, description }` → status from `code.status_code()`
- `Api { status, code, message }` → arbitrary status + code
- `ApiWithHeaders { status, code, message, headers }` → arbitrary status + code + response headers
- `StepUpRequired { acr_values, max_age }` → 401 `insufficient_user_authentication` + `WWW-Authenticate`
- `OccConflict`, `Database`, `Internal` → 500 (intentionally opaque)

There are three converters that must each handle every non-opaque variant explicitly:

1. **`ServiceError::into_api_response`** — used by most REST handlers via `IntoResponse`.
2. **`ServiceError::into_oauth_response`** — used by OAuth/OIDC endpoints (`/oauth/token`, `/oauth/par`, etc.) and by all wrapper helpers.
3. **`into_registration_response`** in `crates/vouch-server/src/handlers/oidc/register.rs` — wraps `into_oauth_response` and adds `WWW-Authenticate` on 401s; it is the sole converter for `/oauth/register`, `GET/PUT/DELETE /oauth/register/:client_id`.

**Violation pattern:** A new variant (e.g., `ApiWithHeaders`) is added to `ServiceError` and wired into `into_api_response`, but `into_oauth_response` is not updated and its `_ =>` catch-all silently converts the variant to `500 server_error`. Since `into_registration_response` delegates entirely to `into_oauth_response`, it inherits the same silent collapse.

**Key risk surface:** Any `ServiceError` variant that can be returned from `extract_resource_token` (in `crates/vouch-server/src/handlers/session.rs`) is especially dangerous because that function is called from `OptionalAuthenticatedToken`, which is used by the `/oauth/register` handler — an OAuth endpoint that routes errors through `into_oauth_response`.

Check for:
- Any `ServiceError` variant not listed as an explicit arm in `into_oauth_response` (beyond the intentionally-opaque `OccConflict`, `Database`, `Internal` variants).
- `into_oauth_response` containing a `_ =>` arm that could silently swallow a variant with a specific status code or error code.
- `ApiWithHeaders` (or any future header-bearing variant) handled in `into_api_response` but absent from `into_oauth_response`.
- `into_registration_response` calling `into_oauth_response()` without pre-extracting headers from `ApiWithHeaders` before the call destroys them.

## Violation examples

**Missing arm for `ApiWithHeaders` in `into_oauth_response` (the actual bug):**

```rust
// VIOLATION: ApiWithHeaders added to the enum and handled in into_api_response,
// but not added to into_oauth_response — falls through to the catch-all.
pub fn into_oauth_response(self) -> (StatusCode, Json<OAuthErrorResponse>) {
    match self {
        Self::OAuth { code, description } => ( /* correct */ ),
        Self::NotFound(entity) => ( /* correct */ ),
        Self::Validation(msg) => ( /* correct */ ),
        Self::Api { status, code, message } if status == StatusCode::UNAUTHORIZED => ( /* correct */ ),
        Self::Forbidden(_) => ( /* correct */ ),
        Self::StepUpRequired { .. } => ( /* correct */ ),
        // BUG: ApiWithHeaders is NOT listed here; falls to catch-all below
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Internal server error".to_string()),
                error_uri: None,
            }),
        ),
    }
}
```

**Consequence in `into_registration_response` (the downstream collapse):**

```rust
// VIOLATION: into_registration_response calls into_oauth_response(), which has
// already lost the ApiWithHeaders status/code/headers before this function sees it.
fn into_registration_response(err: crate::error::ServiceError) -> Response {
    let (status, json) = err.into_oauth_response();
    // At this point, if `err` was ApiWithHeaders { status: 401, code: "use_dpop_nonce", headers: [...] },
    // `status` is now 500 and `json.error` is "server_error" — the DPoP-Nonce header is gone.
    if status == StatusCode::UNAUTHORIZED { /* never reached for use_dpop_nonce */ }
    (status, json).into_response()
}
```

**Before the fix — `extract_resource_token` returns `ApiWithHeaders`:**

```rust
// In crates/vouch-server/src/handlers/session.rs
Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
    return Err(ServiceError::api_with_header(
        StatusCode::UNAUTHORIZED,
        "use_dpop_nonce",
        "Authorization server requires nonce in DPoP proof",
        ("DPoP-Nonce", nonce.as_str()),
    ));
    // This error flows through OptionalAuthenticatedToken → /oauth/register handler
    // → into_registration_response → into_oauth_response → _ => server_error (BUG)
}
```

## Correct patterns

**Every non-opaque variant must have an explicit arm in `into_oauth_response`:**

```rust
pub fn into_oauth_response(self) -> (StatusCode, Json<OAuthErrorResponse>) {
    match self {
        Self::OAuth { code, description } => ( /* ... */ ),
        Self::NotFound(entity) => ( /* ... */ ),
        Self::Validation(msg) => ( /* ... */ ),
        Self::Api { status, code, message } if status == StatusCode::UNAUTHORIZED => ( /* ... */ ),
        Self::Forbidden(_) => ( /* ... */ ),
        Self::StepUpRequired { .. } => ( /* ... */ ),
        // CORRECT: ApiWithHeaders handled explicitly, preserving status and code.
        // Note: headers cannot be returned here (return type is a tuple, not Response),
        // so the caller (into_registration_response) must handle header forwarding separately.
        Self::ApiWithHeaders { status, code, message, .. } if status == StatusCode::UNAUTHORIZED => (
            status,
            Json(OAuthErrorResponse {
                error: code,
                error_description: Some(message),
                error_uri: None,
            }),
        ),
        // Only truly opaque variants belong in the catch-all
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthErrorResponse {
                error: "server_error".to_string(),
                error_description: Some("Internal server error".to_string()),
                error_uri: None,
            }),
        ),
    }
}
```

**When a wrapper helper needs headers, handle the variant before calling `into_oauth_response`:**

```rust
fn into_registration_response(err: crate::error::ServiceError) -> Response {
    // Pre-extract ApiWithHeaders before into_oauth_response loses the headers
    if let ServiceError::ApiWithHeaders { status, code, message, headers } = err {
        let oauth_body = Json(OAuthErrorResponse {
            error: code,
            error_description: Some(message),
            error_uri: None,
        });
        let mut response = (status, oauth_body).into_response();
        for (name, value) in headers {
            response.headers_mut().append(name, value);
        }
        return response;
    }
    let (status, json) = err.into_oauth_response();
    // ... rest of 401 WWW-Authenticate wrapping
}
```

## Scope

- **Primary file:** `crates/vouch-server/src/error.rs` — `ServiceError` enum definition, `into_oauth_response`, `into_api_response`.
- **Wrapper helper:** `crates/vouch-server/src/handlers/oidc/register.rs` — `into_registration_response`.
- **Trigger for new violations:** Any commit that adds a new `ServiceError` variant, adds a new arm to `ServiceError::into_api_response`, or adds a new arm to `extract_resource_token` in `crates/vouch-server/src/handlers/session.rs`.
- **Out of scope:** Handler files that call `into_oauth_response()` or `into_registration_response()` directly without modifying the converters themselves.
