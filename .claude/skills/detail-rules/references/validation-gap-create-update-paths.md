# Validation Gap Between Create and Update Paths

Detect security or correctness validation rules that are enforced on resource creation (registration, initial config) but not re-applied on the corresponding update path (RFC 7592 PUT, admin update API, web form, SCIM PATCH), creating a bypass where an update can place a resource into a state that the create path would have rejected.

## What to look for

Look for validation calls that appear in the `create`/`register` function but are **absent or incomplete** in the paired `update`/`put`/`patch` function within the same module. Key patterns:

### 1. RFC 7592 `update_client_configuration` vs `register_client`
In `crates/vouch-server/src/services/oidc/registration.rs`, `register_client` is the create path and `update_client_configuration` is the RFC 7592 PUT path. Any validation helper called in `register_client` must also be called in `update_client_configuration` unless the comment explicitly justifies the omission (e.g., `token_endpoint_auth_method` is immutable and intentionally not updated).

Required parity checks:
- `validate_contacts_and_uris(&request)` — must be called on both paths (previously absent from PUT)
- `validate_userinfo_signed_response_alg(..., fapi_profile)` — must pass `client.fapi_profile` on the update path (previously passed no profile, allowing RS256 for FAPI clients)
- `reject_rs256_for_fapi(alg, fapi_profile, field)` — must be called for **all four** algorithm fields: `id_token_signed_response_alg`, `authorization_signed_response_alg`, `userinfo_signed_response_alg`, `request_object_signing_alg`
- Auth-method/JWKS consistency check: `private_key_jwt` clients must still require `jwks` or `jwks_uri` on PUT (previously absent, allowing JWKS to be cleared)

### 2. Application update handlers vs create handler
In `crates/vouch-server/src/handlers/applications/`, `create_application_api` is the create path. `update_application_api` and the web form handler must apply the same rules:
- Rejecting empty or whitespace-only `name` (previously `None` and `""` were conflated on update)
- Rejecting empty `redirect_uris` for non-`Service` application types (previously enforced only at create; `validate_update_fapi` in `validate.rs` covers this now)

### 3. Shared validation helpers not threaded through update paths
A common sub-pattern: a validation helper gains a new parameter (e.g., `fapi_profile`) but the update call-site is not updated to pass the relevant value, effectively disabling the new check for updates.

### 4. Comments that claim parity but don't deliver it
Beware comments like `// same rules as initial registration` or `// Validate JWKS and jwks_uri (same rules as initial registration)` that appear directly above a validation call — verify the **full set** of rules from the create path is actually mirrored, not just the format check.

## Violation examples

**Missing FAPI profile on update path — RS256 bypass:**
```rust
// BEFORE fix (update_client_configuration)
let userinfo_alg = validate_userinfo_signed_response_alg(
    mutable_request.userinfo_signed_response_alg.as_deref(),
    state.oidc_rsa_key.is_some(),
    // fapi_profile NOT passed — FAPI RS256 restriction silently disabled on PUT
)?;
```

**Missing algorithm field coverage on create path — JARM bypass:**
```rust
// BEFORE fix (register_client) — authorization_signed_response_alg had no FAPI check
if parsed == JwsAlgorithm::Rs256 && state.oidc_rsa_key.is_none() {
    return Err(...);
}
// No reject_rs256_for_fapi() call for authorization_signed_response_alg
```

**Missing auth-method/JWKS consistency on RFC 7592 PUT:**
```rust
// BEFORE fix (update_client_configuration)
// Validate JWKS and jwks_uri (same rules as initial registration):
// mutually exclusive, valid structure, HTTPS URI.
validate_jwks_fields(
    mutable_request.jwks.as_ref(),
    mutable_request.jwks_uri.as_deref(),
)?;
// private_key_jwt + no jwks/jwks_uri NOT rejected — client left unable to authenticate
```

**Missing contacts/URI validation on RFC 7592 PUT:**
```rust
// BEFORE fix: validate_contacts_and_uris() was only called in register_client,
// not in update_client_configuration — invalid logo_uri or non-@ contacts
// could be smuggled in via PUT
```

**Empty name or redirect_uris accepted on application update:**
```rust
// BEFORE fix (update_application_api)
let name = req.name.as_deref().unwrap_or(&client.name);
// No check for empty/whitespace name — "" was accepted on PATCH

// BEFORE fix (validate_update_format)
if let Some(uris) = input.redirect_uris {
    validate_redirect_uris(uris)...?;  // format only, empty slice not rejected
}
// Empty redirect_uris not checked against application_type here
```

## Correct patterns

**Thread immutable registration-time fields into all update-path validators:**
```rust
// update_client_configuration — pass client.fapi_profile (immutable post-registration)
let userinfo_alg = validate_userinfo_signed_response_alg(
    mutable_request.userinfo_signed_response_alg.as_deref(),
    rsa_key,
    client.fapi_profile,  // re-applies FAPI RS256 restriction
)?;
```

**Call reject_rs256_for_fapi on every algorithm field:**
```rust
reject_rs256_for_fapi(parsed, fapi_profile, "id_token_signed_response_alg")?;
reject_rs256_for_fapi(parsed, fapi_profile, "authorization_signed_response_alg")?;
reject_rs256_for_fapi(parsed, fapi_profile, "userinfo_signed_response_alg")?;
reject_rs256_for_fapi(parsed, fapi_profile, "request_object_signing_alg")?;
```

**Re-check auth-method/JWKS relationship on PUT:**
```rust
// PUT is a full replacement, so re-check the auth-method/JWKS relationship
// enforced at initial registration against the client's (immutable) registered
// auth method.
if client.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
    && mutable_request.jwks.is_none()
    && mutable_request.jwks_uri.is_none()
{
    return Err(ServiceError::oauth(
        OAuthErrorCode::InvalidClientMetadata,
        "private_key_jwt requires jwks or jwks_uri",
    ));
}
```

**Call the same contacts/URI validator on update path:**
```rust
// In update_client_configuration, after JWKS checks:
validate_contacts_and_uris(&mutable_request)?;
```

**Distinguish "field absent" from "field explicitly cleared" on update:**
```rust
// Reject empty name only when explicitly provided; None = keep existing
if let Some(new_name) = req.name.as_deref()
    && new_name.trim().is_empty()
{
    return Err(ServiceError::api(StatusCode::BAD_REQUEST, "invalid_name", "..."));
}

// Reject empty redirect_uris for non-service apps via validate_update_fapi
if let Some(uris) = validated.redirect_uris
    && uris.is_empty()
    && !matches!(client.application_type, OAuthClientType::Service)
{
    return Err(AppValidationError::MissingRedirectUris);
}
```

## Scope

- `crates/vouch-server/src/services/oidc/registration.rs` — `register_client` (create) vs `update_client_configuration` (RFC 7592 PUT)
- `crates/vouch-server/src/handlers/applications/api.rs` — `create_application_api` vs `update_application_api`
- `crates/vouch-server/src/handlers/applications/web.rs` — web form create vs update handlers
- `crates/vouch-server/src/handlers/applications/validate.rs` — `validate_create_application` vs `validate_update_format` / `validate_update_fapi`
- `crates/vouch-server/src/handlers/scim/users.rs` — `create_user` vs `patch_user`
- `crates/vouch-server/src/handlers/scim/groups.rs` — `create_group` vs `patch_group`
- `crates/vouch-server/src/handlers/admin/` — any admin update endpoints

Out of scope: pure DB layer functions (`crates/vouch-server/src/db/`), CLI, and non-server crates.
