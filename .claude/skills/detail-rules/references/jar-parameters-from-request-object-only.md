# JAR Parameters From Request Object Only

When a JWT Authorization Request (Request Object) is present, every authorization parameter must come exclusively from the Request Object — never from the form body or query string.

## What to look for

RFC 9101 §6.3 states: "The authorization server MUST only use the parameters in the Request Object, even if the same parameter is provided in the query parameter." This applies in both `par.rs` and `authorize.rs` and covers every authorization parameter: `dpop_jkt`, `response_mode`, `state`, `scope`, `nonce`, `redirect_uri`, etc.

Look for these violation patterns when `params.request` is `Some(...)` or `request_jwt` is present:

**1. Pre-JAR form-body checks on authorization parameters**
Any check that reads `params.<field>` (form body) before JAR validation and before the `if let Some(ref request_jwt) = params.request` branch is incorrect when `params.request` may be `Some`. The check will use a non-authoritative value that RFC 9101 §6.3 requires to be ignored.

**2. Fallback from JAR value to form value: `jar_value.or(form_value)` or `jar_value.as_deref().or(params.<field>.as_deref())`**
Using the JAR's value as primary but falling back to the form body if absent is wrong. If the parameter is absent from the Request Object, it is absent from the request — the form duplicate must be ignored entirely.

**3. `requested_response_mode` set from form body in the JAR branch**
In the JAR branch of `par.rs`, `requested_response_mode` must be `jar_rm` (from `request_params.response_mode`), not `params.response_mode`. The variable `jar_rm` is captured from `request_params` before `validate_authorize_request` consumes it; the non-JAR branch uses `params.response_mode` instead.

**4. `state` echoed from form body in JAR/request_uri_fetch flows**
In `authorize.rs`, the `oauth_state` used for RFC 6749 §4.1.2.1 error responses must come from `request_params.state` (the validated Request Object), not `query.state`. The JAR and request_uri_fetch paths already do this correctly (`let oauth_state = request_params.state.clone()`); any regression that replaces it with `query.state.as_deref()` is a violation.

**5. Gated duplicate form check still present**
A check like `if params.request.is_none() { compare params.dpop_jkt with proof }` is the obsolete intermediate fix. The current correct design has no such gate: the single authoritative check uses `effective_dpop_jkt = validated.dpop_jkt().or(dpop_jkt)` (Request Object's value if present, else DPoP proof's thumbprint) and compares that against the DPoP proof. No separate early form-body check exists.

## Violation examples

**Pre-JAR dpop_jkt check against form body (the root bug, fixed in commit 757714b7)**
```rust
// VIOLATION: runs before JAR validation; uses form dpop_jkt even when a
// Request Object is present whose dpop_jkt is the authoritative value.
if let (Some(proof_jkt), Some(param_jkt)) = (dpop_jkt, &params.dpop_jkt) {
    let is_match: bool = proof_jkt.as_bytes().ct_eq(param_jkt.as_bytes()).into();
    if !is_match {
        return par_error_response(
            OAuthErrorCode::InvalidDpopProof,
            presentation,
            "dpop_jkt parameter does not match DPoP proof JWK thumbprint",
        );
    }
}
```

**Gated intermediate fix (also wrong — still consults form body in JAR flows)**
```rust
// VIOLATION: a gated duplicate check is redundant and incorrect.
// The description for rule_26d9c554 incorrectly showed this as the fix.
if params.request.is_none()
    && let (Some(proof_jkt), Some(param_jkt)) = (dpop_jkt, &params.dpop_jkt)
{
    let is_match: bool = proof_jkt.as_bytes().ct_eq(param_jkt.as_bytes()).into();
    if !is_match {
        return par_error_response(...);
    }
}
```

**JAR branch returning form response_mode (fixed in commit 757714b7)**
```rust
// VIOLATION: non-JAR branch returns params.response_mode — but so does the
// JAR branch, overriding the Request Object's response_mode with the form value.
let (validated, requested_response_mode) = if let Some(ref request_jwt) = params.request {
    // ... JAR validation ...
    (v, params.response_mode.clone())  // BUG: should be (v, jar_rm)
} else {
    // ...
    (v, params.response_mode.clone())  // correct: no JAR, form is authoritative
};
```

**Fallback: JAR value with form-body fallback**
```rust
// VIOLATION: falls back to form body when JAR omits a parameter.
let response_mode_str = jar_response_mode
    .as_deref()
    .or(params.response_mode.as_deref());
let response_mode = parse_response_mode(response_mode_str)?;
```

## Correct patterns

**Single dpop_jkt check using the Request Object's value when present (current main)**
```rust
// validated.dpop_jkt() returns the JAR's value when a Request Object was
// present, else None; dpop_jkt is the thumbprint from the DPoP proof header.
let effective_dpop_jkt = validated.dpop_jkt().or(dpop_jkt);

// RFC 9449 §10.1: one check, one source.
if let (Some(requested_jkt), Some(proof)) = (effective_dpop_jkt, &dpop_proof) {
    let is_match: bool = requested_jkt.as_bytes().ct_eq(proof.jkt.as_bytes()).into();
    if !is_match {
        return par_error_response(
            OAuthErrorCode::InvalidDpopProof,
            presentation,
            "dpop_jkt does not match DPoP proof JWK thumbprint",
        );
    }
}
```

**response_mode from the branch that built the request (current main)**
```rust
let (validated, requested_response_mode) = if let Some(ref request_jwt) = params.request {
    // ... JAR validation ...
    let jar_rm = request_params.response_mode.clone(); // capture before move
    let v = validate_authorize_request(request_params)?;
    (v, jar_rm)  // JAR branch: response_mode from Request Object
} else {
    // ... form-body path ...
    let v = validate_authorize_request(request_params)?;
    (v, params.response_mode.clone())  // non-JAR branch: response_mode from form
};
```

**state echoed from Request Object in JAR/request_uri_fetch flows (current authorize.rs)**
```rust
// RFC 9101 §6.3 governs state on error responses too.
let oauth_state = request_params.state.clone(); // from the validated Request Object
let resolved = AuthorizeResponseTarget::from_validated_client(
    state, oauth_client, redirect_uri,
    ResponseModeSource::Requested(requested_response_mode.as_deref()),
    oauth_state.as_deref(), // NOT query.state
).await?;
```

## Scope

- `crates/vouch-server/src/handlers/oidc/par.rs` — primary location; PAR endpoint handles both JAR and non-JAR pushed authorization requests
- `crates/vouch-server/src/handlers/oidc/authorize.rs` — JAR (`handle_jar_request`), PAR (`handle_par_request`), and request_uri_fetch (`handle_request_uri_fetch`, `fetch_and_resolve_request_uri`) flows
- Any future handler that processes a `request` JWT parameter alongside form/query parameters
