# DPoP Token-First Order and Single WWW-Authenticate Challenge

Detects violations of the token-before-proof ordering for DPoP-scheme requests and the single-challenge contract for 401 responses across `/v1/*`, `/oauth/userinfo`, and `/oauth/register`.

## What to look for

### 1. Proof validated before token is refused (`/v1/*` and `/oauth/userinfo`)

The correct order is: decode token → session lookup → check `cnf.jkt` presence → validate proof → check `confirms_dpop`. A violation occurs when `validate_dpop_at_resource` is called **before** refusing a token that would be rejected (undecodable, revoked, not DPoP-bound). Recording a proof `jti` for a token that will then be refused is the concrete harm.

**At `/v1/*` (`extract_resource_token`):** A single `(AuthScheme::DPoP, _)` arm that calls `validate_dpop_at_resource` before checking `dpop_cnf` is a VIOLATION if the `None` branch returns `NotDpopBound` — the proof jti is consumed before the token is refused. The correct pattern uses two separate arms: `(AuthScheme::DPoP, None)` returns `DpopChallenge::binding(NotDpopBound)` immediately (no proof call), and `(AuthScheme::DPoP, Some(cnf))` calls `validate_dpop_at_resource` then `cnf.confirms_dpop`.

**At `/oauth/userinfo`:** Token decode and session lookup must complete before `validate_dpop_at_resource`. The `dpop_cnf` check (`cnf.jkt.is_some()`) must run before the proof call; `NotDpopBound` must be returned before calling `validate_dpop_at_resource`.

### 2. Token refusals use `DpopChallenge::token`, not `DpopChallenge::binding`

When a DPoP-scheme request is refused because the token itself is invalid (undecodable, wrong audience, revoked session), the error must use `DpopChallenge::token(description)` (`invalid_token` per RFC 9449 Figure 16). `DpopChallenge::binding(...)` is reserved for proof/key-binding failures after a valid token.

### 3. Single `WWW-Authenticate` challenge at `/oauth/register`

`into_registration_response` synthesizes `WWW-Authenticate: Bearer …` for any 401 by default. After commit `f6485dd0`, a `ServiceError::ApiWithHeaders` from a DPoP refusal already carries `WWW-Authenticate: DPoP …` in its headers. If the function calls `response.headers_mut().append(...)` for those headers without first checking whether a `WWW-Authenticate` is already present, the response ends up with two `WWW-Authenticate` values (a wrong-scheme `Bearer` challenge plus the correct `DPoP` challenge).

The guard must be: skip synthesizing the `Bearer` challenge when `extra_headers` already contains a `WWW-Authenticate` entry. The check field is `carries_challenge` (or equivalent).

### 4. `oauth_error` at `/oauth/userinfo` adds a `Bearer` challenge — only for Bearer/form-token paths

`oauth_error` in `userinfo.rs` unconditionally sets `WWW-Authenticate: Bearer …` on every 401. It must not be called for DPoP-scheme refusals; those must use `DpopChallenge::token(...).into_oauth_response()` or `DpopChallenge::binding(...).into_oauth_response()` so the challenge scheme is `DPoP`.

## Violation examples

### Violation A — proof validated before token binding check on `/v1/*`
```rust
// VIOLATION: single DPoP arm validates proof before checking cnf — records jti
// for a not-DPoP-bound token that will then be refused
(AuthScheme::DPoP, _) => {
    let validated = dpop::validate_dpop_at_resource(...).await
        .map_err(DpopError::at_resource)?;   // proof jti recorded here
    match dpop_cnf {
        Some(cnf) if cnf.confirms_dpop(&validated) => { dpop_source = validated.source; }
        Some(_) => return Err(DpopChallenge::binding(PossessionError::DpopKeyMismatch).into()),
        None => return Err(DpopChallenge::binding(PossessionError::NotDpopBound).into()),
        // ^^^ token refused AFTER proof was validated and its jti recorded
    }
}
```

### Violation B — proof validated before `NotDpopBound` check on `/oauth/userinfo`
```rust
// VIOLATION: proof call runs before the cnf.jkt None guard
if is_dpop_scheme {
    let full_uri = format!("{}/oauth/userinfo", config.base_url);
    match dpop::validate_dpop_at_resource(&token, &headers, ...).await {
        Ok(proof) => {
            match decoded.cnf() {
                Some(cnf) if cnf.jkt.is_some() => { /* confirms_dpop */ }
                Some(_) | None => {
                    return DpopChallenge::binding(PossessionError::NotDpopBound).into_oauth_response();
                    // ^^^ jti already recorded above
                }
            }
        }
        Err(e) => { /* ... */ }
    }
}
```

### Violation C — `into_registration_response` adds a Bearer challenge on top of a carried DPoP challenge
```rust
// VIOLATION: synthesizes Bearer challenge without checking for an existing
// WWW-Authenticate in extra_headers — yields two WWW-Authenticate values
fn into_registration_response(err: ServiceError) -> Response {
    let extra_headers = match &err {
        ServiceError::ApiWithHeaders { headers, .. } => Some(headers.clone()),
        _ => None,
    };
    let (status, json) = err.into_oauth_response();
    let mut response = if status == StatusCode::UNAUTHORIZED {
        // ^^^ always synthesizes Bearer challenge, even when extra_headers
        //     already contains WWW-Authenticate: DPoP …
        let www_auth = http::bearer_challenge(&[("error", ...), ("error_description", ...)]);
        (status, [(WWW_AUTHENTICATE, www_auth)], json).into_response()
    } else { ... };
    if let Some(headers) = extra_headers {
        for (name, value) in headers {
            response.headers_mut().append(name, value);
            // ^^^ appends second WWW-Authenticate: DPoP value alongside the first Bearer one
        }
    }
    response
}
```

### Violation D — `decode_token` / session lookup called after proof validation at `/oauth/userinfo`
```rust
// VIOLATION: proof validated, then token decoded — jti recorded for a
// potentially-revoked token
if is_dpop_scheme {
    match dpop::validate_dpop_at_resource(...).await {
        Ok(proof) => {
            let decoded = decode_token(&token, &state.oidc_key, &config.base_url)...;
            // ... binding check
        }
        ...
    }
}
let result = validate_session_token(&state, &token, arrival).await?;
```

## Correct patterns

### Correct — two separate DPoP arms in `extract_resource_token` (`session.rs`)
```rust
let dpop_cnf = access_claims.cnf.as_ref().filter(|cnf| cnf.jkt.is_some());
match (auth_scheme, dpop_cnf) {
    (AuthScheme::Cookie, _) => { /* browser session check */ }
    (AuthScheme::DPoP, None) => {
        // No proof validation; NotDpopBound refused immediately.
        return Err(DpopChallenge::binding(PossessionError::NotDpopBound).into());
    }
    (AuthScheme::DPoP, Some(cnf)) => {
        let full_uri = format!("{}{}", config.base_url, uri);
        let validated = dpop::validate_dpop_at_resource(...).await
            .map_err(DpopError::at_resource)?;
        if !cnf.confirms_dpop(&validated) {
            return Err(DpopChallenge::binding(PossessionError::DpopKeyMismatch).into());
        }
        dpop_source = validated.source;
    }
    (AuthScheme::Bearer, Some(_)) => { /* DPoP-bound token under Bearer refused */ }
    (AuthScheme::Bearer, None) => {}
}
```

### Correct — token-first ordering at `/oauth/userinfo`
```rust
// 1. Decode token
let Some(decoded) = decode_token(&token, &state.oidc_key, &config.base_url) else {
    return refuse_token("Invalid or expired token");  // DpopChallenge::token if DPoP scheme
};
// 2. Session lookup
let result = match validate_session_token(&state, &token, arrival).await { ... };
// 3. Check cnf.jkt BEFORE proof call
let dpop_cnf = decoded.cnf().filter(|cnf| cnf.jkt.is_some());
if is_dpop_scheme {
    let Some(cnf) = dpop_cnf else {
        return DpopChallenge::binding(PossessionError::NotDpopBound).into_oauth_response();
    };
    // 4. Only now validate proof
    let proof = dpop::validate_dpop_at_resource(...).await?;
    if !cnf.confirms_dpop(&proof) {
        return DpopChallenge::binding(PossessionError::DpopKeyMismatch).into_oauth_response();
    }
}
```

### Correct — `into_registration_response` skips Bearer synthesis when DPoP challenge is already carried
```rust
fn into_registration_response(err: ServiceError) -> Response {
    let extra_headers = match &err {
        ServiceError::ApiWithHeaders { headers, .. } => Some(headers.clone()),
        _ => None,
    };
    let carries_challenge = extra_headers.as_ref().is_some_and(|headers| {
        headers.iter().any(|(name, _)| name == axum::http::header::WWW_AUTHENTICATE)
    });
    let (status, json) = err.into_oauth_response();
    let mut response = if status == StatusCode::UNAUTHORIZED && !carries_challenge {
        // synthesize Bearer challenge only when nothing already answered
        let www_auth = http::bearer_challenge(&[("error", ...), ("error_description", ...)]);
        (status, [(WWW_AUTHENTICATE, www_auth)], json).into_response()
    } else {
        (status, json).into_response()
    };
    if let Some(headers) = extra_headers {
        for (name, value) in headers {
            response.headers_mut().append(name, value);
        }
    }
    response
}
```

### Correct — token refusals use `DpopChallenge::token`
```rust
let refuse_token = |description: &str| -> ServiceError {
    match auth_scheme {
        AuthScheme::DPoP => DpopChallenge::token(description).into(),
        AuthScheme::Bearer | AuthScheme::Cookie => {
            ServiceError::api(StatusCode::UNAUTHORIZED, "invalid_token", description)
        }
    }
};
// Used for: decode failure, audience mismatch, session-not-found
```

## Scope

- `crates/vouch-server/src/handlers/session.rs` — `extract_resource_token`: DPoP match arms, `refuse_token` closure
- `crates/vouch-server/src/handlers/oidc/userinfo.rs` — `userinfo`: proof/token ordering, `refuse_token`, `oauth_error` call sites for DPoP paths
- `crates/vouch-server/src/handlers/oidc/register.rs` — `into_registration_response`: `carries_challenge` guard before Bearer synthesis
- `crates/vouch-server/src/handlers/session/tests.rs` — tests asserting single-challenge and token-first order
- `crates/vouch-server/src/handlers/oidc/tests/rfc9449.rs`, `rfc7591.rs` — integration tests for the same invariants
