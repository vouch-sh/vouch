# Redact Secrets in Debug Implementations

Structs containing bearer tokens, OIDC ID tokens, access tokens, refresh tokens, client secrets, or other credentials must not derive `Debug` without a custom implementation that redacts those fields, because `{:?}` formatting in log output exposes credentials in plaintext.

## What to look for

Flag any struct that meets **both** criteria:

1. **Contains a sensitive field** — a field whose name or type indicates it holds a credential:
   - Name contains: `token`, `secret`, `password`, `key` (when holding key material), `bearer`, `access_token`, `id_token`, `refresh_token`, `authorization_token`, `api_key`, `signin_token`
   - Type is a bare `String` or `Option<String>` (not wrapped in `secrecy::SecretString` or `Zeroizing<…>`)

2. **Derives `Debug`** — has `#[derive(Debug, …)]` without a corresponding `impl std::fmt::Debug` that redacts the field.

Structs that use `secrecy::SecretString` for the field are already protected by `secrecy`'s own `Debug` impl (`[REDACTED]`), so they are **not** a violation. Structs that use neither `SecretString` nor a custom `impl Debug` **are** a violation.

Key locations to check:
- `crates/vouch-common/src/api.rs` — public API response types shared between server and CLI
- `crates/vouch-server/src/services/integrations/` — AWS, GitHub token result types
- `crates/vouch-server/src/services/oidc/token.rs` — OIDC token exchange result types
- `crates/vouch-server/src/handlers/oidc/token.rs` — HTTP handler token response types
- `crates/vouch-cli/src/commands/credential/` — CLI credential response types
- `crates/vouch-cli/src/integrations/aws/` — AWS integration response types

## Violation examples

**Bare `#[derive(Debug)]` on a struct with a plain `String` token field (the pattern fixed in commit 0532e1f):**

```rust
// CloudTokenResponse before the fix — id_token printed verbatim in {:?}
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudTokenResponse {
    pub id_token: String,   // OIDC bearer credential — printed plaintext!
    pub expires_in: u64,
}
```

```rust
// AwsTokenResult before the fix — same pattern, server-side
#[derive(Debug)]
pub(crate) struct AwsTokenResult {
    pub id_token: String,   // OIDC bearer credential — printed plaintext!
    pub expires_in: u64,
}
```

**Derived Debug on a struct where a sibling field holds a token (even if Debug isn't used today):**

```rust
// Hypothetical violation — access_token as plain String + #[derive(Debug)]
#[derive(Debug, Deserialize)]
struct CreateTokenResponse {
    access_token: String,   // SSO bearer token — would appear in logs
    expires_in: Option<u64>,
}
```

## Correct patterns

**Pattern A — Custom `impl Debug` that emits `[REDACTED]` for each secret field:**

```rust
#[derive(Serialize, Deserialize)]   // no Debug in derive list
pub struct CloudTokenResponse {
    pub id_token: String,
    pub expires_in: u64,
}

// Custom Debug that redacts id_token to prevent accidental log exposure.
impl std::fmt::Debug for CloudTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudTokenResponse")
            .field("id_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}
```

**Pattern B — Use `secrecy::SecretString` for the field (automatic redaction):**

```rust
#[derive(Debug, Deserialize)]   // derive OK because SecretString redacts itself
struct VouchTokenExchangeResponse {
    access_token: SecretString,   // secrecy's Debug prints "[REDACTED]"
    expires_in: Option<u64>,
}
```

**Pattern C — Struct holds no secret material, plain `#[derive(Debug)]` is fine:**

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct SsoRole {
    pub role_name: String,
    pub account_id: String,   // non-secret identifiers only
}
```

**Test to pair with Pattern A** (the repo convention):

```rust
#[test]
fn test_cloud_token_response_debug_redacts_id_token() {
    let r = CloudTokenResponse { id_token: "secret".to_string(), expires_in: 3600 };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("secret"));
}
```

## Scope

Check all Rust source files under:

- `crates/vouch-common/src/`
- `crates/vouch-server/src/services/integrations/`
- `crates/vouch-server/src/services/oidc/`
- `crates/vouch-server/src/handlers/`
- `crates/vouch-cli/src/commands/credential/`
- `crates/vouch-cli/src/commands/aws/`
- `crates/vouch-cli/src/integrations/aws/`
- `crates/vouch-cli/src/commands/enroll.rs`

Exclude test-only structs (`#[cfg(test)]`) and structs whose only token-like field is already typed as `secrecy::SecretString` or `Zeroizing<…>`.
