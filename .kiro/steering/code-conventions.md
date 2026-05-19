# Code Conventions

## Strict No-Panic Policy

The workspace enforces panic-free code via clippy lints in `Cargo.toml`. These are **denied** (not warned):

### Explicit panics
- `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`, `exit`

### Indexing
- `indexing_slicing`, `string_slice` -- use `.get()` instead of `[]`

### Arithmetic
- `arithmetic_side_effects`, `integer_division`, `modulo_arithmetic`
- Use `checked_*`, `saturating_*`, or `wrapping_*` methods explicitly

### Numeric casts
- `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `cast_precision_loss`, `checked_conversions`
- Use `try_from`, `try_into`, or checked conversions -- never `as` for numeric casts

### Safety
- `unsafe_code` denied at the Rust lint level
- `await_holding_lock`, `large_futures`, `mem_forget` denied

The `vouch-tests` crate overrides these to allow unwrap/expect/panic in test code.

## Error Handling

```rust
// Use explicit error types, not String
pub fn authenticate(cred: &Credential) -> Result<Session, AuthError> { ... }

// Propagate with ?
let session = agent::get_session().await?;
```

## Construction Patterns

```rust
// Prefer builders for complex construction
let session = SessionBuilder::new()
    .user_id(user.id)
    .expires_in(Duration::hours(8))
    .build()?;

// Not: many positional arguments
```

## Documentation

Document public APIs with:
- Brief description
- `# Errors` section listing error conditions
- `# Examples` when helpful

```rust
/// Authenticates using FIDO2 assertion.
///
/// # Errors
///
/// Returns `AuthError::InvalidCredential` if assertion is invalid.
pub fn authenticate(credential: &Credential) -> Result<Session, AuthError> { ... }
```

## Security Patterns

```rust
// Sensitive data: use secrecy
use secrecy::{SecretString, ExposeSecret};
let token: SecretString = fetch_token()?;

// Constant-time comparison for secrets
use subtle::ConstantTimeEq;
if expected.ct_eq(&actual).into() { ... }

// Zeroize on drop
use zeroize::Zeroizing;
let key: Zeroizing<Vec<u8>> = derive_key()?;
```

## Formatting and Linting

```bash
make fmt    # cargo fmt --all
make lint   # cargo clippy --all-targets --all-features -- -D warnings
```

Configuration: edition 2024, max width 100, Unix newlines.

## Commit Messages

Short summary line, optional body explaining "why":

```
Add vouch status command

Show current session state including expiration time
and active delegations.

Closes #42
```
