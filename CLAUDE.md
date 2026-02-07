# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vouch is a hardware-backed authentication system that issues short-lived credentials after FIDO2 verification with a YubiKey. The core principle: **no credential issuance without human presence proof**.

## Architecture Quick Reference

```
vouch/
├── crates/
│   ├── vouch-cli/        # User-facing CLI binary (Apache-2.0/MIT)
│   ├── vouch-agent/      # Background daemon for session/cert management (Apache-2.0/MIT)
│   ├── vouch-server/     # Auth server with OIDC provider, SSH CA (BUSL-1.1)
│   ├── vouch-common/     # Shared types, FIDO2 helpers, API client (Apache-2.0/MIT)
│   └── vouch-tests/      # Integration + property-based tests
├── docs/                 # Architecture, security model, guides
└── packaging/            # AMI and post-install scripts
```

**Agent IPC:** The CLI communicates with the agent daemon over a Unix socket (`~/.vouch/agent.sock`) using JSON-RPC 2.0 with 4-byte length-prefixed messages.

**Database:** vouch-server uses SQLite (dev) and PostgreSQL (prod) via sqlx. Migrations live in `crates/vouch-server/migrations/{sqlite,postgres}/`.

**Key flows:**
1. `vouch enroll` → Browser OIDC → WebAuthn in browser → CLI receives session token (first key)
2. `vouch login` → FIDO2 getAssertion → receive session token
3. `vouch register` → (requires login) → FIDO2 makeCredential → add additional key
4. `vouch credential ssh` → exchange session for SSH certificate
5. `vouch credential aws` → exchange session for AWS temporary credentials
6. `vouch credential gcp` → exchange session for GCP OIDC token (Workload Identity Federation)
7. Native tools (ssh, aws, gcloud) call vouch helpers transparently via `credential_process`

## Build & Development Commands

```bash
# Build (includes CSS compilation)
make build

# Format / lint / check
make fmt
make lint                  # cargo clippy --all-targets --all-features -- -D warnings
make check

# Run locally
make run                   # CLI with RUST_LOG=debug
make run-server            # Server (loads .env, builds CSS first)
make run-agent             # Agent daemon in foreground

# Tests
make test                  # Unit tests (cargo test)
make test-integration      # Integration tests (cargo test --package vouch-tests)
cargo test test_name -- --nocapture  # Single test with output

# CSS (requires tailwindcss CLI)
make css-dev               # Watch mode
make css-build             # Minified production build

# Docker
make docker-build
make docker-run
```

**Toolchain:** Rust 1.93.0, edition 2024 (pinned in `rust-toolchain.toml`). Max line width 100 chars (`.rustfmt.toml`).

## Code Conventions

### Strict No-Panic Policy

The workspace enforces panic-free code via clippy lints in `Cargo.toml`. These are **deny** (not warn):
- `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented` — use `?` and proper error handling
- `indexing_slicing` — use `.get()` instead of `[]`
- `unwrap_in_result`, `panic_in_result_fn`, `get_unwrap` — no panics in Result-returning functions
- `unsafe_code` — denied at the Rust lint level

The `vouch-tests` crate overrides these to allow unwrap/expect/panic in test code.

### Rust Style

```rust
// Use explicit error types, not String
pub fn authenticate(cred: &Credential) -> Result<Session, AuthError>

// Prefer builders for complex construction
let session = SessionBuilder::new()
    .user_id(user.id)
    .expires_in(Duration::hours(8))
    .build()?;

// Document public APIs with examples
/// Authenticates using FIDO2 assertion.
/// 
/// # Errors
/// Returns `AuthError::InvalidCredential` if assertion is invalid.
pub fn authenticate(...) -> Result<...>
```

### Dependencies

Add sparingly. Prefer:
- `ctap-hid-fido2` for FIDO2 (pure Rust)
- `keyring` for credential storage
- `reqwest` + `rustls` (avoid OpenSSL)
- `aws-lc-rs` for crypto (not `ring`)
- `jiff` for time (not `chrono`)
- `clap` for CLI parsing
- `axum` for server (if needed)
- `askama` for HTML templates (compile-time checked)

### Frontend

Keep it simple. No complex JavaScript frameworks.

**Allowed:**
- TailwindCSS — Utility-first CSS (self-hosted, no CDN)
- Tailkit — Pre-built Tailwind components (we have full license)
- HTMX — Server-driven interactivity when needed
- Vanilla JavaScript — For WebAuthn APIs and simple UI interactions

**Not allowed:**
- jQuery
- React, Vue, Angular, Svelte
- Any npm/node.js build toolchain for JavaScript
- External CDN dependencies

**Rationale:** The server UI is for enrollment tasks, not a complex SPA. Askama templates + TailwindCSS + minimal JS keeps it auditable and maintainable.

### Security Patterns

```rust
// Always use secrecy for sensitive data
use secrecy::{SecretString, ExposeSecret};
let token: SecretString = fetch_token()?;

// Constant-time comparison for secrets
use subtle::ConstantTimeEq;
if expected.ct_eq(&actual).into() { ... }

// Zeroize on drop
use zeroize::Zeroizing;
let key: Zeroizing<Vec<u8>> = derive_key()?;
```

## Common Tasks

### Adding a New CLI Command

1. Create file in `crates/vouch-cli/src/commands/`
2. Add to command enum in `crates/vouch-cli/src/commands/mod.rs`
3. Implement `run()` function
4. Add tests

```rust
// crates/vouch-cli/src/commands/status.rs
use clap::Args;

#[derive(Args)]
pub struct StatusArgs {
    #[arg(short, long)]
    verbose: bool,
}

pub async fn run(args: StatusArgs) -> Result<()> {
    let session = agent::get_session().await?;
    // ...
}
```

### Adding a Credential Type

1. Add type to `vouch-common/src/types.rs`
2. Add credential helper in `vouch-cli/src/commands/credential/`
3. Add setup command in `vouch-cli/src/commands/setup/`
4. Update documentation

### Working with FIDO2

```rust
use crate::fido2::{YubiKey, ensure_pin_configured};

// Wait for YubiKey to be inserted
let key = YubiKey::wait_for_device()?;

// Check if PIN is set and prompt for setup if not (requires 8+ chars)
let pin = ensure_pin_configured(&key)?;

// Authenticate using discoverable credential
let result = key.authenticate(&rp_id, &challenge, &pin)?;
```

**PIN Handling:**
- `key.is_pin_set()` — Check if PIN is configured
- `key.set_new_pin(&pin)` — Set initial PIN (8+ characters required)
- `key.change_pin(&current, &new)` — Change existing PIN
- `ensure_pin_configured(&key)` — Detect missing PIN and guide user through setup
- `translate_fido2_error()` — Convert CTAP2 errors to user-friendly messages

## Testing

```bash
make test                  # Unit tests
make test-integration      # Integration + property-based tests (vouch-tests crate)
cargo test test_session_expiration -- --nocapture  # Single test with output

# With YubiKey (requires physical device)
cargo test --features yubikey-tests -- --ignored
```

## What NOT to Do

1. **Don't add dependencies without justification** — Each dep is attack surface
2. **Don't store secrets in plain types** — Use `SecretString`, `Zeroizing`
3. **Don't use `unwrap()`, `expect()`, `panic!()`, or `[]` indexing** — These are deny-linted. Use `?`, `.get()`, and proper error propagation
4. **Don't skip FIDO2 user verification** — `userVerification: required` always
5. **Don't implement crypto yourself** — Use audited libraries
6. **Don't use `chrono`** — Use `jiff` for time
7. **Don't use `ring`** — Use `aws-lc-rs` for crypto

## File Locations

| Need | Location |
|------|----------|
| CLI commands | `crates/vouch-cli/src/commands/` |
| Agent IPC | `crates/vouch-agent/src/` |
| API types | `crates/vouch-common/src/api.rs` |
| Server handlers | `crates/vouch-server/src/handlers/` |
| SSH CA | `crates/vouch-server/src/ssh_ca.rs` |
| Database | `crates/vouch-server/src/db.rs` |
| HTML templates | `crates/vouch-server/templates/` |
| Integration tests | `crates/vouch-tests/tests/` |
| DB migrations | `crates/vouch-server/migrations/{sqlite,postgres}/` |

## Key Design Decisions

1. **CLI is open source** — Auditability builds trust
2. **Rust for memory safety** — Security tool must be secure
3. **YubiKey-only for MVP** — Consistent security properties
4. **8-hour sessions** — Balance security and usability
5. **Built-in SSH CA** — Ed25519 signing, no external dependencies
6. **MDM for distribution** — Don't build what Jamf/Kandji already do
7. **OIDC config is env-var only** — No admin UI for OIDC configuration
8. **Org admin via JWT** — SCIM tokens and auth events at `/api/v1/org/*` use JWT Bearer auth from regular FIDO2 sessions

## Questions to Ask

Before implementing a feature:
1. Does this require new dependencies? Can we avoid them?
2. Does this touch sensitive data? Use appropriate wrappers.
3. Is this in scope for MVP? Check `docs/ROADMAP.md`.
4. Does this change the security model? Document in `docs/SECURITY.md`.

## External Resources

**Specifications:**
- [FIDO2/CTAP2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 7009 - Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 7662 - Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 8693 - Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7643/7644 - SCIM 2.0](https://www.rfc-editor.org/rfc/rfc7643)

**Crates:**
- [ctap-hid-fido2](https://crates.io/crates/ctap-hid-fido2) — Pure Rust FIDO2/CTAP2
- [ssh-key](https://crates.io/crates/ssh-key) — SSH key/certificate handling

**Reference:**
- [Amazon Midway](https://midway-auth.amazon.com) — Inspiration for hardware-backed auth
- [Why Strong Authentication Is Your Most Important Security Control](https://www.linkedin.com/pulse/why-strong-authentication-your-most-important-security-schmidt-unm0e/) - LinkedIn post by Stephen Schmidt, SVP & Chief Security Officer at Amazon
