# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vouch is a hardware-backed authentication system that issues short-lived credentials after FIDO2 verification with a YubiKey. The core principle: **no credential issuance without human presence proof**. Vouch is OpenID Certified for the FAPI 2.0 OP Security Profile (including message signing).

## Architecture Quick Reference

```
vouch/
├── crates/
│   ├── vouch-cli/        # User-facing CLI binary (Apache-2.0/MIT)
│   ├── vouch-agent/      # Background daemon for session/cert management (Apache-2.0/MIT)
│   ├── vouch-server/     # Auth server with OIDC provider, SSH CA (Apache-2.0/MIT)
│   ├── vouch-common/     # Shared types, FIDO2 helpers, API client (Apache-2.0/MIT)
│   ├── vouch-httpsig/    # RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest
│   └── vouch-tests/      # Integration + property-based tests
├── fuzz/                 # libfuzzer targets: BER, attestation objects, COSE keys, HTTP sigs
├── docs/                 # mdBook documentation (build with `make docs-build`)
└── packaging/            # AMI and post-install scripts
```

**Agent IPC:** The CLI communicates with the agent daemon over a Unix socket (`~/.vouch/agent.sock`) using JSON-RPC 2.0 with 4-byte length-prefixed messages.

**Database:** vouch-server uses SQLite (dev), PostgreSQL (prod), and Aurora DSQL via sqlx with a `Pool` enum abstraction (`db/pool.rs`) that dispatches at runtime based on the `DATABASE_URL` scheme. Query building uses `sea-query` for dynamic SQL. DSQL endpoints (hostname contains `.dsql.` and ends `.on.aws`) auto-generate IAM auth tokens. Migrations live in `crates/vouch-server/migrations/{sqlite,postgres}/`. Domain modules are in `crates/vouch-server/src/db/` (users, sessions, authenticators, oauth, scim, etc.).

**Key flows:**
1. `vouch enroll` → Browser OIDC → WebAuthn in browser → CLI receives OAuth access token (first key)
2. `vouch login` → FAPI 2.0: /oauth/fido2/challenge → CTAP2 getAssertion → /oauth/token (FIDO2 grant + DPoP) → DPoP-bound access token
3. `vouch register` → (requires login) → FIDO2 makeCredential → add additional key (POST /v1/keys/register/*)
4. `vouch credential ssh` → exchange access token for SSH certificate
5. `vouch credential aws` → exchange access token for AWS temporary credentials
6. `vouch setup eks` → configure kubeconfig for EKS (chains through `vouch credential aws` → `aws eks get-token`)
7. Native tools (ssh, aws, kubectl) call vouch helpers transparently via `credential_process`

Beyond ssh/aws/eks, credential helpers and setup commands cover many more integrations (kubernetes, github, docker, cargo, codeartifact, codecommit, pip, rds, redshift, ssm, and anthropic/openai via workload identity federation) — see `crates/vouch-cli/src/commands/credential/` and `setup/`.

## Server Architecture

The server has two distinct route groups sharing `AppState`:

- **API routes** (`/v1/`, `/oauth/`, `/scim/`, `/api/v1/`) — JSON responses, JWT Bearer auth. Includes OIDC endpoints, credential issuance, SCIM provisioning, GitHub webhooks, and admin APIs.
- **UI routes** (`/`, `/login`, `/enroll/*`, `/docs/*`, `/applications/*`) — HTML via Askama templates, cookie-based sessions. Static assets embedded via `rust-embed`.

When TLS is configured, a separate HTTP→HTTPS redirect router runs on port 80 (308 redirects, except `/health`).

**AppState** holds: `Pool` (db), `ArcSwap<ServerConfig>` (lock-free config reload), `Webauthn`, optional `SshCa`, optional `GitHubApp`, `DpopState`, and `OidcSigningKey`.

**Services layer** (`crates/vouch-server/src/services/`): Business logic called by handlers — `oidc/` (authorization, token issuance, DPoP, discovery, JWKS, token exchange), `integrations/` (AWS, GitHub App/OAuth/webhooks), `auth.rs` (WebAuthn verification).

**HTTP message signing:** Requests to `/v1/*` may carry RFC 9421 signatures. The generic signing/verification middleware (with an async `KeyResolver` trait) lives in `vouch-httpsig`; the server-side resolver is `infra/httpsig.rs` (extracts `client_id` from the JWT, resolves P-256 public keys from OAuth client JWKS stored at RFC 7591 dynamic registration). Enforcement is optional: verify when `Signature-Input` is present, pass through otherwise. The CLI signing adapter is `crates/vouch-cli/src/fapi/httpsig.rs`.

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
make test-fuzz             # Fuzz targets, 60s each (requires nightly)
make test-coverage         # Coverage report (requires cargo-llvm-cov)
make test-mutants          # Mutation testing (requires cargo-mutants)

# Supply chain
make audit                 # cargo-deny: advisories, licenses, bans

# CSS (requires tailwindcss CLI)
make css-dev               # Watch mode
make css-build             # Minified production build

# Docs (mdBook)
make docs-build
make docs-serve

# Docker
make docker-build
make docker-run
make bake-all              # musl binaries via Docker Bake (also bake-cli, bake-server)
```

**Running the server locally:** at least one upstream IdP must be configured via `VOUCH_IDPS` / `VOUCH_IDP_<SLUG>_*` (the server refuses to start without one), plus `VOUCH_RP_ID`, `VOUCH_JWT_SECRET`, and `VOUCH_DATABASE_URL`. See `AGENTS.md` for a minimum viable command and `docs/src/reference/environment-variables.md` for the full reference.

**Toolchain:** Rust 1.96.0, edition 2024 (pinned in `rust-toolchain.toml`). Max line width 100 chars (`.rustfmt.toml`). Release profile uses `lto = true`, `codegen-units = 1`, `opt-level = "z"`, `panic = "abort"`, `strip = true`.

## Code Conventions

### Strict No-Panic Policy

The workspace enforces panic-free code via clippy lints in `Cargo.toml`. Key categories denied (not warn):
- **Explicit panics**: `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`, `exit`
- **Indexing**: `indexing_slicing`, `string_slice` — use `.get()` instead of `[]`
- **Panics in Result fns**: `unwrap_in_result`, `panic_in_result_fn`, `get_unwrap`
- **Arithmetic**: `arithmetic_side_effects`, `integer_division`, `modulo_arithmetic` — use `checked_*`, `saturating_*`, or `wrapping_*`
- **Numeric casts**: `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `cast_precision_loss`, `checked_conversions` — use `try_from`, `try_into`, or checked conversions
- **Unsafe code**: denied at the Rust lint level

See `Cargo.toml` for the complete list. The `vouch-tests` crate overrides these to allow unwrap/expect/panic in test code.

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

All dependencies are declared at workspace level in the root `Cargo.toml` under `[workspace.dependencies]` with exact versions and minimal features. Crates reference them with `dep.workspace = true`. Add sparingly. Prefer:
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
4. **Don't use `as` for numeric casts** — Use `try_from()`, `try_into()`, or explicit checked conversions to avoid silent truncation/wrapping
5. **Don't skip FIDO2 user verification** — `userVerification: required` always
6. **Don't implement crypto yourself** — Use audited libraries
7. **Don't use `chrono`** — Use `jiff` for time
8. **Don't use `ring`** — Use `aws-lc-rs` for crypto

## File Locations

| Need | Location |
|------|----------|
| CLI commands | `crates/vouch-cli/src/commands/` |
| Credential helpers | `crates/vouch-cli/src/commands/credential/` |
| Setup commands | `crates/vouch-cli/src/commands/setup/` |
| Agent IPC | `crates/vouch-agent/src/` (client.rs, server.rs, protocol.rs, wire.rs) |
| SSH agent protocol | `crates/vouch-agent/src/ssh_agent/` |
| API types | `crates/vouch-common/src/api.rs` |
| FIDO2 types | `crates/vouch-common/src/fido2_types.rs` |
| Server handlers | `crates/vouch-server/src/handlers/` |
| Server services | `crates/vouch-server/src/services/` (oidc/, integrations/) |
| Crypto primitives | `crates/vouch-server/src/crypto/` (jwt.rs, ssh_ca.rs, webauthn_verify.rs, kms_signer.rs, cose.rs, attestation_chain.rs, document_crypto.rs, tpm_decrypt.rs, ber.rs, pem.rs) |
| Server infra | `crates/vouch-server/src/infra/` (router.rs, tls.rs, rate_limit.rs, security_headers.rs, mtls_listener.rs, httpsig.rs, cleanup.rs, s3_config.rs) |
| HTTP message signatures | `crates/vouch-httpsig/` (server resolver: `infra/httpsig.rs`, CLI adapter: `fapi/httpsig.rs`) |
| Fuzz targets | `fuzz/fuzz_targets/` |
| Database modules | `crates/vouch-server/src/db/` (pool.rs, users.rs, sessions.rs, etc.) |
| HTML templates | `crates/vouch-server/templates/` |
| CSS source | `crates/vouch-server/styles/input.css` |
| Static assets | `crates/vouch-server/static/` (embedded via rust-embed) |
| FAPI client (CLI) | `crates/vouch-cli/src/fapi/` (key.rs, dpop.rs, client_assertion.rs, registration.rs) |
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
3. Is this in scope for MVP?
4. Does this change the security model? Document in `docs/src/security/model.md`.

## External Resources

**Specifications:**
- [FIDO2/CTAP2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 7009 - Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 7662 - Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 8176 - Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 8693 - Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 7521 - Assertion Framework for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7521)
- [RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 8725 - JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9101 - JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101)
- [RFC 9126 - Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [RFC 9396 - OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9470 - OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)
- [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 7643/7644 - SCIM 2.0](https://www.rfc-editor.org/rfc/rfc7643)

**Crates:**
- [ctap-hid-fido2](https://crates.io/crates/ctap-hid-fido2) — Pure Rust FIDO2/CTAP2
- [ssh-key](https://crates.io/crates/ssh-key) — SSH key/certificate handling

**Reference:**
- [Amazon Midway](https://midway-auth.amazon.com) — Inspiration for hardware-backed auth
- [Why Strong Authentication Is Your Most Important Security Control](https://www.linkedin.com/pulse/why-strong-authentication-your-most-important-security-schmidt-unm0e/) - LinkedIn post by Stephen Schmidt, SVP & Chief Security Officer at Amazon
