# Contributing to Vouch

Thank you for your interest in contributing to Vouch! This document covers development setup, code style, and submission guidelines.

## Code of Conduct

Be respectful and constructive. We're building security software — thoughtful review and honest feedback make it better.

## What's Open Source

| Component | License | Contributions Welcome |
|-----------|---------|----------------------|
| vouch-cli | Apache-2.0 OR MIT | ✅ Yes |
| vouch-agent | Apache-2.0 OR MIT | ✅ Yes |
| vouch-common | Apache-2.0 OR MIT | ✅ Yes |
| vouch-server | BUSL-1.1 | ✅ Yes (CLA required) |
| Documentation | CC-BY-4.0 | ✅ Yes |

## Development Setup

### Prerequisites

- **Rust** 1.93+ (install via [rustup](https://rustup.rs/), pinned in `rust-toolchain.toml`)
- **YubiKey 5 series** for testing FIDO2 flows (use a dedicated test key, not your primary)
- **Docker** for building and running the server image
- **TailwindCSS CLI** for CSS compilation (`make css-build`)

### Clone and Build

```bash
git clone https://github.com/vouch-sh/vouch.git
cd vouch

make build                # Build release binary (includes CSS)
make test                 # Run unit tests
make lint                 # Run clippy
make fmt                  # Format code
```

### Project Structure

```
vouch/
├── Cargo.toml              # Workspace root
├── Makefile                # Build, test, run, deploy targets
├── crates/
│   ├── vouch-cli/          # CLI binary (commands/, integrations/)
│   ├── vouch-agent/        # Background daemon (Unix socket IPC)
│   │   └── src/
│   │       ├── state.rs    # Session state management
│   │       ├── socket.rs   # Unix socket handling
│   │       ├── protocol.rs # JSON-RPC 2.0 protocol
│   │       ├── wire.rs     # Wire format serialization
│   │       └── ssh_agent/  # SSH agent protocol
│   ├── vouch-common/       # Shared types and utilities
│   │   └── src/
│   │       ├── api.rs      # API types (Credential, Session, etc.)
│   │       ├── fido2_types.rs # FIDO2 type definitions
│   │       └── contracts.rs   # Shared contracts
│   ├── vouch-server/       # Auth server (BUSL-1.1)
│   │   ├── src/handlers/   # HTTP route handlers
│   │   ├── src/db/         # Database layer (sqlx)
│   │   ├── migrations/     # sqlite/ and postgres/
│   │   └── templates/      # Askama HTML templates
│   └── vouch-tests/        # Integration + property-based tests
│       └── tests/
│           ├── integration.rs
│           ├── golden_files.rs
│           └── proptest.rs
├── docs/                   # Architecture, security, deployment guides
└── packaging/              # AMI and post-install scripts
```

### Running Locally

```bash
make run                   # CLI with RUST_LOG=debug
make run-server            # Server (loads .env, builds CSS first)
make run-agent             # Agent daemon in foreground with debug logging

# Or directly:
cargo run --bin vouch -- --help
RUST_LOG=debug cargo run --bin vouch -- login
```

A `.env` file at the repo root is loaded by the Makefile. See `.env` for required server environment variables (`VOUCH_RP_ID`, `VOUCH_RP_NAME`, `VOUCH_JWT_SECRET`, etc.).

### Running the Server in Docker

```bash
make docker-build
make docker-run            # Runs on localhost:3000 with dev defaults
```

### Testing with YubiKey

For FIDO2 testing, you'll need a physical YubiKey:

```bash
# Check system and YubiKey status
cargo run --bin vouch -- doctor

# Run FIDO2 integration tests (requires YubiKey)
cargo test --features yubikey-tests -- --ignored

# Reset YubiKey FIDO2 app (warning: destructive)
ykman fido reset
```

## Code Style

### Rust Guidelines

We follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) with these specifics:

```rust
// Good: Explicit error types
pub fn authenticate(credential: &Credential) -> Result<Session, AuthError> { ... }

// Bad: String errors
pub fn authenticate(credential: &Credential) -> Result<Session, String> { ... }
```

```rust
// Good: Use builders for complex construction
let session = SessionBuilder::new()
    .user_id(user.id)
    .expires_in(Duration::hours(8))
    .build()?;

// Bad: Many positional arguments
let session = Session::new(user.id, None, Some(8), true, None)?;
```

```rust
// Good: Document public APIs
/// Authenticates a user with their FIDO2 credential.
/// 
/// # Errors
/// 
/// Returns `AuthError::InvalidCredential` if the assertion is invalid.
/// Returns `AuthError::SessionExpired` if the session has expired.
pub fn authenticate(credential: &Credential) -> Result<Session, AuthError> { ... }
```

### Formatting

```bash
make fmt                  # cargo fmt --all
cargo fmt -- --check      # CI check (will fail if unformatted)
```

Configuration is in `.rustfmt.toml`: edition 2024, max width 100, Unix newlines.

### Linting

```bash
make lint   # cargo clippy --all-targets --all-features -- -D warnings
```

The workspace enforces strict no-panic lints (see `Cargo.toml`). In production code, `unwrap()`, `expect()`, `panic!()`, `todo!()`, and `[]` indexing are **denied**. Use `?` for error propagation and `.get()` for indexing. The `vouch-tests` crate overrides these for test code.

### Dependencies

Add dependencies sparingly — each is attack surface. All workspace dependencies are pinned to exact versions with minimal features in the root `Cargo.toml`.

Preferred crates:
- `jiff` for time (not `chrono`)
- `aws-lc-rs` for crypto (not `ring`)
- `reqwest` + `rustls` (avoid OpenSSL)
- `askama` for HTML templates

Before adding a dependency:
1. Check maintenance status
2. Review security advisories (`cargo audit`)
3. Consider size impact
4. Prefer pure Rust over C bindings when possible

## Submitting Changes

### Before You Start

1. **Check existing issues** — Someone may already be working on it
2. **Open a discussion** — For large changes, discuss approach first
3. **Keep scope small** — One feature or fix per PR

### Commit Messages

Write clear, concise commit messages. Use a short summary line followed by an optional body explaining the "why":

```
Add vouch status command

Show current session state including expiration time
and active delegations.

Closes #42
```

### Pull Request Process

1. **Fork and branch**
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make changes**
   - Write tests for new functionality
   - Update documentation if needed
   - Run `cargo fmt` and `cargo clippy`

3. **Test thoroughly**
   ```bash
   cargo test
   cargo test --features yubikey-tests -- --ignored  # if touching FIDO2
   ```

4. **Push and open PR**
   - Fill out the PR template
   - Link related issues
   - Request review

5. **Address feedback**
   - Respond to all comments
   - Push updates as new commits (we squash on merge)

### PR Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] No unrelated changes included

## Testing

### Running Tests

```bash
make test                  # Unit tests (all crates)
make test-integration      # Integration + property-based tests

# Specific test with output
cargo test test_session_expiration -- --nocapture

# FIDO2 tests (requires physical YubiKey)
cargo test --features yubikey-tests -- --ignored
```

Integration tests live in `crates/vouch-tests/tests/` and include property-based tests via `proptest`.

## Security Considerations

When contributing security-sensitive code:

1. **No secrets in code** — Use environment variables or config files
2. **Validate all input** — Especially from network or user
3. **Use constant-time comparison** — For secrets and tokens
4. **Zeroize sensitive data** — Use `secrecy` and `zeroize` crates
5. **Document security assumptions** — In comments and docs

```rust
// Good: Constant-time comparison
use subtle::ConstantTimeEq;
if expected.ct_eq(&provided).into() { ... }

// Bad: Timing attack vulnerable
if expected == provided { ... }
```

```rust
// Good: Zeroize on drop
use secrecy::SecretString;
let api_key: SecretString = load_key()?;

// Bad: Secret in plain String
let api_key: String = load_key()?;
```

## Documentation

### Code Documentation

```rust
/// Brief description of what this does.
///
/// Longer description if needed, explaining behavior,
/// edge cases, and important details.
///
/// # Arguments
///
/// * `credential` - The FIDO2 credential to verify
///
/// # Returns
///
/// The authenticated session on success.
///
/// # Errors
///
/// Returns `AuthError::InvalidCredential` if verification fails.
///
/// # Examples
///
/// ```
/// let session = authenticate(&credential)?;
/// println!("Session expires: {}", session.expires_at);
/// ```
pub fn authenticate(credential: &Credential) -> Result<Session, AuthError> {
```

### Updating Docs

Documentation lives in `/docs`. When updating:

1. Keep language clear and concise
2. Include examples where helpful
3. Update table of contents if adding sections
4. Test any code examples

## Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/vouch-sh/vouch/discussions)
- **Bugs**: Open a [GitHub Issue](https://github.com/vouch-sh/vouch/issues)
- **Security**: Email security@vouch.sh (see [Security Model](docs/src/security/model.md))

## License

By contributing to open source components (vouch-cli, vouch-agent, vouch-common), you agree that your contributions will be dual-licensed under Apache-2.0 OR MIT, at the choice of the user. By contributing to vouch-server, you agree that your contributions will be licensed under the Business Source License 1.1.

---

Thank you for helping make Vouch better! 🔐
