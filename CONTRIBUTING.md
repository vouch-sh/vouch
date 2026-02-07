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

- **Rust** 1.93+ (install via [rustup](https://rustup.rs/))
- **YubiKey 5 series** for testing FIDO2 flows
- **Docker** for running the test server
- **PostgreSQL** 17+ (or use Docker)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/vouch-sh/vouch.git
cd vouch

# Build all crates
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo fmt
```

### Project Structure

```
vouch/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── vouch-cli/          # CLI binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── commands/   # CLI command implementations
│   │   │   └── ...
│   │   └── Cargo.toml
│   │
│   ├── vouch-agent/        # Background daemon
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── session.rs  # Session management
│   │   │   ├── ipc.rs      # Unix socket IPC
│   │   │   └── ...
│   │   └── Cargo.toml
│   │
│   └── vouch-common/       # Shared types and utilities
│       ├── src/
│       │   ├── lib.rs
│       │   ├── types.rs    # Credential, Session, etc.
│       │   ├── fido2.rs    # FIDO2 helpers
│       │   └── ...
│       └── Cargo.toml
│
├── docs/                   # Documentation
├── tests/                  # Integration tests
└── scripts/                # Development scripts
```

### Running Locally

```bash
# Start test infrastructure
docker-compose -f docker-compose.dev.yml up -d

# Run the CLI
cargo run --bin vouch -- --help

# Run the agent
cargo run --bin vouch-agent

# Run with debug logging
RUST_LOG=debug cargo run --bin vouch -- login
```

### Testing with YubiKey

For FIDO2 testing, you'll need a physical YubiKey:

```bash
# Check YubiKey is detected
cargo run --bin vouch -- yubikey info

# Run FIDO2 integration tests (requires YubiKey)
cargo test --features yubikey-tests -- --ignored

# Reset YubiKey FIDO2 app (warning: destructive)
ykman fido reset
```

**Note**: Don't use your primary YubiKey for development. Use a dedicated test key.

### Test Server

The dev compose file includes a mock Vouch server:

```bash
# Start mock server
docker-compose -f docker-compose.dev.yml up -d

# Point CLI at mock server
export VOUCH_SERVER_URL=http://localhost:3000

# Now vouch commands hit the mock server
cargo run --bin vouch -- register
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
# Format all code
cargo fmt

# Check formatting (CI will fail if this fails)
cargo fmt -- --check
```

### Linting

```bash
# Run clippy with strict settings
cargo clippy --all-targets --all-features -- -D warnings

# Common clippy allows (document why if used):
#[allow(clippy::too_many_arguments)]  // Builder pattern would be overkill here
```

### Dependencies

Add dependencies sparingly:

```toml
# Good: Well-maintained, security-audited
ctap-hid-fido2 = "3"    # Pure Rust FIDO2
keyring = "3"            # Platform credential storage

# Avoid: Unmaintained, too many transitive deps
some-kitchen-sink-crate = "0.1"
```

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

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(cli): add vouch status command

Show current session state including expiration time
and active delegations.

Closes #42
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding or updating tests
- `chore`: Build process or auxiliary tool changes

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
- [ ] Commit messages follow convention
- [ ] No unrelated changes included

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_expiration() {
        let session = Session::new(Duration::hours(8));
        assert!(!session.is_expired());
        
        // Simulate time passing
        let expired = session.with_created_at(Utc::now() - Duration::hours(9));
        assert!(expired.is_expired());
    }
}
```

### Integration Tests

```rust
// tests/integration/ssh_test.rs

#[test]
#[ignore]  // Requires YubiKey
fn test_ssh_certificate_flow() {
    // Setup
    let server = TestServer::start();
    let yubikey = TestYubikey::new();
    
    // Register
    let result = vouch_cli::register(&server, &yubikey);
    assert!(result.is_ok());
    
    // Login
    let session = vouch_cli::login(&server, &yubikey).unwrap();
    assert!(!session.is_expired());
    
    // Get SSH cert
    let cert = vouch_cli::get_ssh_cert(&server, &session).unwrap();
    assert!(cert.is_valid());
}
```

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_session_expiration

# With output
cargo test -- --nocapture

# Integration tests (require setup)
cargo test --test integration -- --ignored
```

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
- **Security**: Email security@vouch.sh (see [SECURITY.md](docs/SECURITY.md))

## License

By contributing to open source components (vouch-cli, vouch-agent, vouch-common), you agree that your contributions will be dual-licensed under Apache-2.0 OR MIT, at the choice of the user. By contributing to vouch-server, you agree that your contributions will be licensed under the Business Source License 1.1.

---

Thank you for helping make Vouch better! 🔐
