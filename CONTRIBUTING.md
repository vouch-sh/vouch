# Contributing to vouch

Thank you for your interest in contributing to vouch!

## Development Setup

### Prerequisites

- Rust 1.75+ (2024 edition)
- SQLite 3
- A FIDO2 authenticator (YubiKey, Touch ID, etc.) for testing

### Clone and Build

```bash
git clone https://github.com/vouch-sh/vouch.git
cd vouch
cargo build
```

### Run Tests

```bash
cargo test
```

### Run the Server (Development)

```bash
# Create a config file
cat > vouch.toml << EOF
rp_id = "localhost"
rp_origin = "http://localhost:3000"
jwt_secret = "dev-secret-do-not-use-in-production"
EOF

# Run the server
cargo run -p vouch-server
```

### Run the CLI

```bash
# Point to local server
export VOUCH_SERVER_URL=http://localhost:3000

cargo run -p vouch-cli -- status
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Write doc comments for public APIs
- Add tests for new functionality

## Project Structure

```
crates/
├── vouch-cli/      # CLI binary
├── vouch-server/   # Identity server
├── vouch-agent/    # Local credential agent
└── vouch-common/   # Shared types

docs/               # Documentation
```

## Making Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run lints (`cargo fmt && cargo clippy`)
6. Commit with a clear message
7. Push to your fork
8. Open a Pull Request

## Pull Request Guidelines

- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new functionality
- Ensure CI passes

## Commit Messages

Use clear, descriptive commit messages:

```
feat(cli): add --json flag to status command

Add JSON output option for scripting use cases.
Closes #123
```

Prefixes:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `refactor:` Code change that doesn't fix a bug or add a feature
- `test:` Adding tests
- `chore:` Maintenance tasks

## Reporting Issues

- Check existing issues before opening a new one
- Include reproduction steps
- Include relevant logs/errors
- Specify your environment (OS, Rust version)

## Security Issues

Please report security vulnerabilities privately to security@vouch.sh. Do not open public issues for security problems.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
