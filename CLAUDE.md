# CLAUDE.md

This file provides guidance for Claude Code when working on the vouch codebase.

## Project Overview

vouch is a hardware-backed identity system for developers. It uses FIDO2 (YubiKey, Touch ID) to authenticate users and issues short-lived credentials for GitHub, AWS, and SSH. The key differentiator is **agent delegation** - allowing humans to grant scoped, time-limited credentials to AI coding assistants.

## Build & Test Commands

```bash
# Build all crates
cargo build

# Build release
cargo build --release

# Run tests
cargo test

# Run specific crate tests
cargo test -p vouch-common
cargo test -p vouch-cli
cargo test -p vouch-server

# Run the server (requires config)
cargo run -p vouch-server

# Run the CLI
cargo run -p vouch-cli -- --help
cargo run -p vouch-cli -- status

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## Architecture

```
crates/
├── vouch-cli/      # CLI binary (`vouch` command)
├── vouch-server/   # Identity server (axum)
├── vouch-agent/    # Local credential daemon
└── vouch-common/   # Shared types
```

### Data Flow

1. User runs `vouch login` → opens browser for FIDO2 ceremony
2. User touches YubiKey → server issues JWT session token
3. User runs `vouch get github` → server issues short-lived GitHub token
4. User runs `vouch delegate` → server issues scoped delegation token for AI agent

### Key Types (vouch-common)

- `PresenceType` - `HumanPresent` vs `HumanDelegated` (the core distinction)
- `CredentialTarget` - GitHub, AWS, or SSH credential request
- `DelegationScope` - what an agent is allowed to do
- `Session` - authenticated user session

## Code Style

- Use `jiff` for all time handling (not chrono)
- Use `aws-lc-rs` for crypto (not ring)
- Error handling: `anyhow` for applications, `thiserror` for libraries
- Async runtime: `tokio`
- Web framework: `axum`
- Database: `sqlx` with SQLite

## Current State

The project is scaffolded but not yet functional. Key TODOs:

1. **FIDO2 ceremony** - Wire up `webauthn-rs` in auth handlers
2. **JWT issuance** - Implement session token creation/validation
3. **GitHub integration** - Add `octocrab` and implement token issuance
4. **Agent IPC** - Implement unix socket communication

## Testing Strategy

- Unit tests for vouch-common types
- Integration tests for server handlers (use sqlx test fixtures)
- End-to-end tests for CLI (mock server responses)

## Environment Variables

Server configuration via `VOUCH_*` env vars:

```bash
VOUCH_RP_ID=localhost
VOUCH_RP_ORIGIN=http://localhost:3000
VOUCH_JWT_SECRET=dev-secret-change-in-prod
VOUCH_DATABASE_URL=sqlite:vouch.db?mode=rwc
```

## Security Considerations

- Never log credentials or tokens
- Session tokens are JWTs, store hash in DB not the token itself
- Delegation tokens carry scope - always validate before issuing credentials
- FIDO2 challenges must be single-use and time-limited
