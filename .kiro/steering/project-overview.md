# Project Overview

## What is Vouch?

Vouch is a hardware-backed authentication system that issues short-lived credentials after FIDO2 verification with a YubiKey. The core principle: no credential issuance without human presence proof.

One touch, one PIN, one 8-hour session -- then SSH, AWS, Kubernetes, Git, Docker, and more just work.

## Architecture

Vouch is a Rust workspace with these crates:

| Crate | Role |
|-------|------|
| `vouch-cli` | User-facing CLI binary (commands, credential helpers, integrations) |
| `vouch-agent` | Background daemon for session/cert management (Unix socket IPC) |
| `vouch-common` | Shared types, FIDO2 helpers, API client |
| `vouch-server` | Auth server with OIDC provider, SSH CA, SCIM |
| `vouch-httpsig` | HTTP Message Signatures (RFC 9421) |
| `vouch-tests` | Integration and property-based tests |

## Key Flows

1. `vouch enroll` - Browser OIDC flow, WebAuthn registration, CLI receives OAuth access token
2. `vouch login` - FAPI 2.0: /oauth/fido2/challenge, CTAP2 getAssertion, /oauth/token (FIDO2 grant + DPoP)
3. `vouch register` - (requires login) FIDO2 makeCredential to add additional keys
4. `vouch credential ssh` - Exchange access token for SSH certificate
5. `vouch credential aws` - Exchange access token for AWS temporary credentials
6. Native tools (ssh, aws, kubectl) call vouch helpers transparently via `credential_process`

## Agent IPC

The CLI communicates with the agent daemon over a Unix socket (`~/.vouch/agent.sock`) using JSON-RPC 2.0 with 4-byte length-prefixed messages.

## Server Architecture

Two route groups sharing `AppState`:
- **API routes** (`/v1/`, `/oauth/`, `/scim/`, `/api/v1/`) - JSON responses, JWT Bearer auth
- **UI routes** (`/`, `/login`, `/enroll/*`, `/docs/*`, `/applications/*`) - HTML via Askama templates, cookie-based sessions

**Database:** SQLite for local development, in-memory SQLite for tests, Aurora DSQL in production. The `Pool` enum dispatches at runtime based on `DATABASE_URL` scheme. Query building uses `sea-query`. Migrations in `crates/vouch-server/migrations/{sqlite,postgres}/`.

The data model is document-oriented by design:
- Minimizes schema migrations (important for a multi-tenant production service)
- Supports client-side encryption via HPKE (Hybrid Public Key Encryption) -- encrypted document payloads stored as opaque blobs
- Maintains indexes on non-encrypted fields for query performance
- Supports document expiration (TTL) for automatic cleanup of short-lived records (sessions, nonces, etc.)

**Services layer** (`crates/vouch-server/src/services/`): Business logic -- `oidc/`, `integrations/`, `auth.rs`.

## Toolchain

- Rust 1.95.0, edition 2024 (pinned in `rust-toolchain.toml`)
- Max line width: 100 chars (`.rustfmt.toml`)
- Release profile: `lto = true`, `codegen-units = 1`, `opt-level = "z"`, `panic = "abort"`, `strip = true`

## License

All crates: Apache-2.0 OR MIT (dual-licensed).
