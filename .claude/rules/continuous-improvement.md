# Continuous Improvement

Project-specific instructions for the continuous improvement cycle.
This file is read by the `rust-ci-analyst` agent and the `/rust-agents:continuous-improvement` skill.

## Test Configuration

Vouch is a workspace of three binaries (server, CLI, agent) plus shared library crates. Run via `make`:

```bash
make run-server   # server; loads .env, builds CSS first
make run          # CLI with RUST_LOG=debug
make run-agent    # agent daemon in foreground
```

The server refuses to start without an upstream IdP and core secrets. Minimum env:

```bash
VOUCH_IDPS=<slug> VOUCH_IDP_<SLUG>_*=...   # at least one upstream IdP
VOUCH_RP_ID=localhost
VOUCH_JWT_SECRET=...
VOUCH_DATABASE_URL=sqlite://.local/testing/data/test.db
```

See `docs/src/reference/environment-variables.md` for the full reference, and `AGENTS.md` for a minimum viable command.

For debug output:

```bash
RUST_LOG=debug make run-server 2>.local/testing/debug/session.log
```

## Project Subsystems

Workspace crates: `vouch-cli`, `vouch-agent`, `vouch-server`, `vouch-common`, `vouch-httpsig`, `vouch-i18n`, `vouch-tests`.

Logical subsystems to track in `coverage-status.md`:

- **OIDC provider** — authorization, token issuance, DPoP, discovery, JWKS, token exchange, per-org issuer keys + operator rotation (`services/oidc/`)
- **FIDO2 / WebAuthn** — challenge → CTAP2 getAssertion → verification (`crypto/webauthn_verify.rs`, `services/auth.rs`)
- **SSH CA** — Ed25519 certificate signing (`crypto/ssh_ca.rs`)
- **Credential helpers** — ssh, aws, eks, k8s, github, docker, cargo, rds, redshift, ssm, WIF (`vouch-cli/src/commands/credential/`)
- **DB pool abstraction** — SQLite / PostgreSQL / Aurora DSQL dispatch (`db/pool.rs`), OCC + DSQL retry
- **HTTP message signing** — RFC 9421 / RFC 9530 over `/v1/*` (`vouch-httpsig`, `infra/httpsig.rs`)
- **SCIM 2.0** provisioning, **GitHub App/OAuth/webhooks** integrations (`services/integrations/`)
- **Agent IPC** — Unix-socket JSON-RPC + SSH agent protocol (`vouch-agent/src/`)
- **i18n** — shared Fluent core + per-binary catalogs (`vouch-i18n`)

## Interfaces

Cross-interface consistency matters most for credential output and error messages:

- CLI: `make run` (`vouch <command>`)
- Agent: Unix-socket JSON-RPC (`$XDG_RUNTIME_DIR/vouch/agent.sock`) + SSH agent protocol
- Server API: `/v1/`, `/oauth/`, `/scim/`, `/api/v1/` — JSON, JWT Bearer
- Server UI: `/`, `/login`, `/enroll/*`, `/applications/*` — HTML (Askama), cookie sessions
- Native tool integration: ssh / aws / kubectl invoking vouch helpers via `credential_process`

## Critical Paths

Must be live-tested before any PR that touches them (silent breakage not caught by unit tests):

- OIDC token issuance, DPoP binding, and access-token validation (ES256)
- FIDO2 assertion challenge/verification flow (`vouch login`)
- Credential exchange: `vouch credential ssh` / `aws` / `setup eks`
- RFC 9421 request signing/verification on `/v1/*`
- DB migrations and queries across all three backends (SQLite, PostgreSQL, Aurora DSQL)
- Config parsing/validation and `validate_startup` (i18n catalogs, IdP config)

## Environment Setup

- **Database:** SQLite at `.local/testing/data/test.db` for local cycles; PostgreSQL/DSQL exercised in integration/CI.
- **Upstream IdP:** at least one configured via `VOUCH_IDPS` / `VOUCH_IDP_<SLUG>_*` (server won't boot otherwise).
- **YubiKey:** physical device required for FIDO2 tests — `cargo test --features yubikey-tests -- --ignored`. Without hardware these paths are **Blocked**, not Untested.
- **Fuzzing:** `make test-fuzz` requires the nightly toolchain.

## Reference Projects

- **Amazon Midway** (`https://midway-auth.amazon.com`) — inspiration for hardware-backed auth; watch enrollment UX and credential lifetime model.
- **FAPI 2.0 conformance suite** (`vouch-sh/conformance`, external repo) — tracks `/oauth/*` JAR/JARM/ES256 conformance; does not cover the `vouch-httpsig` `/v1/*` RFC 9421 layer.

## Testing Notes

- `make test` uses `--all-features` so feature-gated tests (e.g. axum middleware) are included — don't drop the flag.
- The **no-panic policy** is enforced by clippy (`unwrap`/`expect`/`panic`/`[]`/`as` denied outside `vouch-tests`); treat lint failures as test failures.
- Single test with output: `cargo test <name> -- --nocapture`.
- Mutation testing (`make test-mutants`) and coverage (`make test-coverage`) are available but slow — run targeted, not every cycle.
