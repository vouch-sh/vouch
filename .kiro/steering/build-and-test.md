# Build and Test

## Prerequisites

- Rust 1.95+ (pinned in `rust-toolchain.toml`)
- TailwindCSS v4 standalone CLI (not npm) for CSS compilation
- Docker for container builds
- System packages (Linux): `libssl-dev`, `libudev-dev`, `cmake`, `golang-go`, `clang`, `pkg-config`

## Environment Variables for aws-lc-rs FIPS

```bash
export AWS_LC_FIPS_SYS_CC=clang
export AWS_LC_FIPS_SYS_CXX=clang++
```

## Key Commands

| Task | Command |
|------|---------|
| Build (release, includes CSS) | `make build` |
| Format | `make fmt` |
| Lint | `make lint` |
| Check | `make check` |
| Unit tests | `make test` |
| Integration tests | `make test-integration` |
| Run CLI | `make run` |
| Run server | `make run-server` |
| Run agent | `make run-agent` |
| Build CSS | `make css-build` |
| Docker build | `make docker-build` |
| Docker run | `make docker-run` |

## Running Specific Tests

```bash
cargo test test_name -- --nocapture   # Single test with output
cargo test --package vouch-tests      # Integration tests only
```

## FIDO2 Tests (require physical YubiKey)

```bash
cargo test --features yubikey-tests -- --ignored
```

## Server Environment (Minimum Viable)

```bash
VOUCH_RP_ID=localhost \
VOUCH_RP_NAME=Vouch \
VOUCH_JWT_SECRET=dev-secret-at-least-32-characters-long \
VOUCH_DATABASE_URL="sqlite:vouch-dev.db?mode=rwc" \
VOUCH_LISTEN_ADDR="[::]:3000" \
RUST_LOG=debug \
cargo run --bin vouch-server
```

At least one upstream IdP is required (`VOUCH_IDPS`); the server refuses to start without one. Configure per-IdP variables with `VOUCH_IDP_<SLUG>_TYPE` plus type-specific vars (see `docs/src/reference/environment-variables.md`).

## Gotchas

- First build is slow (~2-3 min) due to `aws-lc-fips-sys`. Incremental builds are fast.
- Static assets (CSS, fonts, images) are embedded at compile time via `rust-embed`. After changing CSS, rebuild the binary.
- `vouch-tests` overrides strict no-panic clippy lints to allow unwrap/expect in test code.
- The `.env` file at repo root is loaded by the Makefile for server runs.
