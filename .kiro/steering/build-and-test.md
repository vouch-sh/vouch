# Build and Test

## Prerequisites

- Rust 1.97+ (pinned in `rust-toolchain.toml`)
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
| Fuzz tests (60s each, nightly) | `make test-fuzz` |
| Coverage report | `make test-coverage` |
| Mutation testing | `make test-mutants` |
| Dependency audit | `make audit` |
| Run CLI | `make run` |
| Run server | `make run-server` |
| Run agent | `make run-agent` |
| Build CSS | `make css-build` |
| Watch CSS (dev) | `make css-dev` |
| Docker build | `make docker-build` |
| Docker run | `make docker-run` |
| Musl builds (Docker Bake) | `make bake-cli`, `make bake-server`, `make bake-all` |
| Build docs | `make docs-build` |
| Serve docs | `make docs-serve` |

## Running Specific Tests

```bash
cargo test test_name -- --nocapture        # Single test with output
cargo test --all-features                  # All unit tests (includes feature-gated tests)
cargo test --package vouch-tests           # Integration tests only
```

## FIDO2 Hardware Paths

No automated harness covers CTAP2 paths against real hardware — live-test them by running the CLI:

```bash
cargo run --bin vouch -- login
```

`cargo test` needs no hardware; server-side FIDO2 verification is covered through the `CoseVerifier` seam and `MockFidoDevice`.

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
- `vouch-tests` overrides `expect_used`, `unwrap_used`, `panic`, and `indexing_slicing` clippy lints to allow them in test code.
- The `.env` file at repo root is loaded by the Makefile for server runs.
