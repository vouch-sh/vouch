# AGENTS.md

See `CLAUDE.md` for full project overview, architecture, code conventions, and commands.

## Cursor Cloud specific instructions

### System dependencies

The build requires `libssl-dev`, `libudev-dev`, `cmake`, `golang-go`, `clang`, and `pkg-config` on Linux. The `aws-lc-rs` FIPS build also needs these environment variables set:

```
export AWS_LC_FIPS_SYS_CC=clang
export AWS_LC_FIPS_SYS_CXX=clang++
```

These are already configured in `~/.bashrc` on the Cloud VM.

### TailwindCSS

The server UI requires the **standalone** TailwindCSS v4 CLI binary (not npm). It is installed at `/usr/local/bin/tailwindcss`. Run `make css-build` before starting the server or building the project.

### Running the server locally

The server needs a few environment variables to start. Minimum viable command:

```bash
VOUCH_RP_ID=localhost \
VOUCH_RP_NAME=Vouch \
VOUCH_JWT_SECRET=dev-secret-at-least-32-characters-long \
VOUCH_DATABASE_URL="sqlite:vouch-dev.db?mode=rwc" \
VOUCH_LISTEN_ADDR="[::]:3000" \
RUST_LOG=debug \
cargo run --bin vouch-server
```

The server will listen on port 3000 and create a SQLite database file at `vouch-dev.db`. At least one upstream IdP must be configured via `VOUCH_IDPS` (the server refuses to start without one). See the [Environment Variables reference](docs/src/reference/environment-variables.md) for the `VOUCH_IDPS` / `VOUCH_IDP_<SLUG>_*` variables.

### Key commands

All standard commands are in the `Makefile`. Noteworthy:

| Task | Command |
|------|---------|
| Format check | `make fmt` (or `cargo fmt --all --check`) |
| Lint | `make lint` |
| Unit tests | `make test` |
| Integration tests | `make test-integration` |
| Build (release) | `make build` |
| Run server | `make run-server` (loads `.env` if present) |
| Build CSS | `make css-build` |

### Gotchas

- The first `cargo build` / `cargo test` is slow (~2-3 min) due to `aws-lc-fips-sys` compilation. Subsequent incremental builds are fast.
- `cargo test` runs all workspace tests except FIDO2 hardware tests (those require `--features yubikey-tests -- --ignored` and a physical YubiKey).
- The `vouch-tests` crate overrides the strict no-panic clippy lints to allow `unwrap()`/`expect()` in test code.
- Static assets (CSS, fonts, images) are embedded at compile time via `rust-embed`. After changing CSS, you must rebuild the binary for changes to take effect.
