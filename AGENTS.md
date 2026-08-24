# AGENTS.md

See `CLAUDE.md` for full project overview, architecture, code conventions, and commands.

## Cloud environment instructions (Cursor Cloud, Claude Code remote)

### System dependencies

The build requires `libssl-dev`, `libudev-dev`, `cmake`, `golang-go`, `clang`, and `pkg-config` on Linux. The `aws-lc-rs` FIPS build also needs these environment variables set:

```
export AWS_LC_FIPS_SYS_CC=clang
export AWS_LC_FIPS_SYS_CXX=clang++
```

These are already configured in `~/.bashrc` on the Cloud VM.

On Claude Code sessions, `.claude/hooks/session-setup.sh` runs at session start and installs the system packages, rustup, the TailwindCSS CLI, and `prek` when missing (each step skips silently if the network policy blocks its download).

### TailwindCSS

The server UI requires the **standalone** TailwindCSS v4 CLI binary (not npm). It is installed at `/usr/local/bin/tailwindcss`. Run `make css-build` before starting the server or building the project. (On Claude Code remote containers, where GitHub release downloads may be blocked, the session hook falls back to installing the same CLI from the npm registry — this does not add a node toolchain to the project.)

### Disk space (Claude Code remote containers)

Writable disk is a fixed per-session allowance, and a full `--all-features` build of this workspace is large. The session hook disables incremental compilation in these containers (`~/.cargo/config.toml`), which roughly halves `target/` (~14 GB vs ~30 GB per full build cycle). On "no space left on device", delete `target/` subdirectories you no longer need — deletes still succeed while writes fail.

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
- `cargo test` needs no hardware. Paths that talk to a physical YubiKey have no automated coverage and are live-tested by running the CLI; server-side verification is tested through the `CoseVerifier` seam and `MockFidoDevice`.
- The `vouch-tests` crate overrides the strict no-panic clippy lints to allow `unwrap()`/`expect()` in test code.
- Static assets (CSS, fonts, images) are embedded at compile time via `rust-embed`. After changing CSS, you must rebuild the binary for changes to take effect.
