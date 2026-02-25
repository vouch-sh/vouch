# Building From Source

Build Vouch from source using Cargo, the Rust package manager.

## Prerequisites

- **Rust** 1.93+ (install via [rustup](https://rustup.rs/))
- **Git**

The exact Rust version is pinned in `rust-toolchain.toml` and will be installed automatically by rustup.

## Build

```bash
# Clone the repository
git clone https://github.com/vouch-sh/vouch.git
cd vouch

# Build release binaries
make build

# Or build directly with cargo
cargo build --release -p vouch-cli -p vouch-agent
```

The binaries will be in `target/release/`:
- `target/release/vouch`
- `target/release/vouch-agent`

## Install

```bash
# Install to ~/.cargo/bin
cargo install --path crates/vouch-cli
cargo install --path crates/vouch-agent
```

Or copy the binaries manually:

```bash
sudo cp target/release/vouch /usr/local/bin/
sudo cp target/release/vouch-agent /usr/local/bin/
```

## Verify Reproducible Build

For Linux builds, you can verify that the binary matches the official release:

```bash
# Clone at the release tag
git clone --branch v0.1.0 https://github.com/vouch-sh/vouch.git
cd vouch

# Set SOURCE_DATE_EPOCH from the commit
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Build with locked dependencies
cargo build --release --locked -p vouch-cli -p vouch-agent

# Compare with official release
sha256sum target/release/vouch
# Should match the hash in the release's SHA256SUMS file
```

> **Note**: macOS binaries will differ due to Apple code signing and notarization.

## Next Steps

- [Your First Enrollment](first-enrollment.md) — Register your YubiKey
- [Quick Start](quick-start.md) — Configure integrations
