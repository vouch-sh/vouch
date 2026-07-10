#!/bin/bash
# Claude Code SessionStart hook: prepare a fresh container to build and gate this repo.
#
# Every step is idempotent and skips silently when already satisfied or when the
# network policy blocks a download. The hook must never fail the session, so it
# always exits 0. Linux-only; a no-op elsewhere.

[ "$(uname)" = "Linux" ] || exit 0

# System packages: aws-lc-rs (FIPS) and hidapi builds (see AGENTS.md), plus the
# shell linters the prek hooks invoke. dpkg -s fails if ANY package is missing.
pkgs=(libudev-dev libssl-dev pkg-config cmake clang golang-go shellcheck shfmt)
if ! dpkg -s "${pkgs[@]}" >/dev/null 2>&1; then
  # Not &&-chained: a single broken third-party repo makes `update` exit nonzero,
  # but installs from the already-cached indexes still succeed.
  sudo apt-get update -qq >/dev/null 2>&1 || true
  sudo apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
fi

# Rust toolchain manager. rust-toolchain.toml pins the actual toolchain, which
# rustup fetches on first cargo invocation.
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --default-toolchain none >/dev/null 2>&1
fi

# TailwindCSS CLI, required by `make css-build` (and thus build/run-server).
# Prefer the standalone binary (repo policy); fall back to the npm registry,
# which stays reachable when github.com egress is restricted to session repos.
if ! command -v tailwindcss >/dev/null 2>&1; then
  case "$(uname -m)" in
  x86_64) tw_arch=x64 ;;
  aarch64 | arm64) tw_arch=arm64 ;;
  *) tw_arch="" ;;
  esac
  if [ -n "$tw_arch" ]; then
    tw_tmp=$(mktemp)
    if curl -fsSL --max-time 120 -o "$tw_tmp" \
      "https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-${tw_arch}" \
      >/dev/null 2>&1; then
      sudo install -m 755 "$tw_tmp" /usr/local/bin/tailwindcss >/dev/null 2>&1
    fi
    rm -f "$tw_tmp"
  fi
  if ! command -v tailwindcss >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    npm install -g --silent @tailwindcss/cli >/dev/null 2>&1
    # Unlike the standalone binary, the npm CLI resolves `@import "tailwindcss"`
    # by walking node_modules up from the input CSS file, so the package must
    # also be installed. Put it in the checkout's parent directory: that is on
    # the resolution path but keeps the repo working tree clean (--no-save
    # writes no package.json there either).
    (cd "$(dirname "$PWD")" && npm install --no-save --silent tailwindcss >/dev/null 2>&1)
  fi
fi

# prek, required by the pre-PR gate (see .claude/rules/branching.md). PyPI ships
# prebuilt binaries and stays reachable when github.com egress is restricted.
if ! command -v prek >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/prek" ]; then
  pip3 install --user --quiet prek >/dev/null 2>&1
fi
if [ -x "$HOME/.local/bin/prek" ] && ! command -v prek >/dev/null 2>&1; then
  sudo ln -sf "$HOME/.local/bin/prek" /usr/local/bin/prek >/dev/null 2>&1
fi

# Claude remote-execution containers only (detected by the agent-proxy config
# directory). These tweaks must not touch local developer machines.
if [ -d /root/.ccr ]; then
  # Incremental compilation roughly doubles target/ (~30 GB vs ~14 GB for a full
  # --all-features cycle) and has little value in a container that starts cold,
  # while the session's disk allowance is fixed.
  cargo_config="$HOME/.cargo/config.toml"
  if ! grep -qs 'incremental' "$cargo_config"; then
    mkdir -p "$HOME/.cargo"
    printf '\n[build]\nincremental = false\n' >>"$cargo_config"
  fi

  # git uses one program (gpg.ssh.program) for both signing and verification, but
  # the provisioned signer implements only "-Y sign", so locally every signed
  # commit reports as unverifiable (%G? = N/E) and the stop hook flags good
  # commits. Route verification subcommands to the real ssh-keygen instead; the
  # allowed-signers file is already provisioned.
  # Read config unscoped: the signer program is global but the allowed-signers
  # file is provisioned in the repo-local .git/config (cwd is the project root
  # when SessionStart hooks run).
  shim=/usr/local/bin/git-ssh-sign-shim
  sign_prog=$(git config --get gpg.ssh.program 2>/dev/null)
  signers=$(git config --get gpg.ssh.allowedSignersFile 2>/dev/null)
  if [ "$(git config --get gpg.format 2>/dev/null)" = "ssh" ] &&
    { [ "$sign_prog" = "/tmp/code-sign" ] || [ "$sign_prog" = "$shim" ]; } &&
    [ -f "$signers" ] && [ -e /tmp/code-sign ] &&
    command -v ssh-keygen >/dev/null 2>&1; then
    cat >"$shim" <<'EOF'
#!/bin/sh
# Route git SSH signing to the provisioned signer and everything else
# (-Y verify, -Y find-principals, ...) to the real ssh-keygen.
if [ "$1" = "-Y" ] && [ "$2" = "sign" ]; then
  exec /tmp/code-sign "$@"
fi
exec ssh-keygen "$@"
EOF
    chmod 755 "$shim"
    git config --global gpg.ssh.program "$shim"
  fi
fi

exit 0
