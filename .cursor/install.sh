#!/bin/bash
# Cursor Cloud install: prepare the default Ubuntu image to build and gate this
# repo. Counterpart to .claude/hooks/session-setup.sh — same packages and tools,
# but this script must fail the Build if cargo/CSS prep fails (session-setup
# always exits 0). Idempotent; runs from the project root.
set -euo pipefail

[ "$(uname)" = "Linux" ] || {
  echo "Cursor Cloud install is Linux-only" >&2
  exit 1
}

export PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:${PATH}"
if [ -f "${HOME}/.cargo/env" ]; then
  # shellcheck source=/dev/null
  . "${HOME}/.cargo/env"
fi

# session-setup.sh packages (aws-lc-rs FIPS, hidapi, prek shell linters), plus
# curl/ca-certificates/python3-pip that a from-scratch Ubuntu may lack.
pkgs=(
  libudev-dev libssl-dev pkg-config cmake clang golang-go shellcheck shfmt
  curl ca-certificates python3-pip
)
if ! dpkg -s "${pkgs[@]}" >/dev/null 2>&1; then
  sudo apt-get update -qq || true
  sudo apt-get install -y -qq "${pkgs[@]}"
fi

if ! command -v rustup >/dev/null 2>&1 && [ ! -x "${HOME}/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --default-toolchain none
fi
if [ -f "${HOME}/.cargo/env" ]; then
  # shellcheck source=/dev/null
  . "${HOME}/.cargo/env"
fi

# Standalone Tailwind CSS v4 CLI. Pin matches Dockerfile / reusable-build.yml
# (v4.3.3). Prefer GitHub; npm fallback like session-setup.sh.
if ! command -v tailwindcss >/dev/null 2>&1; then
  tw_ver=v4.3.3
  case "$(uname -m)" in
  x86_64)
    tw_arch=x64
    tw_sum=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a
    ;;
  aarch64 | arm64)
    tw_arch=arm64
    tw_sum=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195
    ;;
  *)
    tw_arch=""
    tw_sum=""
    ;;
  esac
  if [ -n "${tw_arch}" ]; then
    tw_tmp=$(mktemp)
    if curl -fsSL --max-time 120 -o "${tw_tmp}" \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${tw_ver}/tailwindcss-linux-${tw_arch}" &&
      echo "${tw_sum}  ${tw_tmp}" | sha256sum -c -; then
      sudo install -m 755 "${tw_tmp}" /usr/local/bin/tailwindcss
    fi
    rm -f "${tw_tmp}"
  fi
  if ! command -v tailwindcss >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    npm install -g --silent @tailwindcss/cli
    (cd "$(dirname "${PWD}")" && npm install --no-save --silent tailwindcss)
  fi
fi
command -v tailwindcss >/dev/null 2>&1

if ! command -v prek >/dev/null 2>&1 && [ ! -x "${HOME}/.local/bin/prek" ]; then
  pip3 install --user --quiet --break-system-packages prek
fi
if [ -x "${HOME}/.local/bin/prek" ] && ! command -v prek >/dev/null 2>&1; then
  sudo ln -sf "${HOME}/.local/bin/prek" /usr/local/bin/prek
fi

ensure_export() {
  key=$1
  val=$2
  export "${key}=${val}"
  touch "${HOME}/.bashrc"
  if grep -qsE "^export ${key}=" "${HOME}/.bashrc"; then
    sed -i -E "s|^export ${key}=.*|export ${key}=${val}|" "${HOME}/.bashrc"
  else
    printf '\nexport %s=%s\n' "${key}" "${val}" >>"${HOME}/.bashrc"
  fi
}

ensure_export AWS_LC_FIPS_SYS_CC clang
ensure_export AWS_LC_FIPS_SYS_CXX clang++
ensure_export CARGO_INCREMENTAL 0

cargo_config="${HOME}/.cargo/config.toml"
mkdir -p "${HOME}/.cargo"
if grep -qsE '^[[:space:]]*incremental[[:space:]]*=' "${cargo_config}"; then
  sed -i -E 's/^([[:space:]]*incremental[[:space:]]*=[[:space:]]*).*/\1false/' \
    "${cargo_config}"
else
  printf '\n[build]\nincremental = false\n' >>"${cargo_config}"
fi

rustup show
cargo fetch --locked
make css-build
