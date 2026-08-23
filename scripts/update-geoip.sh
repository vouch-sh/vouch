#!/usr/bin/env bash
set -euo pipefail

# update-geoip.sh - Download latest MaxMind GeoLite2 databases
#
# Usage: ./scripts/update-geoip.sh
#
# Requires a MaxMind account ID and license key. Sign up (free) at:
#   https://www.maxmind.com/en/geolite2/signup
#
# Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in your environment
# or .env file.
#
# Reference: https://dev.maxmind.com/geoip/updating-databases/#directly-downloading-databases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../crates/vouch-server/data"
BASE_URL="https://download.maxmind.com/geoip/databases"

# Load .env if present
ENV_FILE="$SCRIPT_DIR/../.env"
if [[ -f "$ENV_FILE" ]]; then
  while IFS='=' read -r key value; do
    # Skip comments and blank lines
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    export "$key=$value"
  done <"$ENV_FILE"
fi

if [[ -z "${MAXMIND_ACCOUNT_ID:-}" ]]; then
  echo "Error: MAXMIND_ACCOUNT_ID is not set." >&2
  echo "Sign up at https://www.maxmind.com/en/geolite2/signup" >&2
  echo "Then export MAXMIND_ACCOUNT_ID=your_account_id" >&2
  exit 1
fi

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "Error: MAXMIND_LICENSE_KEY is not set." >&2
  echo "Sign up at https://www.maxmind.com/en/geolite2/signup" >&2
  echo "Then export MAXMIND_LICENSE_KEY=your_key" >&2
  exit 1
fi

# Check dependencies
for cmd in curl tar; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' is required but not found in PATH." >&2
    exit 1
  fi
done

sha256_verify() {
  local file="$1" expected="$2"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
  else
    actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: SHA-256 mismatch for $file" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    return 1
  fi
}

download_db() {
  local edition="$1"
  local output="$DATA_DIR/${edition}.mmdb"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' RETURN

  local archive="$tmp_dir/${edition}.tar.gz"
  local checksum_file="$tmp_dir/${edition}.tar.gz.sha256"

  echo "Downloading ${edition}..."

  # Download archive using Basic Auth (account_id:license_key)
  curl -sf -L -o "$archive" \
    -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
    "${BASE_URL}/${edition}/download?suffix=tar.gz"

  # Download SHA-256 checksum
  curl -sf -L -o "$checksum_file" \
    -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
    "${BASE_URL}/${edition}/download?suffix=tar.gz.sha256"

  # Verify checksum
  local expected_hash
  expected_hash=$(cut -d' ' -f1 <"$checksum_file")
  sha256_verify "$archive" "$expected_hash"

  # Extract .mmdb file from the archive
  tar -xzf "$archive" -C "$tmp_dir"
  local mmdb_file
  mmdb_file=$(find "$tmp_dir" -name "${edition}.mmdb" -type f | head -1)
  if [[ -z "$mmdb_file" ]]; then
    echo "Error: ${edition}.mmdb not found in archive." >&2
    return 1
  fi

  cp "$mmdb_file" "$output"
  echo "Updated ${output}"
}

mkdir -p "$DATA_DIR"

download_db "GeoLite2-Country"
download_db "GeoLite2-ASN"

echo "GeoIP databases updated successfully."
