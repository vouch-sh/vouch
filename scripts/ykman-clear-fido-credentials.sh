#!/usr/bin/env bash
set -euo pipefail

# ykman-clear-fido-credentials.sh - Remove all FIDO2 discoverable credentials from a YubiKey
#
# Usage: ./ykman-clear-fido-credentials.sh
#
# Requires: ykman (YubiKey Manager CLI)
# Prompts for FIDO2 PIN, then deletes every discoverable credential.

if ! command -v ykman &>/dev/null; then
  echo "Error: 'ykman' is required but not found in PATH." >&2
  echo "Install with: brew install ykman" >&2
  exit 1
fi

read -rsp "Enter FIDO2 PIN: " PIN
echo

# Output format: <credential_id> <rp_id> <username> <display_name>
# First line is a header row
CREDS=$(ykman fido credentials list --pin "$PIN") || {
  echo "Error: Failed to list credentials." >&2
  exit 1
}

if [[ -z "$CREDS" ]]; then
  echo "No discoverable credentials found."
  exit 0
fi

echo "Credentials to delete:"
echo "$CREDS"
echo

read -rp "Delete all? [y/N] " CONFIRM
case "$CONFIRM" in
y | Y) ;;
*)
  echo "Aborted."
  exit 0
  ;;
esac

# Skip the header line, extract credential ID (first field)
echo "$CREDS" | tail -n +2 | while IFS= read -r line; do
  cred_id=$(echo "$line" | awk '{print $1}')
  ykman fido credentials delete "$cred_id" --pin "$PIN" --force
  echo "Deleted: $line"
done

echo "Done."
