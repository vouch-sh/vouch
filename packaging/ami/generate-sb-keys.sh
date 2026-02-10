#!/bin/bash
#
# UEFI Secure Boot Key Generation Script
# ----------------------------------------
#
# Description:
#   One-time script run offline by a security operator to generate the full
#   UEFI Secure Boot key hierarchy for AMI builds:
#
#   - PK (Platform Key): Signs KEK updates. Stored in 1Password.
#   - KEK (Key Exchange Key): Signs DB updates. Stored in 1Password.
#   - DB (Signature Database): Signs UKI binaries. Private key stored as
#     GitHub Actions secret SECUREBOOT_DB_KEY.
#
#   Generates EFI Signature Lists (.esl), signed auth files (.auth),
#   and a UEFI variable store blob (base64-encoded) for use with
#   aws ec2 register-image --uefi-data.
#
# Prerequisites (Linux only):
#   - efitools (for cert-to-efi-sig-list, sign-efi-sig-list)
#   - openssl
#   - python3 + uefivars (pip install uefivars)
#
# Usage:
#   # On Linux directly:
#   ./generate-sb-keys.sh [output-dir]
#
#   # On macOS (via Docker):
#   ./generate-sb-keys.sh --docker [output-dir]
#
# Output:
#   output-dir/
#     PK.key, PK.crt         - Platform Key (KEEP PRIVATE)
#     KEK.key, KEK.crt       - Key Exchange Key (KEEP PRIVATE)
#     DB.key, DB.crt         - Signature Database Key (DB.key is secret)
#     PK.esl, KEK.esl, DB.esl - EFI Signature Lists
#     PK.auth, KEK.auth, DB.auth - Signed auth variables
#     uefi-vars.b64          - Base64-encoded UEFI variable store (AWS format)
#
# After running:
#   1. Store PK.key and KEK.key in 1Password
#   2. Store DB.key as GitHub Actions secret SECUREBOOT_DB_KEY
#   3. Copy PK.crt, KEK.crt, DB.crt, *.esl, uefi-vars.b64 to
#      packaging/ami/secureboot/ and commit
#   4. Securely delete the output directory

set -euo pipefail

# --- Docker mode ---
# efitools is Linux-only. On macOS, re-exec this script inside a container.

if [ "${1:-}" = "--docker" ]; then
    shift
    OUTPUT_DIR="${1:-./secureboot-keys}"
    mkdir -p "$OUTPUT_DIR"
    ABS_OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

    echo "=== Running in Docker (efitools is Linux-only) ==="
    echo "Script: $SCRIPT_DIR/generate-sb-keys.sh"
    echo "Output: $ABS_OUTPUT_DIR"
    docker run --rm \
        -v "$SCRIPT_DIR/generate-sb-keys.sh:/generate-sb-keys.sh:ro" \
        -v "$ABS_OUTPUT_DIR:/output" \
        ubuntu:24.04 \
        bash -eux -c '
            apt-get update -qq
            apt-get install -y -qq efitools openssl python3 python3-pip 2>&1 | tail -1
            pip install --break-system-packages uefivars 2>&1 | tail -1
            bash /generate-sb-keys.sh /output
        '
    echo ""
    echo "Output written to: ${OUTPUT_DIR}/"
    ls -la "${OUTPUT_DIR}/"
    exit 0
fi

# --- Native mode (Linux) ---

OUTPUT_DIR="${1:-./secureboot-keys}"
GUID="$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"
SUBJECT_PREFIX="/CN=Vouch Secure Boot"
VALIDITY_DAYS=3650  # ~10 years

echo "=== Vouch UEFI Secure Boot Key Generation ==="
echo "Output directory: ${OUTPUT_DIR}"
echo "Owner GUID: ${GUID}"
echo ""

# Check prerequisites
for cmd in openssl cert-to-efi-sig-list sign-efi-sig-list; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command not found: $cmd"
        echo ""
        echo "On macOS, run with --docker flag instead:"
        echo "  ./generate-sb-keys.sh --docker [output-dir]"
        echo ""
        echo "On Linux, install dependencies:"
        echo "  apt install efitools openssl"
        echo "  pip install uefivars"
        exit 1
    fi
done

if ! command -v uefivars &>/dev/null; then
    echo "ERROR: uefivars not found. Install with: pip install uefivars"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# --- Generate Key Pairs ---

echo "=== Generating RSA-4096 key pairs ==="

for name in PK KEK DB; do
    echo "Generating ${name} key pair..."
    openssl req -new -x509 \
        -newkey rsa:4096 \
        -sha256 \
        -days "${VALIDITY_DAYS}" \
        -nodes \
        -subj "${SUBJECT_PREFIX} ${name}" \
        -keyout "${OUTPUT_DIR}/${name}.key" \
        -out "${OUTPUT_DIR}/${name}.crt"
    chmod 600 "${OUTPUT_DIR}/${name}.key"
done

echo ""

# --- Generate EFI Signature Lists ---

echo "=== Generating EFI Signature Lists ==="

for name in PK KEK DB; do
    echo "Creating ${name}.esl..."
    cert-to-efi-sig-list -g "${GUID}" \
        "${OUTPUT_DIR}/${name}.crt" \
        "${OUTPUT_DIR}/${name}.esl"
done

echo ""

# --- Generate Signed Auth Variables ---

echo "=== Generating signed .auth variables ==="

# PK signs itself
echo "Signing PK.auth (self-signed)..."
sign-efi-sig-list -g "${GUID}" \
    -k "${OUTPUT_DIR}/PK.key" \
    -c "${OUTPUT_DIR}/PK.crt" \
    PK \
    "${OUTPUT_DIR}/PK.esl" \
    "${OUTPUT_DIR}/PK.auth"

# PK signs KEK
echo "Signing KEK.auth (signed by PK)..."
sign-efi-sig-list -g "${GUID}" \
    -k "${OUTPUT_DIR}/PK.key" \
    -c "${OUTPUT_DIR}/PK.crt" \
    KEK \
    "${OUTPUT_DIR}/KEK.esl" \
    "${OUTPUT_DIR}/KEK.auth"

# KEK signs DB
echo "Signing DB.auth (signed by KEK)..."
sign-efi-sig-list -g "${GUID}" \
    -k "${OUTPUT_DIR}/KEK.key" \
    -c "${OUTPUT_DIR}/KEK.crt" \
    db \
    "${OUTPUT_DIR}/DB.esl" \
    "${OUTPUT_DIR}/DB.auth"

echo ""

# --- Generate UEFI Variable Store ---

echo "=== Generating UEFI variable store ==="

uefivars -i none -o aws \
    -P "${OUTPUT_DIR}/PK.esl" \
    -K "${OUTPUT_DIR}/KEK.esl" \
    -b "${OUTPUT_DIR}/DB.esl" \
    -O "${OUTPUT_DIR}/uefi-vars.b64"

echo ""

# --- Summary ---

echo "=== Key Generation Complete ==="
echo ""
echo "Generated files:"
ls -la "${OUTPUT_DIR}/"
echo ""
echo "IMPORTANT - Next steps:"
echo ""
echo "  1. Store PK.key and KEK.key in 1Password:"
echo "     op document create ${OUTPUT_DIR}/PK.key --title 'Vouch Secure Boot PK' --vault 'Engineering'"
echo "     op document create ${OUTPUT_DIR}/KEK.key --title 'Vouch Secure Boot KEK' --vault 'Engineering'"
echo ""
echo "  2. Add DB.key as GitHub Actions secret:"
echo "     gh secret set SECUREBOOT_DB_KEY -R vouch-sh/vouch < ${OUTPUT_DIR}/DB.key"
echo ""
echo "  3. Copy public artifacts to repo:"
echo "     cp ${OUTPUT_DIR}/{PK,KEK,DB}.crt packaging/ami/secureboot/"
echo "     cp ${OUTPUT_DIR}/{PK,KEK,DB}.esl packaging/ami/secureboot/"
echo "     cp ${OUTPUT_DIR}/uefi-vars.b64 packaging/ami/secureboot/"
echo ""
echo "  4. Commit the public artifacts"
echo ""
echo "  5. Securely delete this output directory:"
echo "     rm -rf ${OUTPUT_DIR}"
echo ""
echo "Owner GUID (save for key rotation): ${GUID}"
