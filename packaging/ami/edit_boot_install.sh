#!/bin/bash
#
# UKI Signing & PCR Measurement Script for KIWI-NG
# -------------------------------------------------
#
# Description:
#   This script is called by KIWI-NG during the image creation process.
#   It locates the UKI (kiwi.efi) in the EFI/Linux directory, moves it
#   to the EFI/BOOT directory, renames it to the standard boot filename
#   (e.g., BOOTX64.EFI), signs it with the Secure Boot DB key (if
#   available), and uses nitro-tpm-pcr-compute to calculate PCR4 and
#   PCR7 values. It also computes PCR12 (kernel command line).
#
# Based on:
#   https://github.com/amazonlinux/kiwi-image-descriptions-examples/tree/main/kiwi-image-descriptions-examples/al2023/attestable-image-example
#
# Usage:
#   Add to KIWI config:
#   <type ... editbootinstall="edit_boot_install.sh">
#
# Parameters (automatically passed by KIWI):
#   $1: Path to the raw disk image
#   $2: Root partition device (e.g., /dev/loop0p2)
#
# Environment:
#   DB_KEY: Path to Secure Boot DB private key (optional, skips signing if absent)
#   DB_CRT: Path to Secure Boot DB certificate (optional, skips signing if absent)
#
# Output:
#   - Saves PCR measurements to <TARGET-DIR>/pcr_measurements.json in the build directory
#   - Kiwi execution stops in the case of failure
#

set -e -o pipefail

disk_image="$1"
root_device="$2"

build_dir=$(dirname "$disk_image")
pcr_values_file="$build_dir/pcr_measurements.json"

if [ ! -b "$root_device" ]; then
    echo "ERROR: Root device not found at: $root_device"
    exit 1
fi

root_mount=$(findmnt -n -o TARGET "$root_device")
echo "INFO: Root partition ($root_device) mounted at: $root_mount"

efi_mount="${root_mount}/boot/efi"
echo "INFO: Checking EFI partition at: $efi_mount"

if ! mountpoint -q "$efi_mount"; then
    echo "ERROR: EFI partition not mounted at: $efi_mount"
    exit 1
fi

EFI_BINARY=$(find "$efi_mount/EFI/BOOT/" -name "BOOT*.EFI" -printf "%f\n" 2>/dev/null | head -n1)

if [ -z "$EFI_BINARY" ]; then
    echo "ERROR: Could not find BOOT*.EFI in $efi_mount/EFI/BOOT/"
    exit 1
fi

if [ -f "$efi_mount/EFI/Linux/kiwi.efi" ]; then
    echo "INFO: Found kiwi.efi at: $efi_mount/EFI/Linux/kiwi.efi"

    echo "INFO: Removing existing $EFI_BINARY"
    rm -f "$efi_mount/EFI/BOOT/$EFI_BINARY"

    echo "INFO: Moving kiwi.efi to $EFI_BINARY location"
    cp "$efi_mount/EFI/Linux/kiwi.efi" "$efi_mount/EFI/BOOT/$EFI_BINARY"

    echo "INFO: Removing /EFI/Linux directory"
    rm -rf "$efi_mount/EFI/Linux"

    if [ -d "$efi_mount/EFI/systemd" ]; then
        echo "INFO: Removing /EFI/systemd directory"
        rm -rf "$efi_mount/EFI/systemd"
    fi

    # --- Secure Boot signing ---
    # Sign the UKI with the DB key BEFORE computing PCR measurements
    # so that PCR4 reflects the signed binary.
    DB_KEY="${DB_KEY:-}"
    DB_CRT="${DB_CRT:-}"

    if [ -n "$DB_KEY" ] && [ -n "$DB_CRT" ] && [ -f "$DB_KEY" ] && [ -f "$DB_CRT" ]; then
        echo "INFO: Signing UKI with Secure Boot DB key"
        UKI_PATH="$efi_mount/EFI/BOOT/$EFI_BINARY"
        SIGNED_UKI="${UKI_PATH}.signed"

        if sbsign --key "$DB_KEY" --cert "$DB_CRT" --output "$SIGNED_UKI" "$UKI_PATH"; then
            mv "$SIGNED_UKI" "$UKI_PATH"
            echo "SUCCESS: UKI signed with Secure Boot DB key"
        else
            echo "ERROR: Failed to sign UKI with sbsign"
            exit 1
        fi
    else
        echo "WARNING: Secure Boot DB key/cert not found, skipping UKI signing"
        echo "  DB_KEY=${DB_KEY:-<not set>}"
        echo "  DB_CRT=${DB_CRT:-<not set>}"
    fi

    # --- PCR4 and PCR7 measurement ---
    if sudo "$root_mount/usr/bin/nitro-tpm-pcr-compute" \
        --image "$efi_mount/EFI/BOOT/$EFI_BINARY" | tee "$pcr_values_file"; then
        echo "SUCCESS: PCR4/PCR7 measurements computed and saved to: $pcr_values_file"
    else
        echo "ERROR: Failed to compute PCR measurements for UKI"
        exit 1
    fi

    # --- PCR12 computation (kernel command line) ---
    # PCR12 records the kernel command line embedded in the UKI.
    # Extract the .cmdline section, hash it, and simulate a PCR extend
    # from the initial all-zeros state.
    echo "INFO: Computing PCR12 (kernel command line)"
    CMDLINE_BIN=$(mktemp)
    UKI_PATH="$efi_mount/EFI/BOOT/$EFI_BINARY"

    if objcopy -O binary -j .cmdline "$UKI_PATH" "$CMDLINE_BIN" 2>/dev/null; then
        # SHA-256 hash of the command line content
        CMDLINE_HASH=$(sha256sum "$CMDLINE_BIN" | cut -d' ' -f1)
        echo "INFO: Kernel command line SHA-256: $CMDLINE_HASH"

        # Simulate PCR extend: SHA-256(32_zero_bytes || cmdline_hash)
        # Initial PCR state is 32 zero bytes (SHA-256 bank)
        ZERO_PCR="0000000000000000000000000000000000000000000000000000000000000000"
        PCR12=$(printf '%s%s' "$ZERO_PCR" "$CMDLINE_HASH" | xxd -r -p | sha256sum | cut -d' ' -f1)
        echo "INFO: PCR12 value: $PCR12"

        # Merge PCR12 into the measurements JSON
        python3 -c "
import json, sys
with open('$pcr_values_file', 'r') as f:
    data = json.load(f)
data['PCR12'] = '$PCR12'
with open('$pcr_values_file', 'w') as f:
    json.dump(data, f, indent=2)
print('SUCCESS: PCR12 merged into', '$pcr_values_file')
"
    else
        echo "WARNING: Could not extract .cmdline section from UKI, skipping PCR12"
    fi
    rm -f "$CMDLINE_BIN"
else
    echo "ERROR: UKI not found at expected location: $efi_mount/EFI/Linux/kiwi.efi"
    echo "DEBUG: Current EFI directory contents:"
    ls -R "$efi_mount/EFI/"
    exit 1
fi
