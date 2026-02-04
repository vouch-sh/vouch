#!/bin/bash
# KIWI-NG config.sh - runs during image build
# Note: Static files are provided via the root/ overlay directory
#
# Based on:
#   https://github.com/amazonlinux/kiwi-image-descriptions-examples/tree/main/kiwi-image-descriptions-examples/al2023/attestable-image-example
set -ex

#======================================
# Enable set-hostname-imds service
#======================================
# This sets the hostname based on IMDS in place of cloud-init
echo "enable set-hostname-imds.service" >> /usr/lib/systemd/system-preset/80-amzn-overrides.preset
systemctl preset set-hostname-imds

#======================================
# Create vouch system user
#======================================
groupadd --system vouch || true
useradd --system --gid vouch --no-create-home --shell /usr/sbin/nologin vouch || true
mkdir -p /var/lib/vouch-server
chown vouch:vouch /var/lib/vouch-server
chmod 750 /var/lib/vouch-server

#======================================
# Set permissions on overlay files
#======================================
# The overlay copies files but doesn't preserve execute permissions
chmod +x /usr/local/bin/vouch-fetch-config.sh

#======================================
# Enable services
#======================================
systemctl enable vouch-config.service
systemctl enable vouch-server.service

#======================================
# Disable unnecessary services
#======================================
# Ensure no SSH or remote access is available
systemctl disable sshd.service 2>/dev/null || true
systemctl mask sshd.service 2>/dev/null || true

#======================================
# Harden the system
#======================================
# Disable root login
passwd -l root

# Remove any existing SSH host keys (shouldn't exist, but be safe)
rm -f /etc/ssh/ssh_host_*

echo "Vouch Server image configuration complete"
