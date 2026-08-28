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
echo "enable set-hostname-imds.service" >>/usr/lib/systemd/system-preset/80-amzn-overrides.preset
systemctl preset set-hostname-imds

#======================================
# Create vouch system user
#======================================
groupadd --system vouch || true
useradd --system --gid vouch --home-dir /var/lib/vouch-server --no-create-home --shell /usr/sbin/nologin vouch || true
usermod -a -G tss vouch

#======================================
# Verify vouch-server binary
#======================================
if [ ! -x /usr/bin/vouch-server ]; then
  echo "ERROR: /usr/bin/vouch-server not found or not executable"
  exit 1
fi

#======================================
# Set vouch home directory permissions
#======================================
chown vouch:vouch /var/lib/vouch-server
chmod 750 /var/lib/vouch-server
chmod 0600 /var/lib/vouch-server/.pgpass
chown vouch:vouch /var/lib/vouch-server/.pgpass

#======================================
# CloudWatch agent journald access
#======================================
# Nothing on this image logs to a file: vouch-server writes to the journal, and
# the CloudWatch agent streams the journal off the instance. The agent runs as
# cwagent (run_as_user in amazon-cloudwatch-agent.json), and a non-root reader
# needs systemd-journal group membership to open the journal.
usermod -a -G systemd-journal cwagent

#======================================
# Enable services
#======================================
systemctl enable vouch-server.service
systemctl enable amazon-cloudwatch-agent.service

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

#======================================
# Enable FIPS crypto-policy
#======================================
# fips-mode-setup --enable cannot run here: there is no grubby and the kernel
# cmdline is baked into the signed UKI. Its effects are reproduced as:
#   1. fips=1 on the kernelcmdline (appliance.kiwi)
#   2. the FIPS crypto-policy set below
# The dracut fips module is deliberately NOT included: its kernel HMAC check
# expects /boot/vmlinuz-<ver> + .hmac, which do not exist in the UKI layout,
# and the failed check powers the instance off (rd.shell=0). Kernel integrity
# is enforced by Secure Boot UKI signing and dm-verity instead, and the
# kernel still runs its FIPS self-tests with fips=1.
update-crypto-policies --no-reload --set FIPS
CURRENT_POLICY=$(update-crypto-policies --show)
if [ "$CURRENT_POLICY" != "FIPS" ]; then
  echo "ERROR: crypto-policy is '${CURRENT_POLICY}', expected 'FIPS'"
  exit 1
fi

#======================================
# Verify kernel hardening drop-in
#======================================
# STIG-aligned sysctl settings are provided via the root/ overlay. Values are
# applied at boot by systemd-sysctl; here we only assert the file is present so
# a missing overlay fails the build instead of silently shipping unhardened.
if [ ! -f /etc/sysctl.d/90-vouch-hardening.conf ]; then
  echo "ERROR: /etc/sysctl.d/90-vouch-hardening.conf not found"
  exit 1
fi

echo "Vouch Server image configuration complete"
