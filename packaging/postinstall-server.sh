#!/bin/bash
set -e

# Create vouch system user and group
getent group vouch >/dev/null 2>&1 || groupadd --system vouch
getent passwd vouch >/dev/null 2>&1 || useradd --system --gid vouch --no-create-home --shell /usr/sbin/nologin vouch

# Create data directory
mkdir -p /var/lib/vouch-server
chown vouch:vouch /var/lib/vouch-server
chmod 750 /var/lib/vouch-server

# Create config directory
mkdir -p /etc/vouch-server
chmod 750 /etc/vouch-server

# Grant capability to bind privileged ports (80, 443)
if command -v setcap &> /dev/null; then
    setcap 'cap_net_bind_service=+ep' /usr/bin/vouch-server || true
fi

echo ""
echo "Vouch Server installed successfully!"
echo ""
echo "Configure environment variables in /etc/vouch-server/env"
echo "(or /run/vouch-server/env for dynamic configuration)"
echo ""
echo "To enable the server:"
echo "  sudo systemctl enable --now vouch-server"
echo ""
