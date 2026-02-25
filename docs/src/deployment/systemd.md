# Systemd (Bare Metal)

Deploy Vouch as a systemd service on bare metal servers or VMs.

## Install via Package

The RPM and DEB packages include a systemd service unit:

```bash
# RPM (RHEL/Fedora/Amazon Linux)
rpm -ivh vouch-server-1.0.0-1.x86_64.rpm

# DEB (Debian/Ubuntu)
dpkg -i vouch-server_1.0.0_amd64.deb
```

The package installs:
- Binary at `/usr/bin/vouch-server`
- Systemd unit at `/etc/systemd/system/vouch-server.service`
- Default config at `/etc/vouch/vouch.env`
- Data directory at `/data` (with appropriate permissions)

## Configure

Edit the environment file:

```bash
sudo cp /etc/vouch/vouch.env /etc/vouch/vouch.env.local
sudo chmod 600 /etc/vouch/vouch.env.local
sudo vi /etc/vouch/vouch.env.local
```

At minimum, set:

```bash
VOUCH_RP_ID=auth.example.com
VOUCH_JWT_SECRET=<your-64-character-secret>
VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc
VOUCH_TLS_CERT=<base64-encoded-certificate>
VOUCH_TLS_KEY=<base64-encoded-private-key>
```

See [Configuration Reference](configuration.md) for all options.

## Start the Service

```bash
# Enable and start
sudo systemctl enable --now vouch-server

# Check status
sudo systemctl status vouch-server

# View logs
sudo journalctl -u vouch-server -f
```

## Manual Install (Without Package)

If installing the binary manually:

1. Copy the binary:
   ```bash
   sudo cp vouch-server /usr/bin/
   sudo chmod 755 /usr/bin/vouch-server
   ```

2. Create a systemd unit:
   ```ini
   # /etc/systemd/system/vouch-server.service
   [Unit]
   Description=Vouch Identity Server
   After=network.target

   [Service]
   Type=simple
   User=vouch
   Group=vouch
   EnvironmentFile=/etc/vouch/vouch.env
   ExecStart=/usr/bin/vouch-server
   Restart=on-failure
   RestartSec=5

   # Security hardening
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/data
   AmbientCapabilities=CAP_NET_BIND_SERVICE

   [Install]
   WantedBy=multi-user.target
   ```

3. Create the service user and directories:
   ```bash
   sudo useradd -r -s /sbin/nologin vouch
   sudo mkdir -p /etc/vouch /data
   sudo chown vouch:vouch /data
   sudo chmod 700 /data
   ```

4. Reload and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now vouch-server
   ```

## Upgrading

```bash
# Back up database
sudo cp /data/vouch.db /data/vouch.db.backup.$(date +%Y%m%d)

# Upgrade package (migrations run automatically on next startup)
sudo rpm -Uvh vouch-server-1.1.0-1.x86_64.rpm
# or: sudo dpkg -i vouch-server_1.1.0_amd64.deb

# Restart
sudo systemctl restart vouch-server

# Verify
curl -k https://auth.example.com/health
```
