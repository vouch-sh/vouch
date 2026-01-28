# Air-Gapped Deployment Guide

> **Status: Planned** — This document describes the planned air-gapped deployment architecture for Vouch Enterprise. The features described here are under development (see [ROADMAP.md](ROADMAP.md), v0.8). The core components (SSH CA, FIDO2 authentication) exist today, but the packaging, automation scripts, and air-gap-specific commands are not yet implemented.

This guide covers deploying Vouch in environments with no internet connectivity, such as defense contractors, government agencies, financial services, and critical infrastructure.

## Overview

In an air-gapped environment:
- No SaaS services available
- Updates delivered via sneakernet
- Internal identity provider (no Google Workspace)
- Time sync from isolated NTP or GPS

Vouch's built-in SSH CA and local-first architecture make it well-suited for these constraints.

## Architecture

```
+---------------------------------------------------------------------------+
|                           AIR-GAPPED ENCLAVE                               |
|                                                                            |
|  +----------------------------------------------------------------------+  |
|  |                      On-Premises Vouch Stack                         |  |
|  |                                                                      |  |
|  |  +--------------+  +----------------+  +----------------------------+ |  |
|  |  |   Vouch      |  |   Built-in     |  |       SQLite               | |  |
|  |  |   Server     |  |   SSH CA       |  |                            | |  |
|  |  |              |  |                |  |  * Users & credentials     | |  |
|  |  |  * WebAuthn  |  |  * Ed25519 CA  |  |  * Sessions                | |  |
|  |  |  * OIDC      |  |  * SSH certs   |  |  * Audit logs              | |  |
|  |  |  * Sessions  |  |  * 8hr TTL     |  |                            | |  |
|  |  +--------------+  +----------------+  +----------------------------+ |  |
|  |         |                  |                        |                 |  |
|  |         +------------------+------------------------+                 |  |
|  |                            |                                          |  |
|  +----------------------------+------------------------------------------+  |
|                               |                                             |
|                               | Internal Network Only                       |
|                               v                                             |
|  +----------------------------------------------------------------------+  |
|  |                         Workstations                                  |  |
|  |                                                                       |  |
|  |  +--------------+  +--------------+  +------------------------------+ |  |
|  |  | Workstation  |  | Workstation  |  |    Protected Resources       | |  |
|  |  |              |  |              |  |                              | |  |
|  |  | * vouch CLI  |  | * vouch CLI  |  |  * SSH servers               | |  |
|  |  | * YubiKey    |  | * YubiKey    |  |  * Internal apps             | |  |
|  |  | * Certs      |  | * Certs      |  |  * Databases                 | |  |
|  |  +--------------+  +--------------+  +------------------------------+ |  |
|  |                                                                       |  |
|  +-----------------------------------------------------------------------+  |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  |                        Time Infrastructure                            |  |
|  |  +------------+     +-----------------+                               |  |
|  |  | GPS Time   |---->|  Internal NTP   |----> All hosts                |  |
|  |  | Receiver   |     |  (stratum 1)    |                               |  |
|  |  +------------+     +-----------------+                               |  |
|  +-----------------------------------------------------------------------+  |
+---------------------------------------------------------------------------+
                                    |
                                    | Air Gap (sneakernet)
                                    v
+---------------------------------------------------------------------------+
|                          CONNECTED ENVIRONMENT                             |
|                                                                            |
|  * Signed software bundles                                                 |
|  * CA certificate updates                                                  |
|  * (Optional) Audit log export                                             |
+---------------------------------------------------------------------------+
```

## Prerequisites

### Hardware
- Servers for Vouch stack (VMs or bare metal)
- YubiKey 5 series for each user (firmware 5.2+)
- GPS receiver for time sync (recommended)
- USB drives for sneakernet transfers

### Software (Pre-downloaded)
- Vouch Server container images
- vouch CLI binaries (all platforms)
- CA initialization scripts

## Installation

### Step 1: Prepare Offline Bundle

On a connected machine, download all required components:

```bash
# Download Vouch release bundle
curl -LO https://releases.vouch.sh/enterprise/vouch-enterprise-1.0.0-airgap.tar.gz
curl -LO https://releases.vouch.sh/enterprise/vouch-enterprise-1.0.0-airgap.tar.gz.sig

# Verify signature
gpg --verify vouch-enterprise-1.0.0-airgap.tar.gz.sig

# Extract
tar xzf vouch-enterprise-1.0.0-airgap.tar.gz
```

Bundle contents:
```
vouch-enterprise-1.0.0-airgap/
├── images/
│   └── vouch-server-1.0.0.tar       # Docker image (includes built-in CA + SQLite)
├── cli/
│   ├── vouch-1.0.0-darwin-arm64.tar.gz
│   ├── vouch-1.0.0-darwin-amd64.tar.gz
│   ├── vouch-1.0.0-linux-amd64.tar.gz
│   └── vouch-1.0.0-windows-amd64.zip
├── scripts/
│   ├── init-ca.sh
│   ├── verify-bundle.sh
│   └── generate-config.sh
├── config/
│   ├── docker-compose.yml
│   └── vouch-server.toml.template
├── SHA256SUMS
├── SHA256SUMS.sig
└── INSTALL.md
```

Transfer to air-gapped environment via approved media.

### Step 2: Verify Bundle Integrity

On the air-gapped network:

```bash
# Import Vouch release signing key (transferred separately, verified out-of-band)
gpg --import vouch-release-key.pub

# Verify signatures
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

echo "Bundle verified"
```

### Step 3: Load Container Images

```bash
# Load images into local Docker registry
docker load < images/vouch-server-1.0.0.tar

# Verify images loaded
docker images | grep vouch-server
```

### Step 4: Initialize SSH Certificate Authority

**This is a critical security operation. Follow your organization's key ceremony procedures.**

```bash
# Generate SSH CA key
./scripts/init-ca.sh

# This will:
# 1. Generate Ed25519 CA key pair
# 2. Store private key securely (HSM or encrypted file)
# 3. Export public key for distribution to SSH servers
```

CA key storage options:
- **HSM** (recommended for high-security)
- **Encrypted file** with split knowledge (two administrators)
- **YubiKey PIV** (for smaller deployments)

### Step 5: Configure Vouch Server

```bash
# Generate configuration
./scripts/generate-config.sh

# Edit config/vouch-server.toml
```

Key air-gap settings:
```toml
[server]
mode = "airgap"
bind_address = "0.0.0.0:443"
tls_cert = "/certs/server.crt"
tls_key = "/certs/server.key"

[rp]
id = "auth.internal"
name = "Vouch (Air-Gapped)"

[ssh_ca]
# Built-in SSH CA configuration
private_key_path = "/secrets/ssh-ca-key"
public_key_path = "/etc/vouch/ssh-ca.pub"

[database]
path = "/data/vouch.db"  # SQLite database

[identity]
# Internal identity provider (no Google Workspace)
provider = "local"
# Or configure internal LDAP/AD
# provider = "ldap"
# ldap_url = "ldaps://ldap.internal:636"

[session]
duration_hours = 8

[audit]
# Local storage only
storage = "database"
retention_days = 730  # 2 years

[time]
# Allow clock skew for isolated networks
allowed_skew_seconds = 300
```

### Step 6: Deploy Services

```bash
# Start services
docker-compose up -d

# Verify health
docker-compose ps
curl -k https://auth.internal/health
```

### Step 7: Distribute CA Public Key

The SSH CA public key must be trusted by all SSH servers:

```bash
# Export CA public key
docker exec vouch-server cat /etc/vouch/ssh-ca.pub > vouch-ca.pub

# Copy to all SSH servers
scp vouch-ca.pub root@server:/etc/ssh/vouch-ca.pub

# Configure SSH server
echo "TrustedUserCAKeys /etc/ssh/vouch-ca.pub" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### Step 8: Configure CLI for Air-Gap

```bash
# ~/.vouch/config.json
{
  "server_url": "https://auth.internal",
  "ca_cert_path": "/etc/vouch/root-ca.crt"
}
```

Or via environment:
```bash
export VOUCH_SERVER=https://auth.internal
export VOUCH_CA_CERT=/etc/vouch/root-ca.crt
```

### Step 9: Enroll Users

> **Note:** Air-gap-specific enrollment commands (`vouch enroll --airgap`, `vouch admin user create`) are planned but not yet implemented. Currently, enrollment requires browser access to the Vouch server's web UI.

In air-gapped mode, enrollment will be done locally:

```bash
# Admin creates user account (planned)
vouch admin user create --email user@internal --name "User Name"

# User enrolls their YubiKey (planned CLI-only air-gap mode)
vouch enroll --airgap
# Touch your YubiKey...
# Enter PIN: ****
# Enrolled as user@internal
```

For current deployments, users enroll via the Vouch server's web interface at `https://auth.internal`.

## YubiKey Provisioning

> **Note:** The provisioning commands below (`--export-pubkey`, `admin credential import`, `--airgap`) are planned but not yet implemented.

### Option A: Pre-Provisioned Keys (Recommended)

Keys provisioned in connected environment, public keys transferred:

1. **Connected environment:**
```bash
# Generate resident credential on YubiKey (planned)
vouch enroll --export-pubkey > user-pubkey.json
```

2. **Transfer pubkey via sneakernet**

3. **Air-gapped environment:**
```bash
# Admin imports public key (planned)
vouch admin credential import --user user@internal < user-pubkey.json
```

### Option B: Fully Air-Gapped Provisioning

```bash
# User inserts YubiKey (planned)
# Registration happens entirely on internal network
vouch enroll --airgap

# Creates credential locally, sends public key to internal server
```

## Time Synchronization

Certificate validity depends on accurate time. Options for air-gapped networks:

### GPS Time Receiver (Recommended)

```
+----------------+     +--------------------+
| GPS Receiver   |---->| Internal NTP       |
| (one-way data) |     | Server (stratum 1) |
+----------------+     +--------------------+
         |                      |
         |                      v
    One-way only         All internal hosts
    (no data out)
```

Configure NTP clients:
```bash
# /etc/ntp.conf
server ntp.internal iburst
```

### Manual Time Sync

For truly isolated networks without GPS:

1. Reference time from secure source (atomic clock, verified external)
2. Set time on NTP server manually
3. Document time sync in audit log

```toml
# Adjust vouch config for larger clock skew
[time]
allowed_skew_seconds = 600  # 10 minutes
```

## Software Updates

### Update Procedure

1. **Download update bundle** (connected environment)
```bash
curl -LO https://releases.vouch.sh/enterprise/vouch-enterprise-1.1.0-airgap.tar.gz
curl -LO https://releases.vouch.sh/enterprise/vouch-enterprise-1.1.0-airgap.tar.gz.sig
```

2. **Verify signatures** (connected environment)
```bash
gpg --verify vouch-enterprise-1.1.0-airgap.tar.gz.sig
```

3. **Transfer via approved media** (sneakernet)

4. **Verify again** (air-gapped environment)
```bash
gpg --verify vouch-enterprise-1.1.0-airgap.tar.gz.sig
sha256sum -c SHA256SUMS
```

5. **Apply update**
```bash
./scripts/upgrade.sh

# This will:
# - Stop services
# - Backup database
# - Load new images
# - Run migrations
# - Start services
# - Verify health
```

### Rollback

```bash
./scripts/rollback.sh

# Restores previous version from backup
```

## Audit Log Export

Air-gapped environments still need audit trails for compliance.

### One-Way Data Diode

```
+-----------------+     +-------------+     +-----------------+
| Air-Gapped      |---->| Data Diode  |---->| SIEM            |
| Vouch Server    |     | (hardware)  |     | (connected)     |
|                 |     |             |     |                 |
| UDP syslog out  |     | One-way     |     | Splunk/Datadog  |
+-----------------+     +-------------+     +-----------------+
```

Configure syslog export:
```toml
[audit]
syslog_enabled = true
syslog_address = "diode.internal:514"
syslog_protocol = "udp"
```

### Periodic Export

```bash
#!/bin/bash
# Weekly audit log export script

DATE=$(date +%Y%m%d)
OUTPUT_DIR=/mnt/export

# Export audit logs
vouch admin audit export \
  --since "7 days ago" \
  --format json \
  > $OUTPUT_DIR/audit-$DATE.json

# Encrypt for transport
gpg --encrypt --recipient auditor@company.com \
  $OUTPUT_DIR/audit-$DATE.json

# Generate checksum
sha256sum $OUTPUT_DIR/audit-$DATE.json.gpg > $OUTPUT_DIR/audit-$DATE.sha256

# Remove unencrypted
rm $OUTPUT_DIR/audit-$DATE.json

echo "Export complete: audit-$DATE.json.gpg"
```

Transfer encrypted exports via approved media to connected compliance systems.

## Disaster Recovery

### Backup Strategy

| Component | Frequency | Method | Retention |
|-----------|-----------|--------|-----------|
| SQLite database | Daily | File copy, encrypted | 90 days |
| SSH CA keys | On change | HSM backup or split custody | Permanent |
| Configuration | On change | Git (internal) | Permanent |
| Audit logs | Continuous | Append-only storage | Per policy |

### Recovery Procedure

1. **Restore from backup**
```bash
./scripts/restore.sh --backup-date 2024-01-14
```

2. **Verify CA integrity**
```bash
./scripts/verify-ca.sh
```

3. **Re-sync time**
```bash
./scripts/sync-time.sh
```

4. **Validate all services**
```bash
./scripts/health-check.sh
```

### CA Key Recovery

If CA keys are lost, all issued certificates become unverifiable.

**Prevention:**
- Store CA keys in HSM with backup
- Use split-knowledge for key recovery
- Document key ceremony procedures

**Recovery:**
1. Generate new CA from backup
2. Re-provision all user credentials
3. Redistribute new CA public key
4. Update all SSH server trust anchors

## Security Considerations

### Network Segmentation

```
+-------------------------------------------------------------+
|                    Air-Gapped Network                        |
|                                                              |
|  +-----------------+        +-----------------------------+  |
|  |   Management    |        |      User Network           |  |
|  |   VLAN          |        |                             |  |
|  |                 |        |  +-------+  +-----------+   |  |
|  |  * Vouch Server |<------>|  |Workst.|  | Protected |   |  |
|  |  * PostgreSQL   |        |  +-------+  | Resources |   |  |
|  |                 |        |             +-----------+   |  |
|  +-----------------+        +-----------------------------+  |
|           |                                                  |
|           | Restricted                                       |
|           v                                                  |
|  +-----------------+                                         |
|  | Admin Jumpbox   | <-- Physical access control             |
|  +-----------------+                                         |
+--------------------------------------------------------------+
```

### Physical Security

- Server room access controls
- YubiKey storage procedures
- Media transfer protocols
- Tamper-evident logging

### Compliance Mapping

| Requirement | NIST 800-53 | Implementation |
|-------------|-------------|----------------|
| Hardware auth | IA-2(1) | FIDO2 with YubiKey |
| Credential lifetime | IA-5(1) | 8-hour certificates |
| Audit logging | AU-2, AU-3 | All credential issuance logged |
| Time sync | AU-8 | GPS/NTP infrastructure |
| Key management | SC-12 | HSM or split-custody |

## Troubleshooting

### Cannot Connect to Vouch Server

```bash
# Check network connectivity
ping auth.internal

# Verify TLS
openssl s_client -connect auth.internal:443 -CAfile /etc/vouch/root-ca.crt

# Check server logs
docker-compose logs vouch-server
```

### Certificate Validation Failures

```bash
# Check system time
date
timedatectl status

# Verify CA is trusted
ssh-keygen -L -f /path/to/cert  # View certificate details

# Check certificate dates
ssh-keygen -L -f /path/to/cert | grep Valid
```

### YubiKey Not Recognized

```bash
# Check USB connection
lsusb | grep Yubico

# Verify FIDO2 functionality
ykman fido info

# Reset FIDO2 application (destructive - re-enrollment required)
ykman fido reset
```

## Support

For air-gapped deployment support:
- **Email**: enterprise@vouch.sh (for initial setup, via connected systems)
- **Secure communication**: PGP-encrypted email or Signal
- **On-site**: Available for high-security installations
