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
|  |  +--------------+  +----------------+  +--------------------------+  |  |
|  |  |   Vouch      |  |   Built-in     |  |         SQLite           |  |  |
|  |  |   Server     |  |   SSH CA       |  |                          |  |  |
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

### Step 4: Secure Key Generation

**This is a critical security operation. Follow your organization's key ceremony procedures.**

Vouch requires several cryptographic keys for different purposes. All key generation should be performed on a trusted, air-gapped workstation.

#### Key Overview

| Key | Type | Format | Required | Purpose |
|-----|------|--------|----------|---------|
| JWT Secret | Symmetric | UTF-8 (32+ chars) | **Yes** | Sign OAuth tokens and sessions |
| SSH CA Key | Ed25519 | OpenSSH PEM | Optional | Sign SSH certificates |
| OIDC Signing Key | P-256 ECDSA | PKCS#8 PEM | Optional* | Sign OIDC ID tokens |
| TLS Certificate | RSA/EC | PEM | Optional | HTTPS encryption |
| TLS Private Key | RSA/EC | PEM | Optional | HTTPS encryption |

*Auto-generates ephemeral key if not provided (not recommended for production).

#### JWT Secret Generation (Required)

The JWT secret is used to sign all OAuth tokens and session cookies. It must be at least 32 characters.

```bash
# Generate cryptographically secure 64-character secret
openssl rand -base64 48

# Alternative using /dev/urandom
head -c 48 /dev/urandom | base64

# Store securely - this will be VOUCH_JWT_SECRET
```

**Security Notes:**
- Use a minimum of 32 characters (48+ recommended)
- Never reuse secrets across environments
- Rotate periodically (requires re-authentication of all users)

#### SSH CA Key Generation (Ed25519)

The SSH CA signs user SSH certificates. If not provided, SSH certificate issuance will be disabled.

```bash
# Generate Ed25519 SSH CA key pair (no passphrase for automated use)
ssh-keygen -t ed25519 -f ssh_ca_key -N "" -C "vouch-ca@auth.internal"

# Set restrictive permissions
chmod 600 ssh_ca_key

# Verify key type and fingerprint
ssh-keygen -l -f ssh_ca_key
# Output: 256 SHA256:xxxx vouch-ca@auth.internal (ED25519)

# View public key (for distribution to SSH servers)
cat ssh_ca_key.pub
```

**Environment variable format:**
```bash
# Option 1: Provide key content directly (preferred for containers)
export VOUCH_SSH_CA_KEY="$(cat ssh_ca_key)"

# Option 2: Provide path to key file
export VOUCH_SSH_CA_KEY_PATH="/secrets/ssh_ca_key"
```

**Key Storage Options:**
- **HSM** (recommended for high-security) — Store in hardware security module
- **Encrypted file** with split knowledge — Two administrators hold partial keys
- **YubiKey PIV** (for smaller deployments) — Store on hardware token

#### OIDC Signing Key Generation (P-256 ECDSA)

The OIDC signing key signs ID tokens using ES256 algorithm. If not provided, an ephemeral key is generated on each server restart (not recommended for production as it invalidates all existing tokens).

```bash
# Generate P-256 EC private key in PKCS#8 format
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out oidc_signing_key.pem

# Set restrictive permissions
chmod 600 oidc_signing_key.pem

# Verify key type
openssl ec -in oidc_signing_key.pem -text -noout 2>/dev/null | head -3
# Output should include: Private-Key: (256 bit, prime256v1)

# Extract public key (for debugging/verification)
openssl ec -in oidc_signing_key.pem -pubout -out oidc_signing_key.pub
```

**Environment variable format:**
```bash
# Provide PEM content directly
export VOUCH_OIDC_SIGNING_KEY="$(cat oidc_signing_key.pem)"
```

#### TLS Certificate Generation

For production, use certificates signed by your internal CA. For testing, self-signed certificates can be used.

```bash
# Generate EC private key and self-signed certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls_key.pem -out tls_cert.pem -days 365 -nodes \
  -subj "/CN=auth.internal" \
  -addext "subjectAltName=DNS:auth.internal,DNS:localhost"

# Set restrictive permissions
chmod 600 tls_key.pem

# Verify certificate
openssl x509 -in tls_cert.pem -text -noout | head -15
```

**Environment variable format (base64-encoded):**
```bash
# Base64 encode for environment variables
export VOUCH_TLS_CERT="$(base64 -i tls_cert.pem | tr -d '\n')"
export VOUCH_TLS_KEY="$(base64 -i tls_key.pem | tr -d '\n')"
```

#### Key Security Best Practices

1. **File Permissions**: Always use `chmod 600` for private keys
2. **Never Commit Keys**: Add `*.pem`, `*_key`, `*.key` to `.gitignore`
3. **Audit Key Access**: Log all access to key material
4. **Backup Securely**: Store encrypted backups in separate secure location
5. **Document Fingerprints**: Record key fingerprints in secure documentation
6. **Key Rotation**: Plan for periodic rotation (SSH CA annually, JWT secret quarterly)

### Step 5: Database Setup

Vouch uses SQLite by default, which is suitable for single-node deployments. The database is created automatically on first startup.

```bash
# SQLite (default, single-node)
export VOUCH_DATABASE_URL="sqlite:/data/vouch.db?mode=rwc"

# Create data directory with appropriate permissions
mkdir -p /data
chmod 700 /data
```

For high-availability deployments, PostgreSQL is supported:

```bash
# PostgreSQL (multi-node)
export VOUCH_DATABASE_URL="postgres://user:password@db.internal:5432/vouch"
```

**Database migrations run automatically on server startup.**

### Step 6: Configure Vouch Server

Vouch is configured entirely through environment variables. Create a secure environment file:

```bash
# Create environment file (chmod 600 after editing)
cat > /etc/vouch/vouch.env << 'EOF'
# =============================================================================
# Vouch Server Configuration - Air-Gapped Environment
# =============================================================================

# -----------------------------------------------------------------------------
# Required Configuration
# -----------------------------------------------------------------------------

# JWT signing secret (minimum 32 characters)
VOUCH_JWT_SECRET=<your-64-character-secret-here>

# Relying Party configuration
VOUCH_RP_ID=auth.internal
VOUCH_RP_NAME=Vouch (Air-Gapped)

# Database
VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc

# -----------------------------------------------------------------------------
# Network Configuration
# -----------------------------------------------------------------------------

# Listen address (internal only)
VOUCH_LISTEN_ADDR=0.0.0.0:443

# Base URL (how clients reach the server)
VOUCH_BASE_URL=https://auth.internal

# -----------------------------------------------------------------------------
# TLS Configuration (base64-encoded PEM)
# -----------------------------------------------------------------------------

VOUCH_TLS_CERT=<base64-encoded-certificate>
VOUCH_TLS_KEY=<base64-encoded-private-key>

# -----------------------------------------------------------------------------
# SSH CA Configuration
# -----------------------------------------------------------------------------

# SSH CA private key (PEM content, takes precedence over path)
VOUCH_SSH_CA_KEY=<ssh-ca-private-key-pem>

# Or use a file path instead:
# VOUCH_SSH_CA_KEY_PATH=/secrets/ssh_ca_key

# -----------------------------------------------------------------------------
# OIDC Provider Configuration (for GCP Workload Identity Federation)
# -----------------------------------------------------------------------------

# Vouch acts as an OIDC provider - this key signs the ID tokens
VOUCH_OIDC_SIGNING_KEY=<oidc-signing-key-pem>

# -----------------------------------------------------------------------------
# External Identity Provider (Optional)
# For enrollment via external IdP like Okta, Azure AD
# -----------------------------------------------------------------------------

# VOUCH_OIDC_ISSUER=https://idp.internal
# VOUCH_OIDC_CLIENT_ID=vouch-client
# VOUCH_OIDC_CLIENT_SECRET=<client-secret>

# -----------------------------------------------------------------------------
# Session Configuration
# -----------------------------------------------------------------------------

# Session duration (default: 8 hours)
VOUCH_SESSION_HOURS=8

# Device code settings (for CLI enrollment)
VOUCH_DEVICE_CODE_EXPIRES=600
VOUCH_DEVICE_POLL_INTERVAL=5

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------

# Allowed email domains for enrollment (comma-separated)
VOUCH_ALLOWED_DOMAINS=internal,company.local

# DPoP (Demonstrating Proof of Possession)
VOUCH_DPOP_ENABLED=true
VOUCH_DPOP_NONCE_REQUIRED=false
VOUCH_DPOP_MAX_AGE=300

# -----------------------------------------------------------------------------
# Audit and Retention
# -----------------------------------------------------------------------------

# Cleanup interval (minutes, 0 to disable)
VOUCH_CLEANUP_INTERVAL=15

# Event retention (days)
VOUCH_AUTH_EVENTS_RETENTION_DAYS=730
VOUCH_OAUTH_EVENTS_RETENTION_DAYS=90

# -----------------------------------------------------------------------------
# Branding (Optional)
# -----------------------------------------------------------------------------

VOUCH_ORG_NAME=Your Organization
EOF

# Secure the environment file
chmod 600 /etc/vouch/vouch.env
```

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_JWT_SECRET` | **Yes** | - | Session signing (min 32 chars) |
| `VOUCH_RP_ID` | **Yes** | `localhost` | Relying party domain |
| `VOUCH_RP_NAME` | No | `Vouch` | Display name |
| `VOUCH_DATABASE_URL` | **Yes** | `sqlite:vouch.db?mode=rwc` | Database connection |
| `VOUCH_LISTEN_ADDR` | No | `0.0.0.0:3000` | Server bind address |
| `VOUCH_BASE_URL` | No | `https://{rp_id}` | External URL |
| `VOUCH_SESSION_HOURS` | No | `8` | Session duration |
| `VOUCH_SSH_CA_KEY` | No | - | SSH CA key (PEM content) |
| `VOUCH_SSH_CA_KEY_PATH` | No | `./ssh_ca_key` | SSH CA key file path |
| `VOUCH_OIDC_SIGNING_KEY` | No | auto-generate | OIDC token signing key |
| `VOUCH_TLS_CERT` | No | - | TLS cert (base64 PEM) |
| `VOUCH_TLS_KEY` | No | - | TLS key (base64 PEM) |
| `VOUCH_ALLOWED_DOMAINS` | No | - | Allowed email domains |
| `VOUCH_DPOP_ENABLED` | No | `true` | Enable DPoP support |
| `VOUCH_CLEANUP_INTERVAL` | No | `15` | Cleanup interval (minutes) |
| `VOUCH_AUTH_EVENTS_RETENTION_DAYS` | No | `90` | Auth event retention |

### Step 7: Deploy Services

Create a docker-compose file for deployment:

```yaml
# docker-compose.yml
services:
  vouch-server:
    image: vouch-server:1.0.0
    container_name: vouch-server
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - vouch-data:/data
      - /etc/vouch/secrets:/secrets:ro
    env_file:
      - /etc/vouch/vouch.env
    environment:
      # Override or add environment variables here
      VOUCH_DATABASE_URL: sqlite:/data/vouch.db?mode=rwc
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  vouch-data:
```

Deploy and verify:

```bash
# Start services
docker-compose up -d

# Verify container is running
docker-compose ps

# Check logs for startup errors
docker-compose logs -f vouch-server

# Verify health endpoint
curl -k https://auth.internal/health
# Expected: {"status":"healthy"}

# Verify SSH CA is loaded (if configured)
curl -k https://auth.internal/.well-known/ssh-ca.pub
# Expected: ssh-ed25519 AAAA... vouch-ca@auth.internal
```

### Step 8: Distribute CA Public Key

The SSH CA public key must be trusted by all SSH servers in the air-gapped environment:

```bash
# Export CA public key from running container
docker exec vouch-server cat /etc/vouch/ssh-ca.pub > vouch-ca.pub

# Or fetch via API
curl -k https://auth.internal/.well-known/ssh-ca.pub > vouch-ca.pub

# Copy to all SSH servers
scp vouch-ca.pub root@server:/etc/ssh/vouch-ca.pub

# Configure SSH server to trust the CA
echo "TrustedUserCAKeys /etc/ssh/vouch-ca.pub" >> /etc/ssh/sshd_config

# Optionally, configure authorized principals
echo "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u" >> /etc/ssh/sshd_config

# Restart SSH daemon
systemctl restart sshd
```

**AuthorizedPrincipals Setup (Optional but Recommended):**

```bash
# Create principals directory
mkdir -p /etc/ssh/auth_principals

# For each user, create a file with allowed principals
# Vouch issues certificates with two principals: email and username
echo "john@company.internal" > /etc/ssh/auth_principals/john
echo "john" >> /etc/ssh/auth_principals/john
```

### Step 9: Configure CLI for Air-Gap

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

### Step 10: Enroll Users

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
|  |  * SQLite       |        |  +-------+  | Resources |   |  |
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
