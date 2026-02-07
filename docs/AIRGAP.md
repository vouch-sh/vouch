# Air-Gapped Deployment Guide

> **Status: Planned** — This document describes the air-gapped deployment architecture for Vouch. Server and CLI packages are available from [packages.vouch.sh](https://packages.vouch.sh), and the core components (SSH CA, FIDO2 authentication) exist today. However, air-gap-specific CLI commands (e.g., `vouch enroll --airgap`) and automation scripts are not yet implemented (see [ROADMAP.md](ROADMAP.md), v0.8).

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
|  * Signed software packages (from packages.vouch.sh)                      |
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
- Vouch Server packages (RPM/DEB from [packages.vouch.sh](https://packages.vouch.sh))
- vouch CLI packages (RPM/DEB from [packages.vouch.sh](https://packages.vouch.sh))
- Container images and/or Helm charts (for Kubernetes deployments)

## Installation

### Step 1: Download Packages for Offline Transfer

On a connected machine, download the required packages from `packages.vouch.sh`:

```bash
# Import Vouch GPG signing key
curl -fsSL https://packages.vouch.sh/gpg/vouch.asc | gpg --import

# Download server RPM
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-server-1.0.0-1.x86_64.rpm

# Download CLI RPM (for each workstation architecture)
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-1.0.0-1.x86_64.rpm
curl -LO https://packages.vouch.sh/rpm/aarch64/vouch-1.0.0-1.aarch64.rpm

# For Debian/Ubuntu workstations
curl -LO https://packages.vouch.sh/apt/vouch_1.0.0_amd64.deb
curl -LO https://packages.vouch.sh/apt/vouch_1.0.0_arm64.deb
```

For container-based or Kubernetes deployments, also download:

```bash
# Pull and save container image
docker pull ghcr.io/vouch-sh/vouch:1.0.0
docker save ghcr.io/vouch-sh/vouch:1.0.0 -o vouch-server-1.0.0.tar

# Download Helm chart (for Kubernetes)
helm pull oci://ghcr.io/vouch-sh/charts/vouch-server --version 0.1.0
```

Generate checksums for verification after transfer:

```bash
sha256sum vouch-server-*.rpm vouch-*.rpm vouch-*.deb vouch-server-*.tar > SHA256SUMS
gpg --detach-sign SHA256SUMS
```

Transfer all files to the air-gapped environment via approved media.

### Step 2: Verify Package Integrity

On the air-gapped network:

```bash
# Import Vouch GPG signing key (transferred separately, verified out-of-band)
gpg --import vouch-release-key.pub

# Verify checksums
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

# Verify RPM signatures
rpm -K vouch-server-1.0.0-1.x86_64.rpm
rpm -K vouch-1.0.0-1.x86_64.rpm
```

### Step 3: Install Packages

**RPM-based installation (recommended for bare metal/VM):**

```bash
# Install server
rpm -ivh vouch-server-1.0.0-1.x86_64.rpm

# Install CLI on workstations
rpm -ivh vouch-1.0.0-1.x86_64.rpm
```

**DEB-based installation:**

```bash
# Install CLI on Debian/Ubuntu workstations
dpkg -i vouch_1.0.0_amd64.deb
```

**Container-based installation:**

```bash
# Load container image into local Docker registry
docker load < vouch-server-1.0.0.tar

# Verify image loaded
docker images | grep vouch
```

### Step 4: Secure Key Generation

**This is a critical security operation. Follow your organization's key ceremony procedures.**

Vouch requires several cryptographic keys for different purposes. All key generation should be performed on a trusted, air-gapped workstation.

#### Key Overview

| Key | Type | Format | Required | Purpose |
|-----|------|--------|----------|---------|
| JWT Secret | Symmetric | UTF-8 (32+ chars) | **Yes** | Sign OAuth tokens and sessions |
| SSH CA Key | Ed25519 | Base64-encoded OpenSSH PEM | Optional | Sign SSH certificates |
| OIDC Signing Key | P-256 ECDSA | Base64-encoded PKCS#8 PEM | Optional* | Sign OIDC ID tokens |
| TLS Certificate | RSA/EC | Base64-encoded PEM | Optional | HTTPS encryption |
| TLS Private Key | RSA/EC | Base64-encoded PEM | Optional | HTTPS encryption |

*Auto-generates ephemeral key if not provided (not recommended for production).

> **Note:** All PEM-formatted keys and certificates must be base64-encoded when passed via environment variables. This ensures proper handling of newlines and special characters.

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

**Environment variable format (base64-encoded):**
```bash
# Option 1: Provide base64-encoded key content (preferred for containers)
export VOUCH_SSH_CA_KEY="$(base64 -i ssh_ca_key | tr -d '\n')"

# Option 2: Provide path to key file (file contains raw PEM, not base64)
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

**Environment variable format (base64-encoded):**
```bash
# Provide base64-encoded PEM content
export VOUCH_OIDC_SIGNING_KEY="$(base64 -i oidc_signing_key.pem | tr -d '\n')"
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

For high-availability deployments, a local PostgreSQL instance is supported:

```bash
# PostgreSQL (multi-node, must be reachable on the internal network)
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
#
# Development (no TLS):
#   Server listens on VOUCH_LISTEN_ADDR (default: 0.0.0.0:3000)
#
# Production (TLS enabled):
#   Server automatically listens on port 443 (HTTPS) and port 80 (HTTP redirect)
#   VOUCH_LISTEN_ADDR is ignored when TLS is configured
#   HTTP requests on port 80 are 308 redirected to HTTPS on port 443
#   The /health endpoint is accessible on HTTP (for load balancer health checks)
#   Host header is validated against rp_id to prevent injection attacks
#   Requires CAP_NET_BIND_SERVICE capability (handled by packaging scripts)
# -----------------------------------------------------------------------------

# Listen address (used only when TLS is NOT configured)
VOUCH_LISTEN_ADDR=0.0.0.0:3000

# Base URL (how clients reach the server)
VOUCH_BASE_URL=https://auth.internal

# -----------------------------------------------------------------------------
# TLS Configuration (base64-encoded PEM)
# Generate with: base64 -i cert.pem | tr -d '\n'
# -----------------------------------------------------------------------------

VOUCH_TLS_CERT=<base64-encoded-certificate>
VOUCH_TLS_KEY=<base64-encoded-private-key>

# -----------------------------------------------------------------------------
# SSH CA Configuration (base64-encoded PEM)
# Generate with: base64 -i ssh_ca_key | tr -d '\n'
# -----------------------------------------------------------------------------

# SSH CA private key (base64-encoded PEM, takes precedence over path)
VOUCH_SSH_CA_KEY=<base64-encoded-ssh-ca-private-key>

# Or use a file path instead (file contains raw PEM, not base64):
# VOUCH_SSH_CA_KEY_PATH=/secrets/ssh_ca_key

# -----------------------------------------------------------------------------
# OIDC Provider Configuration (for GCP Workload Identity Federation)
# Generate with: base64 -i oidc_signing_key.pem | tr -d '\n'
# -----------------------------------------------------------------------------

# Vouch acts as an OIDC provider - this key signs the ID tokens (base64-encoded PEM)
VOUCH_OIDC_SIGNING_KEY=<base64-encoded-oidc-signing-key>

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
| `VOUCH_SSH_CA_KEY` | No | - | SSH CA key (base64-encoded PEM) |
| `VOUCH_SSH_CA_KEY_PATH` | No | `./ssh_ca_key` | SSH CA key file path (raw PEM) |
| `VOUCH_OIDC_SIGNING_KEY` | No | auto-generate | OIDC token signing key (base64-encoded PEM) |
| `VOUCH_TLS_CERT` | No | - | TLS cert (base64-encoded PEM) |
| `VOUCH_TLS_KEY` | No | - | TLS key (base64-encoded PEM) |
| `VOUCH_ALLOWED_DOMAINS` | No | - | Allowed email domains |
| `VOUCH_DPOP_ENABLED` | No | `true` | Enable DPoP support |
| `VOUCH_CLEANUP_INTERVAL` | No | `15` | Cleanup interval (minutes) |
| `VOUCH_AUTH_EVENTS_RETENTION_DAYS` | No | `90` | Auth event retention |

### Step 7: Deploy Services

There are several options for deploying the Vouch server.

#### Option A: Systemd Service (RPM Install)

If you installed via RPM, the `vouch-server` systemd service is configured automatically:

```bash
# Configure environment
cp /etc/vouch/vouch.env /etc/vouch/vouch.env.local
# Edit /etc/vouch/vouch.env.local with your settings

# Start and enable the service
systemctl enable --now vouch-server

# Check status
systemctl status vouch-server

# View logs
journalctl -u vouch-server -f
```

#### Option B: Docker Compose

```yaml
# docker-compose.yml
services:
  vouch-server:
    image: ghcr.io/vouch-sh/vouch:1.0.0
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

```bash
# Start services
docker-compose up -d

# Verify container is running
docker-compose ps

# Check logs for startup errors
docker-compose logs -f vouch-server
```

#### Option C: Helm Chart (Kubernetes)

A Helm chart is available for Kubernetes deployments. After transferring the chart archive to the air-gapped environment:

```bash
# Install from the downloaded chart archive
helm install vouch-server vouch-server-0.1.0.tgz \
  --namespace vouch \
  --create-namespace \
  --set image.repository=vouch-server \
  --set image.tag=1.0.0 \
  --values my-values.yaml
```

See the chart's `values.yaml` for all configurable options including secrets, ingress, and persistent storage.

#### Verify Deployment

Regardless of deployment method:

```bash
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
# Fetch CA public key via API
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

Users enroll via the Vouch server's web interface at `https://auth.internal`. Each user navigates to the enrollment page in a browser on the internal network, authenticates via the configured identity provider (or direct registration if no external IdP is configured), and registers their YubiKey through the browser's WebAuthn prompt.

> **Note:** Air-gap-specific CLI enrollment commands (e.g., `vouch enroll --airgap`) are planned but not yet implemented. Currently, enrollment requires browser access to the Vouch server's web UI.

## YubiKey Provisioning

In an air-gapped environment, YubiKey provisioning is done entirely on the internal network through the Vouch server's web UI.

### Provisioning Workflow

1. **Administrator** creates a user account via the Vouch server web interface
2. **User** navigates to `https://auth.internal` on their workstation browser
3. **User** inserts their YubiKey and completes the WebAuthn registration flow
4. **User** sets a PIN on their YubiKey if one is not already configured (minimum 8 characters)
5. The credential is registered and the user can begin authenticating

### YubiKey Requirements

- YubiKey 5 series with firmware 5.2+
- FIDO2/WebAuthn support enabled
- PIN configured (minimum 8 characters)

### Spare Key Strategy

Each user should register at least two YubiKeys (primary and backup). If a YubiKey is lost or damaged:

1. User reports lost key to administrator
2. Administrator revokes the lost key's credential via the web UI
3. User registers their backup YubiKey

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

1. **Download updated packages** (connected environment)
```bash
# Download latest packages from packages.vouch.sh
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-server-1.1.0-1.x86_64.rpm
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-1.1.0-1.x86_64.rpm

# For container deployments
docker pull ghcr.io/vouch-sh/vouch:1.1.0
docker save ghcr.io/vouch-sh/vouch:1.1.0 -o vouch-server-1.1.0.tar
```

2. **Verify signatures** (connected environment)
```bash
rpm -K vouch-server-1.1.0-1.x86_64.rpm
rpm -K vouch-1.1.0-1.x86_64.rpm
```

3. **Transfer via approved media** (sneakernet)

4. **Verify again** (air-gapped environment)
```bash
rpm -K vouch-server-1.1.0-1.x86_64.rpm
sha256sum -c SHA256SUMS
```

5. **Apply update**

For RPM installations:
```bash
# Backup database before upgrade
cp /data/vouch.db /data/vouch.db.backup.$(date +%Y%m%d)

# Upgrade package (migrations run automatically on next startup)
rpm -Uvh vouch-server-1.1.0-1.x86_64.rpm

# Restart service
systemctl restart vouch-server

# Verify health
curl -k https://auth.internal/health
```

For container deployments:
```bash
docker load < vouch-server-1.1.0.tar
# Update docker-compose.yml image tag, then:
docker-compose up -d
```

### Rollback

For RPM installations:
```bash
# Restore database backup
cp /data/vouch.db.backup.YYYYMMDD /data/vouch.db

# Downgrade package
rpm -Uvh --oldpackage vouch-server-1.0.0-1.x86_64.rpm

# Restart service
systemctl restart vouch-server
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

# Export audit logs from SQLite directly
sqlite3 /data/vouch.db \
  ".mode json" \
  "SELECT * FROM auth_events WHERE created_at >= datetime('now', '-7 days');" \
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

1. **Stop the service**
```bash
systemctl stop vouch-server
```

2. **Restore database from backup**
```bash
cp /data/vouch.db.backup.YYYYMMDD /data/vouch.db
chown vouch:vouch /data/vouch.db
```

3. **Re-sync time**
```bash
# Verify NTP synchronization
timedatectl status
chronyc tracking  # or ntpq -p
```

4. **Start and validate**
```bash
systemctl start vouch-server
curl -k https://auth.internal/health
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

# Check server logs (systemd)
journalctl -u vouch-server --since "1 hour ago"

# Check server logs (Docker)
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
