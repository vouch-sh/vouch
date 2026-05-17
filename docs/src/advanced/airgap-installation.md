# Installation

This chapter walks through the complete installation procedure for deploying Vouch in an air-gapped environment, from downloading packages on a connected machine through enrolling users on the isolated network.

## Step 1: Download Packages for Offline Transfer

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

## Step 2: Verify Package Integrity

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

## Step 3: Install Packages

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

## Step 4: Secure Key Generation

**This is a critical security operation. Follow your organization's key ceremony procedures.**

Vouch requires several cryptographic keys for different purposes. All key generation should be performed on a trusted, air-gapped workstation. See the [Key Ceremony](airgap-key-ceremony.md) chapter for detailed instructions on generating each key.

### Key Overview

| Key | Type | Format | Required | Purpose |
|-----|------|--------|----------|---------|
| JWT Secret | Symmetric | UTF-8 (32+ chars) | **Yes** | Sign OAuth tokens and sessions |
| SSH CA Key | Ed25519 | Base64-encoded OpenSSH PEM | Optional | Sign SSH certificates |
| OIDC Signing Key | P-256 ECDSA | Base64-encoded PKCS#8 PEM | Optional* | Sign OIDC ID tokens |
| TLS Certificate | RSA/EC | Base64-encoded PEM | Optional | HTTPS encryption |
| TLS Private Key | RSA/EC | Base64-encoded PEM | Optional | HTTPS encryption |

*Auto-generates ephemeral key if not provided (not recommended for production).

> **Note:** All PEM-formatted keys and certificates must be base64-encoded when passed via environment variables. This ensures proper handling of newlines and special characters.

## Step 5: Database Setup

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

## Step 6: Configure Vouch Server

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
# OIDC Provider Configuration
# Generate with: base64 -i oidc_signing_key.pem | tr -d '\n'
# -----------------------------------------------------------------------------

# Vouch acts as an OIDC provider - this key signs the ID tokens (base64-encoded PEM)
VOUCH_OIDC_SIGNING_KEY=<base64-encoded-oidc-signing-key>

# -----------------------------------------------------------------------------
# External Identity Provider (Optional)
# For enrollment via external IdP (e.g., on-premises OIDC provider)
# -----------------------------------------------------------------------------

# VOUCH_IDPS=internal-oidc
# VOUCH_IDP_INTERNAL_OIDC_TYPE=oidc
# VOUCH_IDP_INTERNAL_OIDC_ISSUER=https://idp.internal
# VOUCH_IDP_INTERNAL_OIDC_CLIENT_ID=vouch-client
# VOUCH_IDP_INTERNAL_OIDC_CLIENT_SECRET=<client-secret>

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

## Step 7: Deploy Services

There are several options for deploying the Vouch server.

### Option A: Systemd Service (RPM Install)

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

### Option B: Docker Compose

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
      test: ["CMD", "wget", "-q", "--spider", "--no-check-certificate", "https://localhost/health"]
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

### Option C: Helm Chart (Kubernetes)

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

### Verify Deployment

Regardless of deployment method:

```bash
# Verify health endpoint
curl -k https://auth.internal/health
# Expected: {"status":"healthy"}

# Verify SSH CA is loaded (if configured)
curl -k https://auth.internal/v1/credentials/ssh/ca
# Expected: ssh-ed25519 AAAA... vouch-ca@auth.internal
```

## Step 8: Distribute CA Public Key

The SSH CA public key must be trusted by all SSH servers in the air-gapped environment:

```bash
# Fetch CA public key via API
curl -k https://auth.internal/v1/credentials/ssh/ca > vouch-ca.pub

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

## Step 9: Configure CLI for Air-Gap

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

## Step 10: Enroll Users

> **Important:** Enrollment requires browser access to the Vouch server's web UI on the internal network. CLI-only enrollment (`vouch enroll --airgap`) is not yet implemented.

Each user:

1. Opens a browser to `https://auth.internal/enroll`
2. Authenticates via the configured identity provider (or direct registration if no external IdP is configured)
3. Registers their YubiKey through the browser's WebAuthn prompt (touch + PIN)

After enrollment, daily login uses the CLI (`vouch login`) with no browser required.
