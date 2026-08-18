# Deployment Overview

This section covers deploying the Vouch server for your organization. The server is the central authentication backend that handles FIDO2 verification, session management, SSH certificate signing, and OIDC token issuance.

## Deployment Checklist

Before deploying, you need:

- [ ] **Domain name** — A domain for your Vouch server (e.g., `auth.example.com`)
- [ ] **TLS certificate** — Valid certificate for your domain (or use Let's Encrypt)
- [ ] **Database** — SQLite (single node) or PostgreSQL (multi-node)
- [ ] **Identity provider** — At least one upstream OIDC or SAML IdP (Google Workspace, Entra ID, Okta, or any compliant provider)
- [ ] **JWT secret** — Cryptographically random string, minimum 32 characters (or use AWS KMS HMAC)
- [ ] **SSH CA key** (optional) — Ed25519 key pair for signing SSH certificates (or use AWS KMS)
- [ ] **OIDC signing key** (optional) — P-256 EC key for signing ID tokens (or use AWS KMS)

## Architecture

```
                    Internet
                       │
                       ▼
              ┌─────────────────┐
              │  Load Balancer  │
              │ TCP passthrough │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Vouch Server   │
              │                 │
              │  • Auth Portal  │
              │  • OIDC Provider│
              │  • SSH CA       │
              │  • REST API     │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │    Database     │
              │                 │
              │  SQLite or      │
              │  PostgreSQL     │
              └─────────────────┘
```

## Deployment Methods

| Method | Best for |
|--------|----------|
| [Systemd](../install/systemd.md) | Bare metal, VMs, single-node |
| [Docker](../install/docker.md) | Container-based deployments |
| [Kubernetes](../install/kubernetes.md) | Multi-node, high availability |

## Configuration

All configuration is via environment variables. See the [Configuration Reference](../configuration/sources.md) for the full list.

The minimum configuration requires:

```bash
VOUCH_RP_ID=auth.example.com        # Your domain
VOUCH_JWT_SECRET=<64-char-secret>    # Session signing secret
VOUCH_DATABASE_URL=sqlite:vouch.db?mode=rwc  # Database
```

For production, also set:

```bash
VOUCH_TLS_CERT=<base64-encoded-pem>  # TLS certificate
VOUCH_TLS_KEY=<base64-encoded-pem>   # TLS private key
VOUCH_SSH_CA_KEY=<base64-encoded-pem> # SSH CA key (or VOUCH_SSH_CA_KMS_KEY_ID)
VOUCH_IDPS=google                                    # External IdP(s)
VOUCH_IDP_GOOGLE_TYPE=oidc
VOUCH_IDP_GOOGLE_ISSUER=https://accounts.google.com
VOUCH_IDP_GOOGLE_CLIENT_ID=...
VOUCH_IDP_GOOGLE_CLIENT_SECRET=...
```

AWS deployments can use KMS for all signing operations instead of managing local keys. See the [Configuration Reference](../configuration/sources.md) for KMS options.

## Sizing

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 vCPU | 2 vCPU |
| Memory | 256 MB | 512 MB |
| Disk | 1 GB (SQLite) | 10 GB (PostgreSQL) |

The server is single-process, async (tokio). Per-session memory overhead is ~2 KB of token metadata. The primary bottleneck is database I/O during token issuance and session validation.

**Database guidance:**
- **SQLite** — single-node deployments under ~500 users
- **PostgreSQL** — multi-node deployments, or more than 500 users
- **Aurora DSQL** — AWS deployments using managed database infrastructure

## Next Steps

1. [Database Setup](../configuration/database.md) — Choose and configure your database
2. [TLS Configuration](../configuration/tls.md) — Set up HTTPS
3. [Configuration Reference](../configuration/sources.md) — Full environment variable reference
4. [Identity Provider Setup](../idp/overview.md) — Connect your corporate IdP
