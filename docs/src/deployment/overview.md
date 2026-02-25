# Deployment Overview

This section covers deploying the Vouch server for your organization. The server is the central authentication backend that handles FIDO2 verification, session management, SSH certificate signing, and OIDC token issuance.

## Deployment Checklist

Before deploying, ensure you have:

- [ ] **Domain name** — A domain for your Vouch server (e.g., `auth.example.com`)
- [ ] **TLS certificate** — Valid certificate for your domain (or use Let's Encrypt)
- [ ] **Database** — SQLite (single node) or PostgreSQL (multi-node)
- [ ] **Identity provider** — Google Workspace, Microsoft Entra ID, or another OIDC provider
- [ ] **JWT secret** — Cryptographically random string, minimum 32 characters
- [ ] **SSH CA key** (optional) — Ed25519 key pair for signing SSH certificates
- [ ] **OIDC signing key** (optional) — P-256 EC key for signing ID tokens

## Architecture

```
                    Internet
                       │
                       ▼
              ┌─────────────────┐
              │  Load Balancer  │
              │  (TLS termination │
              │   or passthrough) │
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

| Method | Best For | Guide |
|--------|----------|-------|
| [Systemd](systemd.md) | Bare metal, VMs, single-node | Production |
| [Docker](docker.md) | Container-based deployments | Production |
| [Kubernetes](kubernetes.md) | Multi-node, high availability | Production |

## Configuration

All configuration is via environment variables. See the [Configuration Reference](configuration.md) for the full list.

The minimum configuration requires:

```bash
VOUCH_RP_ID=auth.example.com        # Your domain
VOUCH_JWT_SECRET=<64-char-secret>    # Session signing secret
VOUCH_DATABASE_URL=sqlite:vouch.db?mode=rwc  # Database
```

For production, you'll also want:

```bash
VOUCH_TLS_CERT=<base64-encoded-pem>  # TLS certificate
VOUCH_TLS_KEY=<base64-encoded-pem>   # TLS private key
VOUCH_SSH_CA_KEY=<base64-encoded-pem> # SSH CA key
VOUCH_OIDC_ISSUER=https://accounts.google.com  # External IdP
VOUCH_OIDC_CLIENT_ID=...
VOUCH_OIDC_CLIENT_SECRET=...
```

## Next Steps

1. [Database Setup](database.md) — Choose and configure your database
2. [TLS Configuration](tls.md) — Set up HTTPS
3. [Configuration Reference](configuration.md) — Full environment variable reference
4. [Identity Provider Setup](../idp/overview.md) — Connect your corporate IdP
