# Configuration Reference

This chapter describes the Vouch server configuration system, including configuration sources, S3-based configuration, and hot-reload behavior.

Vouch server supports multiple configuration methods with a defined precedence order.

## Configuration Sources (Priority Order)

1. **S3 Configuration** (highest) — JSON file fetched from S3
2. **Environment Variables** — Standard `VOUCH_*` prefixed variables
3. **Command-line Arguments** — Direct CLI arguments

When S3 configuration is enabled, it overrides environment variables. This allows for centralized configuration management with dynamic updates.

## S3-Based Configuration

For production deployments, Vouch supports loading configuration from an S3 object. This enables:

- **Centralized management** — Single source of truth for multi-instance deployments
- **Dynamic updates** — Configuration changes without server restart (for supported fields)
- **TLS hot-reload** — Automatic certificate rotation without downtime
- **Secrets management** — Leverage S3 encryption and IAM for credential protection

**Enabling S3 Configuration:**

```bash
# Required: bucket name
VOUCH_S3_CONFIG_BUCKET=my-bucket

# Optional: object key (default: config/vouch-server.json)
VOUCH_S3_CONFIG_KEY=config/vouch-server.json

# Optional: AWS region (uses default credential chain region if not set)
VOUCH_S3_CONFIG_REGION=us-west-2

# Optional: polling interval in seconds (default: 60)
VOUCH_S3_CONFIG_POLL_INTERVAL=60
```

**S3 Configuration JSON Schema:**

```json
{
  "version": 1,
  "listen_addr": "0.0.0.0:443",
  "rp_id": "vouch.example.com",
  "rp_name": "Example Corp",
  "base_url": "https://vouch.example.com",
  "database_url": "postgres://...",
  "jwt_secret": "32+ character secret",
  "tls": {
    "cert": "<base64-encoded PEM certificate>",
    "key": "<base64-encoded PEM private key>"
  },
  "oidc": {
    "issuer_url": "https://accounts.google.com",
    "client_id": "...",
    "client_secret": "..."
  },
  "allowed_domains": ["example.com"],
  "ssh_ca_key": "<base64-encoded PEM Ed25519 private key>",
  "oidc_signing_key": "<base64-encoded PEM EC P-256 private key>"
}
```

All certificate and key fields are **base64-encoded PEM** strings:
```bash
# Encode a PEM file for S3 config
base64 -i cert.pem | tr -d '\n'
```

## Hot-Reloadable vs Startup-Only Fields

| Field | Hot-Reloadable | Notes |
|-------|----------------|-------|
| `tls.cert`, `tls.key` | Yes | Automatic reload on change |
| All other fields | **No** | Requires server restart |

Non-hot-reloadable fields include: `jwt_secret`, `database_url`, `listen_addr`, `rp_id`, `rp_name`, `session_hours`, `cors_origins`, `allowed_domains`, `dpop.*`, OIDC settings, GitHub App settings, SSH CA key, and OIDC signing key.

Changes to non-hot-reloadable fields in S3 are silently ignored. A server restart is required to apply them.

## TLS Certificate Hot-Reload

Vouch supports automatic TLS certificate reloading without dropping connections:

1. **Via S3 polling** — Update `tls.cert` and `tls.key` in S3 config; server detects change via ETag and reloads
2. **Via SIGHUP** — Send `SIGHUP` to the server process to reload TLS certificates

```bash
# Manual TLS certificate reload (Unix only)
kill -SIGHUP $(pgrep vouch-server)
```

**Note:** SIGHUP only reloads TLS certificates. It does not reload any other configuration fields.
