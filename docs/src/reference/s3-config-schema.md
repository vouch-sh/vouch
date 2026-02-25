# S3 Configuration Schema

For production deployments, Vouch supports loading configuration from an S3 object. This enables:

- **Centralized management** — Single source of truth for multi-instance deployments
- **Dynamic updates** — Configuration changes without server restart (for supported fields)
- **TLS hot-reload** — Automatic certificate rotation without downtime
- **Secrets management** — Leverage S3 encryption and IAM for credential protection

## Enabling S3 Configuration

Set the following environment variables to enable S3-based configuration:

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

When S3 configuration is enabled, it overrides environment variables. This allows for centralized configuration management with dynamic updates.

## JSON Schema

The S3 configuration file is a JSON document with the following schema:

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

## Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `version` | integer | Schema version. Must be `1`. |
| `listen_addr` | string | Address and port to listen on (e.g., `0.0.0.0:443`). |
| `rp_id` | string | Relying Party ID (domain). Used as the WebAuthn RP ID. |
| `rp_name` | string | Relying Party display name for browser prompts and UI. |
| `base_url` | string | External base URL for the server. |
| `database_url` | string | Database connection URL (`sqlite:`, `postgres:`, or Aurora DSQL). |
| `jwt_secret` | string | JWT signing secret (minimum 32 characters). |
| `tls.cert` | string | TLS certificate (base64-encoded PEM). |
| `tls.key` | string | TLS private key (base64-encoded PEM). |
| `oidc.issuer_url` | string | External OIDC issuer URL for enrollment. |
| `oidc.client_id` | string | OIDC client ID from the external identity provider. |
| `oidc.client_secret` | string | OIDC client secret from the external identity provider. |
| `allowed_domains` | array of strings | Allowed email domains for enrollment. |
| `ssh_ca_key` | string | SSH CA private key (base64-encoded PEM, Ed25519). |
| `oidc_signing_key` | string | OIDC signing key (base64-encoded PEM, P-256 ECDSA). |

## Base64 Encoding

All certificate and key fields in the S3 configuration must be **base64-encoded PEM** strings. To encode a PEM file:

```bash
# Encode a PEM file for S3 config
base64 -i cert.pem | tr -d '\n'
```

This ensures proper handling of newlines and special characters within JSON values.

## Hot-Reloadable vs Startup-Only Fields

The server polls S3 at the configured interval and detects changes via ETag comparison. However, only certain fields support hot-reload without a server restart:

| Field | Hot-Reloadable | Notes |
|-------|----------------|-------|
| `tls.cert`, `tls.key` | **Yes** | Automatic reload on change |
| All other fields | **No** | Requires server restart |

Non-hot-reloadable fields include: `jwt_secret`, `database_url`, `listen_addr`, `rp_id`, `rp_name`, `session_hours`, `cors_origins`, `allowed_domains`, `dpop.*`, OIDC settings, GitHub App settings, SSH CA key, and OIDC signing key.

Changes to non-hot-reloadable fields in S3 are silently ignored. A server restart is required to apply them.

## TLS Certificate Hot-Reload

Vouch supports automatic TLS certificate reloading without dropping connections:

1. **Via S3 polling** — Update `tls.cert` and `tls.key` in the S3 config; the server detects the change via ETag and reloads automatically.
2. **Via SIGHUP** — Send `SIGHUP` to the server process to reload TLS certificates.

```bash
# Manual TLS certificate reload (Unix only)
kill -SIGHUP $(pgrep vouch-server)
```

**Note:** SIGHUP only reloads TLS certificates. It does not reload any other configuration fields.
