# S3 Configuration Schema

For production deployments, Vouch supports loading configuration from an S3 object. This enables:

- **Centralized management** — Single source of truth for multi-instance deployments
- **Dynamic updates** — Configuration changes without server restart (for supported fields)
- **TLS hot-reload** — Automatic certificate rotation without downtime
- **Secrets management** — Leverage S3 server-side encryption and IAM for credential protection

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
  "dsql_endpoints": {
    "us-east-1": "postgres://vouch@abc123.dsql.us-east-1.on.aws/postgres"
  },
  "jwt_secret": "32+ character secret",
  "session_hours": 8,
  "org_name": "Example Corp",
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
  "ssh_ca_kms_key_id": "mrk-1234abcd5678efgh",
  "oidc_signing_key": "<base64-encoded PEM EC P-256 private key>",
  "oidc_signing_kms_key_id": "mrk-abcd1234efgh5678",
  "jwt_hmac_kms_key_id": "mrk-5678abcd1234efgh",
  "document_key": {
    "kms_key_id": "mrk-<key-id>",
    "encrypted_private_key": "<base64-encoded KMS ciphertext>"
  },
  "dpop": {
    "max_age_seconds": 300
  },
  "cors_origins": ["https://app.example.com"],
  "github": {
    "app_id": 12345,
    "app_name": "my-vouch-app",
    "app_key": "<PEM RSA private key>",
    "webhook_secret": "<secret>",
    "client_id": "<oauth-client-id>",
    "client_secret": "<oauth-client-secret>"
  },
  "cleanup_interval_minutes": 15,
  "auth_events_retention_days": 90,
  "oauth_events_retention_days": 90,
  "cli_download_macos": "https://example.com/vouch-macos",
  "cli_download_linux": "https://example.com/vouch-linux",
  "cli_download_windows": "https://example.com/vouch-windows",
  "device_code_expires_seconds": 600,
  "device_poll_interval_seconds": 5
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
| `dsql_endpoints` | object | Regional DSQL endpoints. Maps AWS region to full connection string. |
| `jwt_secret` | string | JWT signing secret (minimum 32 characters). Not required if `jwt_hmac_kms_key_id` is set. |
| `session_hours` | integer | Session duration in hours. |
| `org_name` | string | Organization display name for branding in the UI. |
| `tls.cert` | string | TLS certificate (base64-encoded PEM). |
| `tls.key` | string | TLS private key (base64-encoded PEM). |
| `oidc.issuer_url` | string | External OIDC issuer URL for enrollment. |
| `oidc.client_id` | string | OIDC client ID from the external identity provider. |
| `oidc.client_secret` | string | OIDC client secret from the external identity provider. |
| `allowed_domains` | array of strings | Allowed email domains for enrollment. |
| `ssh_ca_key` | string | SSH CA private key (base64-encoded PEM, Ed25519). |
| `ssh_ca_kms_key_id` | string | AWS KMS key ID for SSH CA signing (Ed25519). Overrides `ssh_ca_key`. |
| `oidc_signing_key` | string | OIDC signing key (base64-encoded PEM, P-256 ECDSA). |
| `oidc_signing_kms_key_id` | string | AWS KMS key ID for OIDC token signing (P-256). Overrides `oidc_signing_key`. |
| `jwt_hmac_kms_key_id` | string | AWS KMS key ID for HMAC state token signing. Overrides `jwt_secret`. |
| `document_key` | object | P-384 document encryption key. Contains `kms_key_id` and `encrypted_private_key`. |
| `dpop.max_age_seconds` | integer | Maximum age of DPoP proofs in seconds. |
| `cors_origins` | array of strings | CORS allowed origins. |
| `github.app_id` | integer | GitHub App ID. |
| `github.app_name` | string | GitHub App name (slug from `github.com/apps/{name}`). |
| `github.app_key` | string | GitHub App private key (PEM RSA). |
| `github.webhook_secret` | string | GitHub webhook secret for signature verification. |
| `github.client_id` | string | GitHub App OAuth client ID. |
| `github.client_secret` | string | GitHub App OAuth client secret. |
| `cleanup_interval_minutes` | integer | Background cleanup task interval in minutes. |
| `auth_events_retention_days` | integer | Retention period for authentication events in days. |
| `oauth_events_retention_days` | integer | Retention period for OAuth usage events in days. |
| `cli_download_macos` | string | CLI download URL for macOS, displayed in the server UI. |
| `cli_download_linux` | string | CLI download URL for Linux, displayed in the server UI. |
| `cli_download_windows` | string | CLI download URL for Windows, displayed in the server UI. |
| `device_code_expires_seconds` | integer | Device code expiration in seconds. |
| `device_poll_interval_seconds` | integer | Device code polling interval in seconds. |

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

Non-hot-reloadable fields include: `jwt_secret`, `database_url`, `listen_addr`, `rp_id`, `rp_name`, `session_hours`, `cors_origins`, `allowed_domains`, `dpop.*`, OIDC settings, GitHub App settings, SSH CA key, OIDC signing key, and all KMS key IDs.

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
