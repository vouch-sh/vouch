# S3 Configuration Schema

The complete field reference for the S3 configuration document.

For how S3 configuration fits with environment variables and command-line flags, how to enable
it, the bucket requirements, and the polling behavior, see
[Configuration Sources](../configuration/sources.md).

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
  "idps": [
    {
      "id": "google",
      "type": "oidc",
      "issuer": "https://accounts.google.com",
      "client_id": "...",
      "client_secret": "..."
    },
    {
      "id": "corp-saml",
      "type": "saml",
      "metadata_url": "https://idp.example.com/saml/metadata",
      "sp_entity_id": "https://vouch.example.com",
      "email_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "domain_attribute": "department"
    }
  ],
  "allowed_domains": ["example.com"],
  "ssh_ca_key": "<base64-encoded PEM Ed25519 private key>",
  "ssh_ca_kms_key_id": "mrk-1234abcd5678efgh",
  "oidc_signing_key": "<base64-encoded PEM EC P-256 private key>",
  "oidc_signing_kms_key_id": "mrk-abcd1234efgh5678",
  "oidc_rsa_signing_key": "<base64-encoded PEM RSA-3072 private key>",
  "oidc_rsa_signing_kms_key_id": "mrk-rsa1234abcd5678",
  "jwt_hmac_kms_key_id": "mrk-5678abcd1234efgh",
  "document_key": {
    "kms_key_id": "mrk-<key-id>",
    "encrypted_private_key": "<base64-encoded KMS ciphertext>",
    "algorithm": "p384"
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
  "resource_name": "Vouch",
  "resource_documentation": "https://vouch.sh/docs/",
  "resource_policy_uri": "https://vouch.sh/privacy/",
  "resource_tos_uri": "https://vouch.sh/terms/",
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
| `idps[]` | array of objects | Configured identity providers (OIDC + SAML). Order controls login-page button order. Each entry has `id`, `type` (`"oidc"` or `"saml"`), and type-specific fields. |
| `idps[].id` | string | Operator-chosen slug (`[a-z0-9-]{1,32}`, no leading/trailing hyphen, unique). Used in the state table, callback routing, and audit logs. |
| `idps[].type` | string | `"oidc"` or `"saml"`. |
| `idps[].issuer` (OIDC) | string | OIDC issuer URL. The server auto-discovers endpoints. |
| `idps[].client_id` (OIDC) | string | OIDC client ID from the IdP. |
| `idps[].client_secret` (OIDC) | string | OIDC client secret from the IdP. |
| `idps[].metadata_url` (SAML) | string | URL to the SAML IdP metadata XML document. |
| `idps[].sp_entity_id` (SAML) | string | SP entity ID (defaults to `base_url`). |
| `idps[].email_attribute` (SAML) | string | SAML attribute name for email extraction. |
| `idps[].domain_attribute` (SAML) | string | SAML attribute name for domain extraction. |
| `allowed_domains` | array of strings | Allowed email domains for enrollment. |
| `ssh_ca_key` | string | SSH CA private key (base64-encoded PEM, Ed25519). |
| `ssh_ca_kms_key_id` | string | AWS KMS key ID for SSH CA signing (Ed25519). Overrides `ssh_ca_key`. |
| `oidc_signing_key` | string | OIDC signing key (base64-encoded PEM, P-256 ECDSA). |
| `oidc_signing_kms_key_id` | string | AWS KMS key ID for OIDC token signing (P-256). Overrides `oidc_signing_key`. |
| `oidc_rsa_signing_key` | string | OIDC RSA signing key (base64-encoded PEM, RSA-3072). Signs ID tokens with RS256. |
| `oidc_rsa_signing_kms_key_id` | string | AWS KMS key ID for OIDC RSA signing (RSA-3072). Overrides `oidc_rsa_signing_key`. |
| `jwt_hmac_kms_key_id` | string | AWS KMS key ID for HMAC state token signing. Overrides `jwt_secret`. |
| `document_key` | object | Document encryption key. Contains `kms_key_id`, `encrypted_private_key`, and optional `algorithm` (default `"p384"`, currently the only value). |
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
| `oauth_events_retention_days` | integer | Retention period for OAuth usage and credential-issuance (`aws_credential`, `github_credential`, `ssh_credential`, `token_exchange`) events in days. |
| `resource_name` | string | Human-readable name of this protected resource (RFC 9728). Defaults to `"Vouch"`. |
| `resource_documentation` | string | URL of developer documentation for this protected resource (RFC 9728). Defaults to `"https://vouch.sh/docs/"`. |
| `resource_policy_uri` | string | URL of the resource's data-use policy (RFC 9728). Defaults to `"https://vouch.sh/privacy/"`. |
| `resource_tos_uri` | string | URL of the resource's terms of service (RFC 9728). Defaults to `"https://vouch.sh/terms/"`. |
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

Only `tls.cert` and `tls.key` are applied while the server is running. Every other field in this
document takes effect at startup only, and changes to them are ignored — silently — until the
server restarts. See
[Configuration Sources](../configuration/sources.md#hot-reloadable-vs-startup-only-fields).
