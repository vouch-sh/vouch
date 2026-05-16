# Environment Variables

All Vouch server configuration is done via environment variables (prefixed with `VOUCH_`). These can also be passed as command-line arguments.

## Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_RP_ID` | Yes | `localhost` | Relying Party ID (domain, e.g., `vouch.sh`). Used as the WebAuthn RP ID. |
| `VOUCH_RP_NAME` | No | `Vouch` | Relying Party display name shown in browser prompts and UI. |
| `VOUCH_DATABASE_URL` | Yes | `sqlite:vouch.db?mode=rwc` | Database connection URL. Supports `sqlite:`, `postgres:`, and Aurora DSQL endpoints. |
| `VOUCH_JWT_SECRET` | **Conditional** | _(empty)_ | JWT signing secret. **Must be at least 32 characters.** Must not consist of a single repeated character. Used to sign internal state tokens. Required unless `VOUCH_JWT_HMAC_KMS_KEY_ID` is set. |
| `VOUCH_BASE_URL` | No | `https://{rp_id}` | Base URL for this server. Auto-derived from `VOUCH_RP_ID` if not set (`http://localhost:{port}` for local dev, `https://{rp_id}` for production). |
| `VOUCH_ORG_NAME` | No | _(none)_ | Organization name for branding in the UI. Falls back to `VOUCH_RP_NAME` if not set. |
| `VOUCH_ALLOWED_DOMAINS` | No | _(none)_ | Comma-separated list of allowed email domains for enrollment (e.g., `example.com,corp.example.com`). If not set, all domains are allowed. Normalized to lowercase. |

## Network

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_LISTEN_ADDR` | No | `[::]:3000` | Address and port to listen on. Ignored when TLS is configured (server listens on 443 instead). |

## Upstream Identity Provider

Vouch can be configured with **one** upstream IdP using the legacy shorthand (`VOUCH_OIDC_*` xor `VOUCH_SAML_*`), or **multiple** IdPs side-by-side using the slug-prefixed form (`VOUCH_IDPS` + `VOUCH_IDP_<SLUG>_*`). The two forms can coexist — the legacy shorthand becomes the entry with slug `default`, and slug-form entries add buttons to the landing page picker.

### OIDC (single-IdP shorthand)

These variables configure a single external OpenID Connect identity provider for enrollment. All three must be set together for OIDC enrollment to work. At startup, the server fetches the OIDC discovery document from `{issuer}/.well-known/openid-configuration` to auto-discover authorization, token, and JWKS endpoints. When set, the entry is registered under slug `default`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_OIDC_ISSUER` | No | _(none)_ | OIDC issuer URL (e.g., `https://accounts.google.com`). Must serve a valid OIDC discovery document. |
| `VOUCH_OIDC_CLIENT_ID` | No | _(none)_ | OIDC client ID from the external identity provider. |
| `VOUCH_OIDC_CLIENT_SECRET` | No | _(none)_ | OIDC client secret from the external identity provider. |

### SAML (single-IdP shorthand)

These variables configure a single external SAML 2.0 identity provider for enrollment. `VOUCH_SAML_IDP_METADATA_URL` is required for SAML; the others are optional. When set, the entry is registered under slug `default`. `VOUCH_OIDC_*` and `VOUCH_SAML_*` cannot both be set — to mix OIDC and SAML upstreams, use the multi-IdP form below.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SAML_IDP_METADATA_URL` | No | _(none)_ | URL to the SAML IdP metadata XML document. Fetched at server startup. |
| `VOUCH_SAML_SP_ENTITY_ID` | No | `{VOUCH_BASE_URL}` | SAML SP entity ID sent in authentication requests. Defaults to the server's base URL. |
| `VOUCH_SAML_EMAIL_ATTRIBUTE` | No | _(auto-detect)_ | SAML attribute name containing the user's email address. |
| `VOUCH_SAML_DOMAIN_ATTRIBUTE` | No | _(none)_ | SAML attribute name containing the user's domain (for domain restriction). |

### Multiple Identity Providers

Set `VOUCH_IDPS` to a comma-separated list of slugs to register **additional** IdPs alongside the legacy shorthand. Each slug enables a `VOUCH_IDP_<SLUG>_*` family of variables. The landing page renders one button per registered IdP; users pick which one to sign in with.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDPS` | No | _(none)_ | Comma-separated list of slugs. Each must match `[a-z0-9_-]+`, 1–32 chars. The slug `default` is reserved for the legacy shorthand. Duplicate slugs are rejected. |

For each slug `<SLUG>` listed in `VOUCH_IDPS`, set **either** the OIDC fields or the SAML fields (presence of `_ISSUER` selects OIDC; presence of `_METADATA_URL` selects SAML). Setting both on the same slug is rejected.

**OIDC slug:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDP_<SLUG>_ISSUER` | Yes (OIDC) | _(none)_ | OIDC issuer URL. Triggers discovery at startup. |
| `VOUCH_IDP_<SLUG>_CLIENT_ID` | Yes (OIDC) | _(none)_ | OAuth client ID. |
| `VOUCH_IDP_<SLUG>_CLIENT_SECRET` | Yes (OIDC) | _(none)_ | OAuth client secret. |
| `VOUCH_IDP_<SLUG>_ALLOWED_DOMAINS` | No | _(none)_ | Comma-separated email-domain allowlist for this IdP. Narrows `VOUCH_ALLOWED_DOMAINS`; does not widen it. |
| `VOUCH_IDP_<SLUG>_ALLOWED_TENANTS` | No | _(none)_ | Microsoft Entra only: comma-separated tenant GUID allowlist. Only consulted when the discovered issuer is multi-tenant Entra (`/common/v2.0` or `/organizations/v2.0`); silently ignored for any other IdP. |

**SAML slug:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDP_<SLUG>_METADATA_URL` | Yes (SAML) | _(none)_ | URL to the SAML IdP metadata XML document. |
| `VOUCH_IDP_<SLUG>_SP_ENTITY_ID` | No | `{VOUCH_BASE_URL}` | SP entity ID for this IdP. |
| `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` | No | _(auto-detect)_ | SAML attribute name carrying email. |
| `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` | No | _(none)_ | SAML attribute name carrying domain. |
| `VOUCH_IDP_<SLUG>_ALLOWED_DOMAINS` | No | _(none)_ | Comma-separated email-domain allowlist for this IdP. |

**Example: Google (legacy) + Microsoft Entra (slug-form):**

```bash
# Legacy Google entry (slug = "default")
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=...
VOUCH_OIDC_CLIENT_SECRET=...

# Add a multi-tenant Entra entry (slug = "microsoft")
VOUCH_IDPS=microsoft
VOUCH_IDP_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
VOUCH_IDP_MICROSOFT_CLIENT_ID=...
VOUCH_IDP_MICROSOFT_CLIENT_SECRET=...
```

## Session

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SESSION_HOURS` | No | `8` | Session duration in hours. After this time, the user must re-authenticate. |
| `VOUCH_DEVICE_CODE_EXPIRES` | No | `600` | Device code expiration in seconds. How long a device code remains valid during enrollment. |
| `VOUCH_DEVICE_POLL_INTERVAL` | No | `5` | Device code polling interval in seconds. How frequently the CLI polls for device code completion. |

## SSH CA

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SSH_CA_KEY` | No | _(none)_ | SSH CA private key content (base64-encoded PEM format, Ed25519). If set, takes precedence over `VOUCH_SSH_CA_KEY_PATH`. |
| `VOUCH_SSH_CA_KEY_PATH` | No | `./ssh_ca_key` | Path to SSH CA private key file (raw PEM, not base64). Set to empty string to disable SSH CA entirely. |

## OIDC Signing

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_OIDC_SIGNING_KEY` | No | _(auto-generate)_ | OIDC signing key content (base64-encoded PEM format, P-256 ECDSA). Used for signing access tokens and ID tokens with ES256 algorithm. If not set, an ephemeral key is generated on each server restart (not recommended for production). |
| `VOUCH_OIDC_RSA_SIGNING_KEY` | No | _(auto-generate)_ | OIDC RSA signing key content (base64-encoded PEM format, RSA-3072). Used for signing ID tokens with RS256 algorithm per OIDC Core Section 3.1.3.7. Minimum 3072-bit key enforced. If not set, an ephemeral key is generated on each server restart. |

## AWS KMS

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SSH_CA_KMS_KEY_ID` | No | _(none)_ | AWS KMS key ID for SSH CA signing (Ed25519). When set, overrides `VOUCH_SSH_CA_KEY` and `VOUCH_SSH_CA_KEY_PATH`. |
| `VOUCH_OIDC_SIGNING_KMS_KEY_ID` | No | _(none)_ | AWS KMS key ID for OIDC token signing (P-256 ECDSA). When set, overrides `VOUCH_OIDC_SIGNING_KEY`. |
| `VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID` | No | _(none)_ | AWS KMS key ID for OIDC RSA token signing (RSA-3072, `RSASSA_PKCS1_V1_5_SHA_256`). When set, overrides `VOUCH_OIDC_RSA_SIGNING_KEY`. |
| `VOUCH_JWT_HMAC_KMS_KEY_ID` | No | _(none)_ | AWS KMS key ID for HMAC state token signing. When set, `VOUCH_JWT_SECRET` is not required. |

## DPoP

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_DPOP_MAX_AGE` | No | `300` | Maximum age of DPoP proofs in seconds. Proofs older than this are rejected. |

## Cleanup & Retention

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CLEANUP_INTERVAL` | No | `15` | Background cleanup task interval in minutes. Set to `0` to disable automatic cleanup. |
| `VOUCH_AUTH_EVENTS_RETENTION_DAYS` | No | `90` | Retention period for authentication events in days. Events older than this are purged during cleanup. |
| `VOUCH_OAUTH_EVENTS_RETENTION_DAYS` | No | `90` | Retention period for OAuth usage events in days. Events older than this are purged during cleanup. |

## CORS

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CORS_ORIGINS` | No | _(none)_ | Comma-separated list of CORS allowed origins. Empty means same-origin only. Use `*` to allow all origins (not recommended for production). |

## GitHub App

These variables configure the Vouch GitHub App integration for issuing GitHub tokens. The App ID, name, and key are required together for GitHub App functionality. OAuth client ID and secret are additionally needed for GitHub user authentication.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_GITHUB_APP_ID` | No | _(none)_ | GitHub App ID (numeric, assigned when creating the app on github.com). |
| `VOUCH_GITHUB_APP_NAME` | No | _(none)_ | GitHub App name (the slug from `github.com/apps/{name}`). |
| `VOUCH_GITHUB_APP_KEY` | No | _(none)_ | GitHub App private key (PEM format, RSA). Can use literal `\n` for newlines. |
| `VOUCH_GITHUB_WEBHOOK_SECRET` | No | _(none)_ | GitHub webhook secret for verifying webhook signatures (HMAC-SHA256). |
| `VOUCH_GITHUB_APP_CLIENT_ID` | No | _(none)_ | GitHub App Client ID for OAuth user authentication. Found in GitHub App settings (different from the numeric App ID). |
| `VOUCH_GITHUB_APP_CLIENT_SECRET` | No | _(none)_ | GitHub App Client Secret for OAuth user authentication. |

## TLS

When both `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY` are set, the server listens on port 443 (HTTPS) with an automatic HTTP-to-HTTPS redirect on port 80. The `VOUCH_LISTEN_ADDR` setting is ignored when TLS is configured.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_TLS_CERT` | No | _(none)_ | TLS certificate (base64-encoded PEM). |
| `VOUCH_TLS_KEY` | No | _(none)_ | TLS private key (base64-encoded PEM). Required if `VOUCH_TLS_CERT` is set. |

## S3 Configuration

Vouch supports loading configuration from an S3 object for centralized management. S3 configuration values override environment variables.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_S3_CONFIG_BUCKET` | No | _(none)_ | S3 bucket name for configuration file. If set, config is loaded from S3. |
| `VOUCH_S3_CONFIG_KEY` | No | `config/vouch-server.json` | S3 object key for configuration file. |
| `VOUCH_S3_CONFIG_REGION` | No | _(auto)_ | AWS region for S3 access. Uses the default credential chain region if not set. |
| `VOUCH_S3_CONFIG_POLL_INTERVAL` | No | `60` | S3 config polling interval in seconds. How frequently the server checks for configuration changes. |

## JWT Assertion

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_JWT_ASSERTION_MAX_LIFETIME` | No | `300` | Maximum lifetime (seconds) for `private_key_jwt` client-authentication JWT assertions (RFC 7523 §2.2 / §3). Assertions older than this are rejected. |

## Protected Resource Metadata (RFC 9728)

These optional variables configure descriptive metadata published in the OAuth 2.0 Protected Resource Metadata document at `/.well-known/oauth-protected-resource`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_RESOURCE_NAME` | No | `Vouch` | Human-readable name of this protected resource. |
| `VOUCH_RESOURCE_DOCUMENTATION` | No | `https://vouch.sh/docs/` | URL of developer documentation for this protected resource. |
| `VOUCH_RESOURCE_POLICY_URI` | No | `https://vouch.sh/privacy/` | URL of the resource's data-use policy. |
| `VOUCH_RESOURCE_TOS_URI` | No | `https://vouch.sh/terms/` | URL of the resource's terms of service. |

## CLI Download URLs

These optional variables configure download links displayed in the server UI.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CLI_DOWNLOAD_MACOS` | No | _(none)_ | CLI download URL for macOS, displayed in the server UI. |
| `VOUCH_CLI_DOWNLOAD_LINUX` | No | _(none)_ | CLI download URL for Linux, displayed in the server UI. |
| `VOUCH_CLI_DOWNLOAD_WINDOWS` | No | _(none)_ | CLI download URL for Windows, displayed in the server UI. |
