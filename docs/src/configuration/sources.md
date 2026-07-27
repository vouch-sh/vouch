# Configuration Sources

The Vouch server reads its configuration from three places. This chapter covers how they combine,
how S3-based configuration works, and which settings can change without a restart.

For the complete list of settings, see [Environment Variables](../reference/environment-variables.md)
and the [S3 Configuration Schema](../reference/s3-config-schema.md).

## Precedence

1. **S3 configuration** (highest) — a JSON object fetched from S3 at startup
2. **Command-line arguments** — `--kebab-case` flags passed to `vouch-server serve`
3. **Environment variables** — `VOUCH_*` prefixed

Every setting is available in all three forms. The command-line flags and environment variables
are the same options: each flag declares an environment variable as its fallback, so passing
`--session-hours 4` overrides `VOUCH_SESSION_HOURS=8`. S3 configuration is applied last and
overwrites whatever the flags and environment produced.

A `.env` file in the working directory is loaded before parsing, so values in it behave exactly
like environment variables.

> **Note**: S3 overriding the environment is the opposite of what most tools do, and it is
> deliberate — it lets a fleet share one authoritative document while the environment supplies
> only per-instance values. If a setting is not taking effect, check whether the S3 document is
> also setting it.

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

The document is a JSON object; see the
[S3 Configuration Schema](../reference/s3-config-schema.md) for every field, its type, and its
default. All certificate and key fields are base64-encoded PEM:

```bash
# Encode a PEM file for the S3 config
base64 -i cert.pem | tr -d '\n'
```

### Bucket requirements

The configuration document contains the JWT secret, IdP client secrets, and private keys. Treat
the bucket accordingly:

| Requirement | Why |
|-------------|-----|
| Server-side encryption | The document holds secrets at rest |
| Block Public Access | It must never be reachable anonymously |
| Least-privilege IAM | The server needs only `s3:GetObject` and `s3:HeadObject` |
| Versioning | Gives you rollback and a change trail |
| Access logging | Lets you detect unauthorized reads |

A minimal bucket policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/vouch-server"},
      "Action": ["s3:GetObject", "s3:HeadObject"],
      "Resource": "arn:aws:s3:::my-bucket/config/vouch-server.json"
    }
  ]
}
```

### Polling behavior

- **ETag-based** — a `HEAD` request checks for a change before any full `GET`.
- **Fail-fast at startup** — if S3 configuration is enabled and the object cannot be fetched or
  parsed, the server refuses to start.
- **Fail-open at runtime** — if S3 becomes unreachable later, the server keeps running with the
  configuration it already has.
- **No stale writes** — configuration is only replaced after a successful fetch and parse.

## AWS KMS Signing Keys

As an alternative to managing local key material, Vouch supports AWS KMS for signing operations:

| Environment Variable | Key Type | Replaces |
|---------------------|----------|----------|
| `VOUCH_SSH_CA_KMS_KEY_ID` | Ed25519 (`ECC_EDWARDS_CURVE_25519`) | `VOUCH_SSH_CA_KEY` / `VOUCH_SSH_CA_KEY_PATH` |
| `VOUCH_OIDC_SIGNING_KMS_KEY_ID` | P-256 (`ECC_NIST_P256`) | `VOUCH_OIDC_SIGNING_KEY` |
| `VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID` | RSA-3072 (`RSA_3072`) | `VOUCH_OIDC_RSA_SIGNING_KEY` |
| `VOUCH_JWT_HMAC_KMS_KEY_ID` | HMAC-256 (`HMAC_256`) | `VOUCH_JWT_SECRET` |

Multi-region keys (`mrk-` prefix) are recommended for high availability. KMS key IDs can also be set in the S3 config (`ssh_ca_kms_key_id`, `oidc_signing_kms_key_id`, `jwt_hmac_kms_key_id`).

See [Key Management](keys.md) for generation and rotation details.

## Hot-Reloadable vs Startup-Only Fields

| Field | Hot-Reloadable | Notes |
|-------|----------------|-------|
| `tls.cert`, `tls.key` | Yes | Automatic reload on change |
| All other fields | **No** | Requires server restart |

Non-hot-reloadable fields include: `jwt_secret`, `database_url`, `listen_addr`, `rp_id`, `rp_name`, `session_hours`, `cors_origins`, `allowed_domains`, `dpop.*`, OIDC settings, SAML settings, GitHub App settings, SSH CA key, OIDC signing keys, and all KMS key IDs.

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
