# Environment Variables

Every server setting listed here is available three ways: as a `VOUCH_`-prefixed environment
variable, as an equivalent `--kebab-case` command-line flag, and as a field in the
[S3 configuration document](s3-config-schema.md). An explicit flag beats the environment variable;
S3 configuration beats both. See [Configuration Sources](../configuration/sources.md).

A few variables the server reads are not `VOUCH_`-prefixed — `RUST_LOG`, the `OTEL_*` and `AWS_*`
families, and `DSQL_USER`. They are listed in their relevant sections below.

## Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_RP_ID` | No | `localhost` | Relying Party ID (domain, e.g. `auth.example.com`). Used as the WebAuthn RP ID. The default only works for local development — set it for any real deployment, because WebAuthn credentials are bound to it and changing it later invalidates every enrolled authenticator. |
| `VOUCH_RP_NAME` | No | `Vouch` | Relying Party display name shown in browser prompts and UI. |
| `VOUCH_DATABASE_URL` | No | `sqlite:vouch.db?mode=rwc` | Database connection URL. Supports `sqlite:`, `postgres:`, and Aurora DSQL endpoints. The default creates a SQLite file in the process working directory — set it explicitly so the database does not land somewhere transient. |
| `VOUCH_JWT_SECRET` | **Conditional** | _(empty)_ | JWT signing secret. **Must be at least 32 characters.** Must not consist of a single repeated character. Used to sign internal state tokens. Required unless `VOUCH_JWT_HMAC_KMS_KEY_ID` is set. |
| `VOUCH_BASE_URL` | No | `https://{rp_id}` | Base URL for this server. Auto-derived from `VOUCH_RP_ID` if not set (`http://localhost:{port}` for local dev, `https://{rp_id}` for production). |
| `VOUCH_ORG_NAME` | No | _(none)_ | Organization name for branding in the UI. Falls back to `VOUCH_RP_NAME` if not set. |
| `VOUCH_ALLOWED_DOMAINS` | No | _(none)_ | Comma-separated list of allowed email domains for enrollment (e.g., `example.com,corp.example.com`). If not set, all domains are allowed. Normalized to lowercase. |

## Network

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_LISTEN_ADDR` | No | `[::]:3000` | Address and port to listen on. **Ignored when TLS is configured** — the server then binds 443 and 80 unconditionally. |
| `VOUCH_MTLS_PORT` | No | `8443` | Port for the mTLS listener used by RFC 8705 certificate-bound tokens. The listener starts automatically whenever TLS is configured; there is no flag to disable it, and a bind failure here is fatal. |
| `VOUCH_TRUSTED_PROXIES` | No | _(empty)_ | Comma-separated CIDRs of trusted reverse proxies (e.g. `10.0.0.0/8`). When empty, `X-Forwarded-For` is ignored entirely and the TCP peer is treated as the client — which behind a load balancer means **every user shares one rate-limit bucket**. An invalid CIDR is a fatal startup error. See [Behind a Reverse Proxy](../configuration/reverse-proxy.md). |
| `VOUCH_EXTRA_CA_CERTS` | No | _(none)_ | Path to a PEM bundle of additional certificate authorities for the server's outbound HTTPS client. Needed when your IdP, or another service the server calls, uses an internal CA. An unreadable file is a fatal startup error. |

## Upstream Identity Provider

Configure one or more upstream IdPs (OIDC, SAML, or any mix) as a single unified list. `VOUCH_IDPS` holds a comma-separated list of slugs; each slug picks up its `VOUCH_IDP_<SLUG>_*` variables. Slugs match `[a-z0-9-]{1,32}` (no leading or trailing hyphen) and must be unique.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDPS` | Yes | _(none)_ | Comma-separated list of IdP slugs in display order (e.g., `google,entra,corp-saml`). At least one slug is required; the server refuses to start otherwise. |
| `VOUCH_IDP_<SLUG>_TYPE` | Yes (per IdP) | _(none)_ | `oidc` or `saml`. |

Hyphens in slugs become underscores in variable names: a slug of `corp-saml` becomes `VOUCH_IDP_CORP_SAML_*`.

### OIDC IdP (per slug)

OIDC IdPs auto-discover authorization, token, and JWKS endpoints from `{issuer}/.well-known/openid-configuration` at startup.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDP_<SLUG>_ISSUER` | Yes | _(none)_ | OIDC issuer URL (e.g., `https://accounts.google.com`). Must serve a valid OIDC discovery document. |
| `VOUCH_IDP_<SLUG>_CLIENT_ID` | Yes | _(none)_ | OIDC client ID from the IdP. |
| `VOUCH_IDP_<SLUG>_CLIENT_SECRET` | Yes | _(none)_ | OIDC client secret from the IdP. |

### SAML IdP (per slug)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDP_<SLUG>_METADATA_URL` | Yes | _(none)_ | URL to the SAML IdP metadata XML document. Fetched at server startup. |
| `VOUCH_IDP_<SLUG>_SP_ENTITY_ID` | No | `{VOUCH_BASE_URL}` | SP entity ID sent in authentication requests. Defaults to the server's base URL. |
| `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` | No | _(auto-detect)_ | SAML attribute name containing the user's email address. |
| `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` | No | _(none)_ | SAML attribute name containing the user's domain (for domain restriction). |

## Session

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SESSION_HOURS` | No | `8` | Session duration in hours. After this time, the user must re-authenticate. |
| `VOUCH_DEVICE_CODE_EXPIRES` | No | `600` | Device code expiration in seconds. How long a device code remains valid during enrollment. |
| `VOUCH_DEVICE_POLL_INTERVAL` | No | `5` | Device code polling interval in seconds. How frequently the CLI polls for device code completion. |
| `VOUCH_SESSION_CACHE_MAX_CAPACITY` | No | `10000` | Maximum entries in the in-memory session lookup cache. |
| `VOUCH_SESSION_CACHE_TTL_SECS` | No | `30` | How long a cached session lookup stays valid. Raising it reduces database reads; lowering it shortens the window in which a revoked session is still honored by an instance. |

## SSH CA

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SSH_CA_KEY` | No | _(none)_ | SSH CA private key content (Ed25519, OpenSSH format). Accepts either raw PEM or base64-encoded PEM — the server detects which by looking for the `-----BEGIN` header. If set, takes precedence over `VOUCH_SSH_CA_KEY_PATH`. |
| `VOUCH_SSH_CA_KEY_PATH` | No | `./ssh_ca_key` | Path to SSH CA private key file (raw PEM). Set to an empty string to disable the SSH CA entirely. **If the file does not exist, the server generates a new Ed25519 CA key and writes it to this path** — see the warning below. |

> **Warning**: because a missing `VOUCH_SSH_CA_KEY_PATH` file causes the server to generate a new
> CA key, starting on a fresh or unmounted volume silently rotates your SSH CA. Every host's
> `TrustedUserCAKeys` entry then stops matching and users cannot log in with newly issued
> certificates. Either provision the key file before first start, or supply the key through
> `VOUCH_SSH_CA_KEY` / `VOUCH_SSH_CA_KMS_KEY_ID`, which never auto-generate.

## OIDC Signing

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_OIDC_SIGNING_KEY` | No | _(auto-generate)_ | OIDC signing key content (base64-encoded PEM format, P-256 ECDSA). Used for signing access tokens and ID tokens with ES256 algorithm. If not set, an ephemeral key is generated on each server restart (not recommended for production). |
| `VOUCH_OIDC_RSA_SIGNING_KEY` | No | _(auto-generate)_ | OIDC RSA signing key content (base64-encoded PEM format, RSA-3072). Used for signing ID tokens with RS256 algorithm per OIDC Core Section 3.1.3.7 and all AWS credential tokens (`/v1/credentials/aws/token`, serving both STS `AssumeRoleWithWebIdentity` and IAM Identity Center `CreateTokenWithIAM`). Minimum 3072-bit key enforced. If not set, an ephemeral key is generated on each server restart — AWS token verification then breaks after restarts and across multiple instances, so any deployment using the AWS integration must set this (or the KMS variant). |

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
| `VOUCH_OAUTH_EVENTS_RETENTION_DAYS` | No | `90` | Retention period for OAuth usage and credential-issuance (`aws_credential`, `github_credential`, `ssh_credential`, `token_exchange`) events in days. Events older than this are purged during cleanup. |

## CORS

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CORS_ORIGINS` | No | _(none)_ | Comma-separated list of explicit CORS allowed origins for UI routes (e.g. `https://app.example.com`). Empty means same-origin only. Wildcard (`*`) is not supported — UI routes use credentialed cookie sessions, which are incompatible with wildcard origins per the CORS spec. |

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

> **Self-hosters should override the last three.** Their defaults point at Vouch's own site, so a
> deployment that leaves them alone publishes Vouch's documentation, privacy policy, and terms as
> its own in a document clients read to learn who operates the resource. Point them at your
> organization's pages.
>
> The same applies to the `/privacy` and `/terms` UI routes, which are fixed redirects to
> `vouch.sh`. Override those at your reverse proxy if you need your own.

## CLI Download URLs

These optional variables configure download links displayed in the server UI.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CLI_DOWNLOAD_MACOS` | No | _(none)_ | CLI download URL for macOS, displayed in the server UI. |
| `VOUCH_CLI_DOWNLOAD_LINUX` | No | _(none)_ | CLI download URL for Linux, displayed in the server UI. |
| `VOUCH_CLI_DOWNLOAD_WINDOWS` | No | _(none)_ | CLI download URL for Windows, displayed in the server UI. |

## Database Tuning

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_DB_MAX_CONNECTIONS` | No | `25` | Maximum size of the connection pool. Multiply by your instance count when sizing PostgreSQL's `max_connections`. |
| `VOUCH_DB_MIN_CONNECTIONS` | No | `2` | Minimum idle connections kept open. |
| `VOUCH_DB_IDLE_TIMEOUT_SECS` | No | `300` | How long an idle connection is kept before being closed. |
| `VOUCH_DB_ACQUIRE_TIMEOUT_SECS` | No | `5` | How long a request waits for a free connection before failing. |
| `DSQL_USER` | No | `admin` | **Not `VOUCH_`-prefixed.** Database username for Aurora DSQL when the connection URL carries none. |

## Authenticator Policy

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_ALLOWED_AAGUIDS` | No | _(empty — any)_ | Which authenticator models may enroll. Accepts `fips-only`, `yubikey-5`, or a comma-separated list of AAGUID UUIDs. Empty means any hardware authenticator. A non-UUID entry in a list is a fatal startup error. |
| `VOUCH_REQUIRE_ATTESTATION_CERT` | No | `false` | Reject self-attestation, requiring a full attestation certificate chain. Enable alongside `VOUCH_ALLOWED_AAGUIDS` if you rely on the model restriction, since self-attested AAGUIDs are unverified. |

Regardless of these settings, software authenticators are always rejected: the `none` attestation
format is refused, so only hardware-backed credentials can enroll. See
[Security Hardening](../operations/security-hardening.md#authenticator-policy).

## Observability

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_LOG_FORMAT` | No | `text` | Log output format: `text` or `json`. Any other value is a fatal startup error. |
| `VOUCH_METRICS_BEARER_TOKEN` | No | _(none)_ | Bearer token protecting `GET /metrics`. **When unset, the metrics endpoint is not registered at all.** |
| `RUST_LOG` | No | `info` | **Not `VOUCH_`-prefixed.** Standard `EnvFilter` directive, e.g. `info,vouch_server=debug`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | _(none)_ | **Not `VOUCH_`-prefixed.** OTLP/gRPC collector endpoint. When unset, span export is disabled entirely. When set but unreachable at startup, the server fails to start. |
| `OTEL_SERVICE_NAME` | No | `vouch-server` | **Not `VOUCH_`-prefixed.** Service name attached to exported spans. |

See [Monitoring and Metrics](../operations/monitoring.md).

## AWS Environment

These are read by the AWS SDK or by Vouch's AWS-specific resolution logic. None are
`VOUCH_`-prefixed.

| Variable | Used for |
|----------|----------|
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region for KMS and S3, and for resolving `dsql_endpoints` |
| `AWS_AZ` | Availability zone, checked first when resolving `dsql_endpoints` |
| `AWS_PARTITION` | Partition segment (`aws`, `aws-us-gov`) when building cross-account KMS ARNs |
| `AWS_USE_FIPS_ENDPOINT` | Whether AWS SDK clients (S3, KMS) use FIPS endpoints |

On EC2, `AWS_REGION`, `AWS_AZ`, and `AWS_PARTITION` fall back to IMDS
(`placement/region`, `placement/availability-zone`, `services/partition`) when unset —
see [EC2 instance bootstrap](#ec2-instance-bootstrap) below. `AWS_PARTITION` has no IMDS
equivalent on older instance generations (`services/partition` 404s), in which case
cross-account KMS ARN construction is skipped.

## EC2 Instance Bootstrap

On EC2, `vouch-server` performs its own bootstrap at startup before building
`ServerConfig`: it reads the region, availability zone, and partition from IMDSv2, then
fetches a `KEY=VALUE` configuration blob from AWS Systems Manager Parameter Store
(`ssm:GetParameter` with decryption) and applies it as a config layer strictly *below*
CLI flags and process environment variables — an explicit `--flag` or a real env var
always wins over the parameter; only variables the operator hasn't already set are
filled in.

- **Parameter name.** Read from the `VouchConfigParameter` EC2 instance tag (requires
  the instance to have been launched with `--metadata-options
  'InstanceMetadataTags=enabled'`). The tag is the opt-in: when it is not visible, the
  SSM fetch is skipped and the server keeps only the IMDS-derived instance facts,
  starting from CLI flags and process environment.
- **Format.** Strict `KEY=VALUE` lines, one per line, with `#` comments and blank lines
  allowed — the same format systemd's `EnvironmentFile=` accepts. No `export ` prefix, no
  CRLF line endings, no quoted values; any of these is a hard startup error rather than a
  silent misparse.
- **Scope.** Only variables backed by a `vouch-server` CLI flag (every `VOUCH_*`
  variable in this reference, plus `AWS_REGION`/`AWS_AZ`/`AWS_PARTITION`/
  `AWS_USE_FIPS_ENDPOINT`) are read from the parameter. Anything else in the blob
  (for example a stray `RUST_LOG`) is ignored, since it was never real process
  environment to begin with. In particular, use `AWS_REGION` — not
  `AWS_DEFAULT_REGION` — in the parameter: the alias is honored only as a real
  environment variable, and inside the blob it is ignored in favor of the
  IMDS-derived region.
- **Never running on EC2 (IMDS unreachable), or `AWS_EC2_METADATA_DISABLED=true`.**
  Bootstrap is skipped entirely and the server starts from CLI flags and process
  environment only, same as a non-EC2 deployment.
- **On EC2 but the SSM call fails.** This is treated as a startup failure (never a
  silent fallback to an unconfigured server) — the log records a `VOUCH_BOOTSTRAP_FAILED`
  line naming the parameter and region. The unit's `Restart=always` retries transient
  failures (e.g. SSM throttling); a persistent failure means the instance never becomes
  healthy, which an Auto Scaling Group replaces.
- **Already configured via env/CLI.** If the S3 config bucket is already set (the
  `VOUCH_S3_CONFIG_BUCKET` variable or the `--s3-config-bucket` flag), the IMDS probe
  is skipped entirely, so non-EC2 and fully env-configured deployments pay nothing.

## Test Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_CERTIFICATION_TEST_TOKEN` | No | _(none)_ | **Never set in production.** Enables OpenID conformance test mode: registers a login-bypass route, **disables all rate limiting**, and relaxes the requirement for an upstream IdP. The server logs a security warning at startup when it is set. |

## Startup Validation

The server refuses to start when any of the following holds. Each produces a message naming the
offending variable.

| Condition | Message |
|-----------|---------|
| `VOUCH_IDPS` empty or unset | `No upstream IdP configured. Set VOUCH_IDPS=<slug>[,<slug>...]` |
| A slug fails `[a-z0-9-]{1,32}`, or leads/trails with a hyphen | Invalid provider slug |
| Two IdPs share a slug | `Duplicate IdP slug '<id>'` |
| A per-IdP variable is missing (`_TYPE`, or OIDC `_ISSUER`/`_CLIENT_ID`/`_CLIENT_SECRET`, or SAML `_METADATA_URL`) | Names the missing variable |
| `VOUCH_IDP_<SLUG>_TYPE` is neither `oidc` nor `saml` | Invalid type |
| An IdP's OIDC discovery or SAML metadata fetch fails | `Failed to configure IdP '<id>'` |
| Only one of `VOUCH_TLS_CERT` / `VOUCH_TLS_KEY` is set | `Partial TLS configuration: set both ... or neither.` |
| `VOUCH_JWT_SECRET` under 32 characters, and no KMS HMAC key | `VOUCH_JWT_SECRET must be at least 32 characters` |
| `VOUCH_JWT_SECRET` is a single repeated character | `must not consist of a single repeated character` |
| Either retention variable is negative | Negative retention rejected |
| `VOUCH_CORS_ORIGINS` contains `*` | Wildcard is invalid with credentialed cookie sessions |
| `VOUCH_ALLOWED_AAGUIDS` has a non-UUID entry | `Invalid VOUCH_ALLOWED_AAGUIDS` |
| `VOUCH_LOG_FORMAT` is not `text` or `json` | `Invalid VOUCH_LOG_FORMAT` |
| `VOUCH_TRUSTED_PROXIES` has a malformed CIDR | `Invalid CIDR in VOUCH_TRUSTED_PROXIES` |
| `VOUCH_EXTRA_CA_CERTS` file is unreadable | Read failure |
| `VOUCH_DATABASE_URL` scheme is not `sqlite:`/`postgres:`/`postgresql:` | Unsupported scheme |
| A KMS key ID is set but the KMS client cannot be built | Names the key |
| S3 configuration is enabled but the object cannot be fetched or parsed | `Failed to fetch S3 configuration` |
| Issuer subdomains are claimed but document encryption is not configured | `issuer subdomains are claimed but document encryption is not configured` |
| The mTLS listener cannot bind | `Failed to start mTLS listener` |

A JWT secret with fewer than 8 distinct bytes produces a warning, not an error.

See [Troubleshooting](../operations/troubleshooting.md#the-server-wont-start) for what to do about
each.

## Localization

The server negotiates the response language per request from the `Accept-Language` header and the
OIDC `ui_locales` parameter. There is no server-side environment variable for it, and no
configuration is required.

The `vouch` CLI resolves its own language separately, from `--lang`, `VOUCH_LANG`, and the standard
POSIX locale variables. That is client-side; see [vouch.sh/docs](https://vouch.sh/docs/).
