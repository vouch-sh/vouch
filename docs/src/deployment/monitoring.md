# Health Checks and Monitoring

## Health Endpoint

Vouch exposes a health check endpoint:

```
GET /health
```

Response:
```json
{"status": "healthy"}
```

This endpoint:
- Returns HTTP 200 when the server is operational
- Is accessible over HTTP (port 80) even when TLS is configured, for load balancer health checks
- Does not require authentication

## Monitoring Endpoints

| Endpoint | Method | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/health` | GET | No | Server health status |
| `/.well-known/openid-configuration` | GET | No | OIDC discovery (verifies OIDC provider is functional) |
| `/.well-known/oauth-protected-resource` | GET | No | OAuth 2.0 Protected Resource Metadata (RFC 9728) |
| `/v1/credentials/ssh/ca` | GET | No | SSH CA public key (verifies SSH CA is loaded) |

## Log Format

Vouch uses structured logging via `tracing`. Set the log level with the `RUST_LOG` environment variable:

```bash
# Production (warnings and errors only)
RUST_LOG=warn

# Standard operation
RUST_LOG=info

# Debugging
RUST_LOG=debug

# Component-specific logging
RUST_LOG=vouch_server=debug,tower_http=info
```

## Audit Events

All authentication and credential issuance events are logged to the database. Key events:

| Event Type | Description |
|------------|-------------|
| `enrollment_complete` | User enrolled a new hardware key |
| `login_success` | User authenticated with FIDO2 |
| `login_failure` | Failed authentication attempt |
| `credential_issued` | SSH certificate or other credential issued |
| `session_created` | New session established |
| `session_revoked` | Session explicitly revoked |
| `key_registered` | Additional hardware key registered |
| `key_removed` | Hardware key removed |
| `org_issuer_key_rotated` | Per-org issuer signing keys rotated (one event per algorithm) |
| `org_issuer_key_revoked` | Per-org previous signing keys revoked (one event per algorithm) |
| `org_issuer_key_emergency_rotation` | Emergency rotation of per-org issuer keys (one event per algorithm) |
| `scim_provision` | User provisioned via SCIM |
| `scim_deprovision` | User de-provisioned via SCIM |

## Retention

Configure retention periods for audit events:

```bash
# Auth events (login, enrollment) — default 90 days
VOUCH_AUTH_EVENTS_RETENTION_DAYS=730

# OAuth usage events — default 90 days
VOUCH_OAUTH_EVENTS_RETENTION_DAYS=90
```

Events older than the retention period are cleaned up automatically by the background cleanup task (controlled by `VOUCH_CLEANUP_INTERVAL`).

## Alerting Recommendations

| Condition | Alert Level | Description |
|-----------|------------|-------------|
| `/health` returns non-200 | Critical | Server is unhealthy |
| Multiple failed login attempts | Warning | Possible brute force |
| SSH CA key not loaded | Warning | SSH certificates won't be issued |
| Database approaching capacity | Warning | SQLite file growth or PostgreSQL storage |
| Session cleanup failing | Warning | Check cleanup interval and retention settings |
