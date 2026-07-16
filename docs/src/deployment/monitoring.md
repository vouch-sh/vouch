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

Authentication, credential issuance, and administrative events are written to the
`audit_events` table and browsable at `/admin/audit`. Emails are masked to
domain-only, with an HMAC column for correlation.

### Authentication and key lifecycle

| Event Type | Description |
|------------|-------------|
| `login_success` | User authenticated — FIDO2 passkey login, or a returning user signing in on the website via the upstream IdP (the latter has no `authenticator_id`) |
| `login_failed` | Failed authentication attempt |
| `enrollment` | User enrolled their first hardware key |
| `logout` | User logged out (including RFC 7009 token revocation) |
| `key_registered` | Additional hardware key registered (`vouch register`) |
| `key_removed` | Hardware key removed |
| `device_auth_approved` | Browser approved a CLI device-authorization request |
| `key_registration_replay` | Replayed key-registration link rejected (possible attack) |

### Credential issuance

| Event Type | Description |
|------------|-------------|
| `ssh_credential` | SSH certificate issued; `data` includes the serial, principals, requesting agent, and expiry |
| `aws_credential` | AWS OIDC token issued; `data` includes the pinned IAM `role_arn` (the `https://aws.amazon.com/roles` claim), the requesting agent, and token expiry |
| `github_credential` | GitHub installation token issued or installation connected; `data` includes repositories and permissions |
| `token_exchange` | RFC 8693 token exchange (workload identity federation); `data` includes the client, audience, scope, and issued token type |

### OAuth clients

| Event Type | Description |
|------------|-------------|
| `oauth_token_issued` | Token issued at `/oauth/token` (`data.details` carries the grant type) |
| `oauth_token_revoked` | All tokens for an application revoked |
| `oauth_client_registered` | OAuth client registered (RFC 7591 or applications UI) |
| `oauth_client_updated` | OAuth client configuration updated |
| `oauth_client_deleted` | OAuth client deleted |
| `oauth_secret_added` | Client secret added |
| `oauth_secret_revoked` | Client secret revoked |

### Administration and organization

| Event Type | Description |
|------------|-------------|
| `admin_promote` / `admin_demote` | Org-admin role granted / removed |
| `admin_activate` / `admin_deactivate` | User account reactivated / deactivated |
| `admin_revoke_credentials` | Admin revoked a member's keys, sessions, and certificates |
| `admin_remove_user` | Admin removed a member from the organization |
| `admin_policy_create` / `admin_policy_update` / `admin_policy_delete` / `admin_policy_toggle` | Posture policy changes |
| `admin_create_scim_token` / `admin_delete_scim_token` / `admin_revoke_scim_token` | SCIM token lifecycle |
| `scim_operation` | SCIM provisioning operation (`data` carries operation and resource type) |
| `org_domain_added` / `org_domain_verified` / `org_domain_removed` / `org_domain_expired` / `org_domain_unverified` | Additional-domain lifecycle |
| `org_subdomain_claimed` / `org_subdomain_released` | Issuer subdomain lifecycle |
| `org_issuer_key_rotated` | Per-org issuer signing keys rotated (one event per algorithm) |
| `org_issuer_key_revoked` | Per-org previous signing keys revoked (one event per algorithm) |
| `org_issuer_key_emergency_rotation` | Emergency rotation of per-org issuer keys (one event per algorithm) |

## Retention

Configure retention periods for audit events:

```bash
# Auth events (login, enrollment, logout, key/device-auth lifecycle)
# — default 90 days
VOUCH_AUTH_EVENTS_RETENTION_DAYS=730

# OAuth usage and credential-issuance events (oauth_*, aws_credential,
# github_credential, ssh_credential, token_exchange) — default 90 days
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
