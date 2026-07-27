# Audit Events

Every authentication, credential issuance, and administrative action is recorded as an audit
event. Events are stored in the `audit_events` table and browsable at `/admin/audit`.

Email addresses are masked to domain only, with an HMAC column alongside so you can correlate a
user's activity without the log itself holding their address. Events are enriched with the country
code, ASN, and network organization resolved from the client IP.

> The GeoIP databases are compiled into the server binary. They cannot be refreshed independently —
> new geolocation data arrives with a new Vouch release.

## Audit Events

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

Events fall into three retention classes. The class is a property of the event type; it is not
configurable.

| Class | Governed by | Contains |
|-------|-------------|----------|
| Authentication | `VOUCH_AUTH_EVENTS_RETENTION_DAYS` (default 90) | Logins, enrollment, logout, key and device-auth lifecycle, SCIM operations |
| OAuth and credentials | `VOUCH_OAUTH_EVENTS_RETENTION_DAYS` (default 90) | Credential issuance, token issue/revoke, client registration — the high-volume events |
| **Kept forever** | *nothing — never deleted* | Every administrative action, OAuth client and secret lifecycle, and all organization domain, subdomain, and issuer-key events |

The third class is the one to know about. Administrative and organization-lifecycle records are
**never** purged by the cleanup task, regardless of how you set the two retention variables. That
is deliberate: these are the records that answer "who granted this person admin, and when", and
they are low-volume enough to keep indefinitely. Plan database growth accordingly, and if a
regulation requires you to delete them, that is a manual database operation.

```bash
# Keep authentication events for two years, credential events for 90 days.
VOUCH_AUTH_EVENTS_RETENTION_DAYS=730
VOUCH_OAUTH_EVENTS_RETENTION_DAYS=90
```

Expired events are removed by the background cleanup task, which runs every
`VOUCH_CLEANUP_INTERVAL` minutes (default 15). Setting the interval to `0` disables cleanup
entirely, and events then accumulate without bound.

> **Retention values must not be negative.** The server rejects a negative value at startup, because
> a negative window produces a cutoff in the future — which would delete the entire audit log on the
> first cleanup pass.

## Browsing and exporting

`/admin/audit` provides a paginated view scoped to your organization.

There is no built-in export or syslog/SIEM streaming. To ship events off-box, query the
`audit_events` table directly:

```bash
# SQLite
sqlite3 /data/vouch.db \
  "SELECT * FROM audit_events WHERE created_at > datetime('now', '-1 day');"

# PostgreSQL
psql "$VOUCH_DATABASE_URL" -c \
  "SELECT * FROM audit_events WHERE created_at > now() - interval '1 day';"
```

Application logs are separate from audit events and go to stdout — see
[Monitoring and Metrics](../operations/monitoring.md) for structured logging and the
`x-fapi-interaction-id` correlation header.
